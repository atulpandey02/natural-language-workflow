"""Restore orchestrator (M11.5 P2) — safe fresh-host restore.

Intended for a NEW / disposable host. It refuses to restore into an arbitrary
active production database: the operator must supply a destructive confirmation
matching the exact target identity, no runtime role may be connected, and the
target DB must be empty. It never starts the worker/scheduler; runtime services
are a SEPARATE operator action after validation + quiescence pass.

Sequence: confirm -> guard (no runtime connections, empty DB) -> restic restore ->
verify manifest+hashes -> pg_restore (NO auto-migrations) -> flush ephemeral Redis
-> validate -> quiesce -> record. Any failed step raises (non-zero exit).
"""

import json
import os
import subprocess
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from nlw.backup.backup import DB_DUMP_NAME, GLOBALS_NAME
from nlw.backup.config import (
    RestoreSettings,
    sa_engine_url,
    validated_runtime_file,
    validated_work_dir,
)
from nlw.backup.gate import build_gate, db_system_identifier, write_gate
from nlw.backup.manifest import MANIFEST_NAME, verify_manifest
from nlw.backup.quiescence import quiesce
from nlw.backup.restic import Restic
from nlw.backup.runtime_guard import (
    ComposeRuntimeProbe,
    NullRuntimeProbe,
    RuntimeProbe,
    assert_runtime_stopped,
)
from nlw.backup.validate import human_summary, validate_restore

log = structlog.get_logger("nlw.restore")

_RUNTIME_ROLES = ("nlw_app", "nlw_worker", "nlw_scheduler")


@dataclass(frozen=True)
class RestoreResult:
    ok: bool
    snapshot: str
    validation: dict[str, Any]
    runs_quiesced: int
    gate_path: str | None = None
    restore_generation: str | None = None
    restore_event_id: str | None = None


def _build_runtime_probe(settings: RestoreSettings) -> RuntimeProbe:
    if settings.runtime_guard == "off":
        return NullRuntimeProbe()
    return ComposeRuntimeProbe(project=settings.compose_project)


def assert_no_runtime_connections(engine: Engine) -> None:
    """Refuse if any runtime role is connected (i.e. api/worker/scheduler active)."""
    with engine.connect() as conn:
        n = int(
            conn.execute(
                text("SELECT count(*) FROM pg_stat_activity WHERE usename = ANY(:roles)"),
                {"roles": list(_RUNTIME_ROLES)},
            ).scalar_one()
        )
    if n:
        raise RuntimeError(
            "restore refused: runtime services appear active "
            f"({n} runtime-role connections). Stop api/worker/scheduler first."
        )


def assert_target_empty(engine: Engine) -> None:
    """Refuse to overwrite a non-empty database."""
    with engine.connect() as conn:
        n = int(
            conn.execute(
                text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
            ).scalar_one()
        )
    if n:
        raise RuntimeError(
            f"restore refused: target database is not empty ({n} public tables). "
            "Restore only into a fresh empty database/volume."
        )


def _default_pg_restore(db_dump: Path, database_url: str) -> None:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp")}
    # PRESERVE ownership (no --no-owner) so the restored schema keeps its
    # NOSUPERUSER SECURITY DEFINER owners instead of collapsing onto the restoring
    # superuser. --exit-on-error fails CLOSED if any ALTER OWNER cannot resolve
    # (missing role) — better than a silently superuser-owned schema.
    res = subprocess.run(
        ["pg_restore", "--exit-on-error", "--dbname", database_url, str(db_dump)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(f"pg_restore failed (exit {res.returncode})")


def _flush_redis(redis_url: str) -> None:
    try:
        import redis
    except ImportError:
        log.warning("restore.redis_flush_skipped", reason="redis client absent")
        return
    client = redis.Redis.from_url(redis_url)
    client.flushdb()
    log.info("restore.redis_flushed")


PgRestoreFn = Callable[[Path, str], None]


def run_restore(
    settings: RestoreSettings,
    *,
    restic: Restic | None = None,
    pg_restore_fn: PgRestoreFn = _default_pg_restore,
    redis_url: str | None = None,
    runtime_probe: RuntimeProbe | None = None,
) -> RestoreResult:
    # (H1) explicit destructive confirmation matching the exact target identity.
    settings.require_confirmation()
    db_url = settings.restore_database_url.get_secret_value()
    if not db_url:
        raise ValueError("NLW_RESTORE_DATABASE_URL is required")
    # psycopg-v3 dialect for the engine; pg_restore keeps the raw libpq db_url.
    engine = create_engine(sa_engine_url(db_url))
    restic = restic or Restic(settings.restic_env())
    probe = runtime_probe if runtime_probe is not None else _build_runtime_probe(settings)
    work = validated_work_dir(settings.work_dir)

    # (B) runtime services must be DOWN — Compose state scoped to the exact project,
    # fail closed if undeterminable. (H) plus the DB-session check as defense in
    # depth; (H) never overwrite a non-empty DB.
    assert_runtime_stopped(probe)
    assert_no_runtime_connections(engine)
    assert_target_empty(engine)

    # retrieve + decrypt the selected snapshot.
    restic.restore(settings.snapshot, work)
    restored_root = _find_restored_dir(work)

    # verify manifest + integrity hashes.
    manifest = json.loads((restored_root / MANIFEST_NAME).read_text())
    files = {
        DB_DUMP_NAME: restored_root / DB_DUMP_NAME,
        GLOBALS_NAME: restored_root / GLOBALS_NAME,
    }
    verify_manifest(manifest, files)
    log.info("restore.manifest_verified", revision=manifest.get("alembic_revision"))

    # (B, TOCTOU) recheck runtime state IMMEDIATELY before the destructive restore —
    # a service that started after the first guard is caught here.
    assert_runtime_stopped(probe)
    assert_no_runtime_connections(engine)

    # restore schema/data (NO automatic migrations — restore at the recorded rev).
    pg_restore_fn(files[DB_DUMP_NAME], db_url)

    # clear ephemeral Redis (never restore stale queue state).
    if redis_url or os.environ.get("REDIS_URL"):
        _flush_redis(redis_url or os.environ["REDIS_URL"])

    # (B) recheck before quiescence/validation (these can be run as separate commands).
    assert_runtime_stopped(probe)

    # MANDATORY quiescence BEFORE any runtime service could start.
    qr = quiesce(engine, manifest=manifest, note="restore")
    log.info(
        "restore.quiesced",
        runs=qr.runs_quiesced,
        steps=qr.steps_quiesced,
        actions=qr.actions_unknowned,
        schedules=qr.schedules_recomputed,
    )

    # validate (deeper than row counts).
    report = validate_restore(engine, expected_revision=manifest.get("alembic_revision"))
    log.info("restore.validated", ok=report["ok"])
    if not report["ok"]:
        raise RuntimeError("restore validation FAILED:\n" + human_summary(report))

    # (C) restore-ready gate — written atomically ONLY now (quiescence + validation
    # both succeeded), bound to THIS restore generation and THIS DB cluster.
    generation = str(uuid.uuid4())
    gate = build_gate(
        restore_event_id=qr.event_id or "",
        restore_generation=generation,
        target_project=settings.compose_project or settings.target_id,
        snapshot=settings.snapshot,
        db_system_identifier=db_system_identifier(engine),
        database_name=str(manifest.get("database") or ""),
        quiescence_cutoff=qr.cutoff,
        validation_completed_at=datetime.now(UTC),
    )
    gate_path = validated_runtime_file(settings.gate_file, what="restore gate")
    write_gate(gate, gate_path)
    log.info("restore.gate_written", generation=generation, path=str(gate_path))

    return RestoreResult(
        ok=True,
        snapshot=settings.snapshot,
        validation=report,
        runs_quiesced=qr.runs_quiesced,
        gate_path=str(gate_path),
        restore_generation=generation,
        restore_event_id=qr.event_id,
    )


def restore_ready(engine: Engine) -> bool:
    """The runtime-start gate: a restore was quiesced (a dr_restore_events row
    exists) AND no non-terminal work remains. Runtime services must not start until
    this is true. (Enforced procedurally + by the restore Compose profile not
    including api/worker/scheduler.)"""
    with engine.connect() as conn:
        events = int(conn.execute(text("SELECT count(*) FROM dr_restore_events")).scalar_one())
        non_terminal = int(
            conn.execute(
                text(
                    "SELECT count(*) FROM workflow_runs "
                    "WHERE status IN ('PENDING','RUNNING','WAITING_APPROVAL')"
                )
            ).scalar_one()
        )
    return events > 0 and non_terminal == 0


def _find_restored_dir(work: Path) -> Path:
    """restic restore recreates the absolute source path under the target. Find the
    directory that contains our manifest."""
    for p in work.rglob(MANIFEST_NAME):
        return p.parent
    raise RuntimeError("restored snapshot does not contain a manifest")
