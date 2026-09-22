"""Backup/restore/quiesce/validate/prune/gate-check CLI (M11.5 P2).

    python -m nlw.backup backup      # encrypted off-host backup + verify + retention
    python -m nlw.backup restore     # guarded fresh-host restore (+ quiesce + validate + gate)
    python -m nlw.backup quiesce      # post-restore quiescence only (idempotent)
    python -m nlw.backup validate     # post-restore validation only (read-only)
    python -m nlw.backup prune        # SEPARATE admin retention (immutable-mode maintenance)
    python -m nlw.backup gate-check   # verify the restore-ready gate (runtime-start gate)

Each reads its config from the environment (fail-closed) and exits non-zero on any
failure. Secrets are never printed.

Exit codes:
    0  success
    1  operation failed (validation/gate/backup step failed)
    2  usage / unexpected error (sanitized to a class name)
    3  backup already running (single-execution lock held by another process)
    4  restore-ready gate check failed (missing/stale/tampered/wrong DB)
    5  enable-runtime rejected (stale/mismatched/unvalidated generation)
    6  startup blocked by the authoritative DB recovery lock (or indeterminate)
"""

import argparse
import contextlib
import json
import os
import re
import sys
from pathlib import Path

import structlog
from sqlalchemy import create_engine

from nlw.backup.config import BackupSettings, RestoreSettings, sa_engine_url, validated_runtime_file
from nlw.backup.gate import GateError, verify_restore_gate
from nlw.backup.locking import BackupAlreadyRunning
from nlw.backup.quiescence import quiesce
from nlw.backup.recovery_lock import (
    EnableRejected,
    RecoveryLocked,
    RecoveryStateUnknown,
    assert_startup_allowed_sync,
    enable_runtime,
)
from nlw.backup.restic import Restic
from nlw.backup.restore import run_restore
from nlw.backup.validate import human_summary, validate_restore

log = structlog.get_logger("nlw.backup.cli")

EXIT_ALREADY_RUNNING = 3
EXIT_GATE_FAILED = 4
EXIT_ENABLE_REJECTED = 5
EXIT_STARTUP_BLOCKED = 6


def _cmd_backup() -> int:
    from nlw.backup.backup import run_backup  # local import: avoids CLI import cost

    result = run_backup(BackupSettings())
    print(f"backup ok: snapshot={result.snapshot_id} duration_s={result.duration_seconds:.1f}")
    return 0 if result.ok else 1


def _cmd_restore() -> int:
    result = run_restore(RestoreSettings())
    print(human_summary(result.validation))
    print(
        f"restore ok: quiesced {result.runs_quiesced} non-terminal run(s); "
        f"gate={result.gate_path} generation={result.restore_generation}"
    )
    return 0 if result.ok else 1


def _cmd_quiesce() -> int:
    url = os.environ.get("NLW_RESTORE_DATABASE_URL", "")
    if not url:
        raise ValueError("NLW_RESTORE_DATABASE_URL is required")
    engine = create_engine(sa_engine_url(url))
    r = quiesce(engine, note="manual-quiesce")
    print(
        f"quiesced: runs={r.runs_quiesced} steps={r.steps_quiesced} "
        f"actions={r.actions_unknowned} schedules={r.schedules_recomputed} cutoff={r.cutoff}"
    )
    return 0


def _cmd_validate() -> int:
    url = os.environ.get("NLW_RESTORE_DATABASE_URL", "")
    if not url:
        raise ValueError("NLW_RESTORE_DATABASE_URL is required")
    engine = create_engine(sa_engine_url(url))
    report = validate_restore(engine, expected_revision=os.environ.get("NLW_EXPECTED_REVISION"))
    if os.environ.get("NLW_VALIDATE_JSON"):
        print(json.dumps(report))
    else:
        print(human_summary(report))
    return 0 if report["ok"] else 1


def _cmd_prune() -> int:
    """SEPARATE administrative retention for immutable mode (addendum D).

    Deliberately NOT part of the backup job: it deletes, so it must run as a distinct
    human-gated process with delete-capable credentials that are NOT stored on the
    VPS. Requires an explicit confirmation to avoid accidental invocation.
    """
    if os.environ.get("NLW_BACKUP_ALLOW_PRUNE") != "1":
        raise RuntimeError(
            "prune refused: set NLW_BACKUP_ALLOW_PRUNE=1 to run administrative "
            "retention (a separate, human-gated maintenance step)"
        )
    settings = BackupSettings()
    restic = Restic(settings.restic_env())
    restic.forget_prune(
        daily=settings.retention_daily,
        weekly=settings.retention_weekly,
        monthly=settings.retention_monthly,
    )
    print(
        f"prune ok: daily={settings.retention_daily} weekly={settings.retention_weekly} "
        f"monthly={settings.retention_monthly}"
    )
    return 0


def _cmd_evidence() -> int:
    """Print NON-SECRET pre-deployment backup evidence as JSON (M12A-Prep §G):
    the sanitized repository location, the metrics textfile contents, the newest
    ``nlw-db`` snapshot (id/time/hostname/tags) and the artifact NAMES inside it.
    The rollout gate evaluates this document; nothing here decides anything."""
    settings = BackupSettings()
    restic = Restic(settings.restic_env())
    snaps = restic.latest_snapshots()
    names = restic.snapshot_file_names(snaps[0]["id"]) if snaps else []
    metrics_text = ""
    with contextlib.suppress(OSError):
        metrics_text = Path(settings.metrics_file).read_text()
    repo = re.sub(r"://[^/@]+@", "://<redacted>@", settings.restic_repository)
    doc = {
        "format_version": 1,
        "repository": repo,
        "metrics_text": metrics_text,
        "snapshots": snaps,
        "artifact_names": names,
    }
    for needle in ("password", "secret", "token"):
        if needle in json.dumps(doc).lower():
            raise RuntimeError("evidence document would contain a secret-bearing value")
    print(json.dumps(doc, indent=2, sort_keys=True))
    return 0


def _cmd_gate_check() -> int:
    """Verify the restore-ready gate against the live DB (runtime-start gate).

    Normal (non-restore) deployments do NOT run this: it is invoked only in restore
    mode (NLW_RESTORE_MODE=1) by the runtime entrypoint before api/worker/scheduler
    start. Fails closed (exit 4) on a missing/stale/tampered/wrong-DB gate.
    """
    url = os.environ.get("NLW_RESTORE_DATABASE_URL") or os.environ.get("DATABASE_URL", "")
    if not url:
        raise ValueError("NLW_RESTORE_DATABASE_URL (or DATABASE_URL) is required for gate-check")
    gate_path = validated_runtime_file(
        os.environ.get("NLW_RESTORE_GATE_FILE", "/var/lib/nlw/restore-ready.json"),
        what="restore gate",
    )
    engine = create_engine(sa_engine_url(url))
    expected_project = os.environ.get("NLW_RESTORE_COMPOSE_PROJECT") or None
    try:
        gate = verify_restore_gate(engine, Path(gate_path), expected_project=expected_project)
    except GateError as exc:
        log.error("backup.cli.gate_check_failed", error_class=type(exc).__name__)
        print(f"gate-check FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_GATE_FAILED
    print(
        f"gate-check ok: generation={gate['restore_generation']} "
        f"event={gate['restore_event_id']} project={gate['target_project']}"
    )
    return 0


def _cmd_enable_runtime() -> int:
    """Explicitly enable the newest, validated restore generation (operator step).

    Uses the RESTORE/operator DB credential (never a runtime role). Does not start
    any container. Requires the exact generation id + the project/database
    confirmation; rejects stale/mismatched/unvalidated generations.
    """
    url = os.environ.get("NLW_RESTORE_DATABASE_URL", "")
    event_id = os.environ.get("NLW_RESTORE_EVENT_ID", "")
    confirm_project = os.environ.get("NLW_RESTORE_COMPOSE_PROJECT") or os.environ.get(
        "NLW_RESTORE_TARGET_ID", ""
    )
    operator = os.environ.get("NLW_RESTORE_OPERATOR", "operator")
    if not url or not event_id or not confirm_project:
        raise ValueError(
            "enable-runtime requires NLW_RESTORE_DATABASE_URL, NLW_RESTORE_EVENT_ID, and "
            "NLW_RESTORE_COMPOSE_PROJECT (or NLW_RESTORE_TARGET_ID)"
        )
    engine = create_engine(sa_engine_url(url))
    try:
        result = enable_runtime(
            engine, event_id=event_id, confirm_project=confirm_project, operator=operator
        )
    except EnableRejected as exc:
        log.error("backup.cli.enable_rejected", error_class=type(exc).__name__)
        print(f"enable-runtime REJECTED: {exc}", file=sys.stderr)
        return EXIT_ENABLE_REJECTED
    state = "already enabled" if result.already_enabled else "ENABLED"
    print(f"enable-runtime ok: generation {result.event_id} {state} at {result.enabled_at}")
    return 0


def _cmd_startup_check() -> int:
    """The exact preflight api/worker/scheduler run at boot, against the runtime DB
    role. Exit 6 if the newest restore generation is not operator-enabled."""
    url = os.environ.get("NLW_RESTORE_DATABASE_URL") or os.environ.get("DATABASE_URL", "")
    if not url:
        raise ValueError("NLW_RESTORE_DATABASE_URL (or DATABASE_URL) is required for startup-check")
    engine = create_engine(sa_engine_url(url))
    try:
        assert_startup_allowed_sync(engine)
    except (RecoveryLocked, RecoveryStateUnknown) as exc:
        log.error("backup.cli.startup_blocked", error_class=type(exc).__name__)
        print(f"startup-check BLOCKED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_STARTUP_BLOCKED
    print("startup-check ok: recovery lock permits startup")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nlw.backup")
    parser.add_argument(
        "command",
        choices=(
            "backup",
            "restore",
            "quiesce",
            "validate",
            "prune",
            "gate-check",
            "enable-runtime",
            "startup-check",
            "evidence",
        ),
    )
    args = parser.parse_args(argv)
    handlers = {
        "backup": _cmd_backup,
        "restore": _cmd_restore,
        "quiesce": _cmd_quiesce,
        "validate": _cmd_validate,
        "prune": _cmd_prune,
        "evidence": _cmd_evidence,
        "gate-check": _cmd_gate_check,
        "enable-runtime": _cmd_enable_runtime,
        "startup-check": _cmd_startup_check,
    }
    try:
        return handlers[args.command]()
    except BackupAlreadyRunning as exc:
        # Stable, sanitized "already running" status — no dump/upload/prune/metrics ran.
        log.warning("backup.cli.already_running")
        print(f"{args.command}: {exc}", file=sys.stderr)
        return EXIT_ALREADY_RUNNING
    except Exception as exc:  # sanitized: class name only, never secrets/args
        log.error(f"backup.cli.{args.command}_failed", error_class=type(exc).__name__)
        print(f"{args.command} FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
