"""Backup orchestrator (M11.5 P2): consistent dump -> manifest -> encrypted
off-host repository -> verify -> retention, with fail-closed semantics.

A backup is reported SUCCESSFUL only when the encrypted snapshot reached the
off-host repository AND the repository verified — never merely because ``pg_dump``
exited zero. Every step is fail-closed; any incomplete step exits non-zero and
does NOT advance the "last successful backup" timestamp.

The DB capture, DB-info, and restic seams are injectable so unit tests exercise
the step-sequencing/failure logic without a real Postgres or repository; the drill
runs the real subprocesses against MinIO.
"""

import os
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import structlog

from nlw.backup.config import BackupSettings, validated_runtime_file, validated_work_dir
from nlw.backup.locking import backup_lock
from nlw.backup.manifest import build_manifest, write_manifest
from nlw.backup.metrics_file import BackupMetrics, write_metrics
from nlw.backup.restic import Restic, ResticError

log = structlog.get_logger("nlw.backup")

DB_DUMP_NAME = "db.dump"
GLOBALS_NAME = "globals.sql"


@dataclass(frozen=True)
class DbInfo:
    pg_version: str
    alembic_revision: str | None
    database_name: str


@dataclass(frozen=True)
class BackupResult:
    ok: bool
    snapshot_id: str
    duration_seconds: float


# --- default (real) seams ---


def _pg_env(database_url: str) -> dict[str, str]:
    """Child env for pg tools: pass the DSN as a single PG* var set is avoided;
    libpq reads the URL from the last positional arg. The password inside the URL
    is handled by libpq, never placed on argv separately."""
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp")}


def _default_dump(work_dir: Path, database_url: str) -> dict[str, Path]:
    """pg_dump (custom format) + roles-only globals WITHOUT passwords. The DSN is
    the last positional arg (libpq parses it); we never echo it."""
    db_path = work_dir / DB_DUMP_NAME
    globals_path = work_dir / GLOBALS_NAME
    env = _pg_env(database_url)
    # PRESERVE ownership (no --no-owner): the SECURITY DEFINER functions are owned
    # by dedicated NOSUPERUSER roles (nlw_rls_bypass / nlw_workspace_bootstrap) and
    # tables by the owner role. --no-owner would flatten every object onto the
    # restoring superuser, silently turning SECURITY DEFINER functions into a
    # privilege-escalation vector. Roles are reinstated from bootstrap/IaC before
    # restore, so the ownership commands resolve.
    dump = subprocess.run(
        ["pg_dump", "--format=custom", "--file", str(db_path), database_url],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if dump.returncode != 0:
        raise RuntimeError(f"pg_dump failed (exit {dump.returncode})")
    globs = subprocess.run(
        ["pg_dumpall", "--roles-only", "--no-role-passwords", "--dbname", database_url],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if globs.returncode != 0:
        raise RuntimeError(f"pg_dumpall --roles-only failed (exit {globs.returncode})")
    globals_path.write_text(globs.stdout)
    for p in (db_path, globals_path):
        p.chmod(0o600)
    return {DB_DUMP_NAME: db_path, GLOBALS_NAME: globals_path}


def _default_db_info(database_url: str) -> DbInfo:
    import psycopg

    with psycopg.connect(database_url) as conn:
        ver_row = conn.execute("SELECT version()").fetchone()
        rev_row = conn.execute("SELECT version_num FROM alembic_version").fetchone()
        db_row = conn.execute("SELECT current_database()").fetchone()
    ver = str(ver_row[0]) if ver_row else ""
    return DbInfo(
        pg_version=ver.split(" ")[1] if ver else "",
        alembic_revision=(str(rev_row[0]) if rev_row else None),
        database_name=str(db_row[0]) if db_row else "",
    )


def _tool_versions() -> dict[str, str]:
    out: dict[str, str] = {}
    for tool in ("pg_dump", "restic"):
        try:
            r = subprocess.run([tool, "--version"], capture_output=True, text=True, check=False)
            out[tool] = r.stdout.strip().splitlines()[0] if r.returncode == 0 else "unknown"
        except FileNotFoundError:
            out[tool] = "absent"
    return out


DumpFn = Callable[[Path, str], dict[str, Path]]
DbInfoFn = Callable[[str], DbInfo]


def run_backup(
    settings: BackupSettings,
    *,
    restic: Restic | None = None,
    dump_fn: DumpFn = _default_dump,
    db_info_fn: DbInfoFn = _default_db_info,
    tool_versions_fn: Callable[[], dict[str, str]] = _tool_versions,
    now_fn: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> BackupResult:
    db_url = settings.backup_database_url.get_secret_value()
    if not db_url:
        raise ValueError("NLW_BACKUP_DATABASE_URL is required")
    # (A) single-execution lock around the ENTIRE lifecycle, acquired BEFORE any dump
    # or temp artifact. A second concurrent invocation raises BackupAlreadyRunning
    # here — before pg_dump, upload, prune, or any metrics write.
    lock_file = validated_runtime_file(settings.lock_file, what="backup lock")
    with backup_lock(lock_file):
        return _run_backup_locked(
            settings,
            db_url=db_url,
            restic=restic,
            dump_fn=dump_fn,
            db_info_fn=db_info_fn,
            tool_versions_fn=tool_versions_fn,
            now_fn=now_fn,
        )


def _run_backup_locked(
    settings: BackupSettings,
    *,
    db_url: str,
    restic: Restic | None,
    dump_fn: DumpFn,
    db_info_fn: DbInfoFn,
    tool_versions_fn: Callable[[], dict[str, str]],
    now_fn: Callable[[], datetime],
) -> BackupResult:
    started = now_fn()
    t0 = time.monotonic()
    restic = restic or Restic(settings.restic_env())
    work = validated_work_dir(settings.work_dir)

    verified_off_host = False
    verify_ok = False
    retention_ok = False
    snapshot_id = ""

    def _emit(success: bool) -> None:
        write_metrics(
            settings.metrics_file,
            BackupMetrics(
                success=success,
                duration_seconds=time.monotonic() - t0,
                verify_success=verify_ok,
                retention_success=retention_ok,
                verified_off_host=verified_off_host,
            ),
            now=time.time(),
        )

    try:
        # (1)(2) config validated on construction; confirm DB connectivity + info.
        info = db_info_fn(db_url)
        log.info("backup.start", database=info.database_name, revision=info.alembic_revision)

        # (3) consistent capture + (4) roles/globals (no passwords).
        files = dump_fn(work, db_url)

        # (5) integrity metadata + manifest (no secrets).
        completed = now_fn()
        manifest = build_manifest(
            started_at=started,
            completed_at=completed,
            files=files,
            alembic_revision=info.alembic_revision,
            app_version=os.environ.get("NLW_APP_VERSION"),
            pg_version=info.pg_version,
            database_name=info.database_name,
            tool_versions=tool_versions_fn(),
        )
        write_manifest(manifest, work)

        # (6) encrypt as data enters the off-host repository.
        restic.ensure_repository()
        snapshot_id = restic.backup_dir(work, tags=["nlw-db", f"rev-{info.alembic_revision}"])

        # (7) verify the repository + that the snapshot is present/readable.
        restic.check()
        if snapshot_id and not restic.snapshot_exists(snapshot_id):
            raise ResticError("newly created snapshot is not listable")
        verify_ok = True
        verified_off_host = True  # dump reached the repo AND verified

        # (9) retention ONLY after a verified success — and ONLY in simple mode.
        # In immutable mode the writer has no delete rights; pruning is a separate,
        # human-gated admin process off the VPS (see backup-providers.md).
        if settings.retention_mode == "simple":
            restic.forget_prune(
                daily=settings.retention_daily,
                weekly=settings.retention_weekly,
                monthly=settings.retention_monthly,
            )
        else:
            log.info("backup.retention_delegated", mode=settings.retention_mode)
        retention_ok = True

        _emit(True)  # (8) success signal
        log.info("backup.done", snapshot=snapshot_id, duration_s=round(time.monotonic() - t0, 2))
        return BackupResult(
            ok=True, snapshot_id=snapshot_id, duration_seconds=time.monotonic() - t0
        )
    except Exception as exc:
        _emit(False)  # (8) failure signal; last-success timestamp NOT advanced
        log.error("backup.failed", error_class=type(exc).__name__)
        raise
    finally:
        # (transient plaintext material is wiped on success AND failure)
        _wipe_work_dir(work)


def _wipe_work_dir(work: Path) -> None:
    """Remove the specific transient files/dir we created — never a broad glob and
    only under the validated work root."""
    try:
        if work.exists() and str(work) not in ("/", str(Path.home())):
            shutil.rmtree(work, ignore_errors=True)
    except OSError:
        pass
