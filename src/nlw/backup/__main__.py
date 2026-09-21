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
"""

import argparse
import json
import os
import sys
from pathlib import Path

import structlog
from sqlalchemy import create_engine

from nlw.backup.config import BackupSettings, RestoreSettings, sa_engine_url, validated_runtime_file
from nlw.backup.gate import GateError, verify_restore_gate
from nlw.backup.locking import BackupAlreadyRunning
from nlw.backup.quiescence import quiesce
from nlw.backup.restic import Restic
from nlw.backup.restore import run_restore
from nlw.backup.validate import human_summary, validate_restore

log = structlog.get_logger("nlw.backup.cli")

EXIT_ALREADY_RUNNING = 3
EXIT_GATE_FAILED = 4


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nlw.backup")
    parser.add_argument(
        "command",
        choices=("backup", "restore", "quiesce", "validate", "prune", "gate-check"),
    )
    args = parser.parse_args(argv)
    handlers = {
        "backup": _cmd_backup,
        "restore": _cmd_restore,
        "quiesce": _cmd_quiesce,
        "validate": _cmd_validate,
        "prune": _cmd_prune,
        "gate-check": _cmd_gate_check,
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
