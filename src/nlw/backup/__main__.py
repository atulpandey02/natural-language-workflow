"""Backup/restore/quiesce/validate CLI (M11.5 P2).

    python -m nlw.backup backup     # encrypted off-host backup + verify + retention
    python -m nlw.backup restore    # guarded fresh-host restore (+ quiesce + validate)
    python -m nlw.backup quiesce     # post-restore quiescence only (idempotent)
    python -m nlw.backup validate    # post-restore validation only (read-only)

Each reads its config from the environment (fail-closed) and exits non-zero on any
failure. Secrets are never printed.
"""

import argparse
import json
import os
import sys

import structlog
from sqlalchemy import create_engine

from nlw.backup.backup import run_backup
from nlw.backup.config import BackupSettings, RestoreSettings, sa_engine_url
from nlw.backup.quiescence import quiesce
from nlw.backup.restore import run_restore
from nlw.backup.validate import human_summary, validate_restore

log = structlog.get_logger("nlw.backup.cli")


def _cmd_backup() -> int:
    result = run_backup(BackupSettings())
    print(f"backup ok: snapshot={result.snapshot_id} duration_s={result.duration_seconds:.1f}")
    return 0 if result.ok else 1


def _cmd_restore() -> int:
    result = run_restore(RestoreSettings())
    print(human_summary(result.validation))
    print(f"restore ok: quiesced {result.runs_quiesced} non-terminal run(s)")
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nlw.backup")
    parser.add_argument("command", choices=("backup", "restore", "quiesce", "validate"))
    args = parser.parse_args(argv)
    handlers = {
        "backup": _cmd_backup,
        "restore": _cmd_restore,
        "quiesce": _cmd_quiesce,
        "validate": _cmd_validate,
    }
    try:
        return handlers[args.command]()
    except Exception as exc:  # sanitized: class name only, never secrets/args
        log.error(f"backup.cli.{args.command}_failed", error_class=type(exc).__name__)
        print(f"{args.command} FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
