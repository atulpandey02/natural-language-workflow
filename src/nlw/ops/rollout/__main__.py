"""``python -m nlw.ops.rollout [phase] --release MANIFEST [options]``.

The default phase is ``preflight`` and is READ-ONLY. ``--release`` is required
and must be the CI-generated manifest downloaded for the exact release commit
(``deploy/staging/release.example.json`` is rejected in every mode). Mutating
phases require:

* ``--authorize <exact phrase>``  (AUTHORIZE_M12A_SIGNED_CONTEXT_STAGING_DEPLOYMENT)
* ``--escrow-confirm <exact phrase>`` + ``--attestation FILE`` for verify-escrow
* a verified off-host backup (verify-backup) before drain and any DB change

No ``--yes``; an empty or partial phrase is a hard stop. Phrases are compared
only, never persisted. ``go-check`` is a read-only M12 GO evaluation. The
rehearsal (scripts/ops/rehearse-0010-to-0016.sh) uses ``--local`` to execute the
same phases against a disposable local stack.
"""

from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from pathlib import Path

from nlw.ops.release_provenance import ProvenanceError, verify_manifest_file
from nlw.ops.rollout.attestation import AttestationError
from nlw.ops.rollout.backup_evidence import BackupEvidenceError
from nlw.ops.rollout.gates import GateError
from nlw.ops.rollout.phases import Operator, Rollout, RolloutStop
from nlw.ops.rollout.release import ReleaseSpecError
from nlw.ops.rollout.remote import (
    LocalRemote,
    SshRemote,
    TargetConfig,
    TargetConfigError,
    load_target,
)
from nlw.ops.rollout.state import PHASES, StateError

DEFAULT_TARGET = Path("deploy/staging/target.env")
DEFAULT_KEYS_DIR = "/srv/nlw/ctx-keys"
COMMANDS = (*PHASES, "go-check")


def _log(msg: str) -> None:
    print(f"[rollout] {msg}", flush=True)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m nlw.ops.rollout")
    p.add_argument("phase", nargs="?", default="preflight", choices=COMMANDS)
    p.add_argument("--release", type=Path, required=True, help="CI-generated release manifest")
    p.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    p.add_argument("--ssh-key", type=Path, default=None)
    p.add_argument("--keys-dir", default=DEFAULT_KEYS_DIR, help="host directory of the key files")
    p.add_argument("--authorize", default=None, metavar="PHRASE")
    p.add_argument("--escrow-confirm", default=None, metavar="PHRASE")
    p.add_argument("--attestation", type=Path, default=None)
    p.add_argument("--backup-max-age-hours", type=float, default=26.0)
    p.add_argument(
        "--local",
        action="store_true",
        help="rehearsal only: run the phases with bash on THIS machine instead of SSH",
    )
    p.add_argument(
        "--provenance-fixture",
        type=Path,
        default=None,
        help="rehearsal only (requires --local): the unsigned fixture provenance envelope",
    )
    p.add_argument(
        "--allow-fixture-repository",
        action="store_true",
        help="rehearsal only (requires --local): accept the disposable MinIO backup fixture",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.provenance_fixture is not None and not args.local:
        print(
            "[rollout] --provenance-fixture is rehearsal-only (requires --local)", file=sys.stderr
        )
        return 2
    try:
        # Schema, then PROVENANCE (GitHub attestation policy; fixture only under
        # --local) — before the target config is even read: no host is contacted
        # for a manifest that is not verified release authority.
        release, receipt = verify_manifest_file(
            args.release, local=bool(args.local), fixture=args.provenance_fixture
        )
        _log(
            f"provenance verified by {receipt.verifier}: {receipt.repository} "
            f"{receipt.workflow}@{receipt.ref} run {receipt.run_id} "
            f"(manifest sha256 {receipt.manifest_sha256[:12]}"
            f"{', REHEARSAL FIXTURE — not GitHub provenance' if receipt.fixture else ''})"
        )
        target: TargetConfig = load_target(args.target, ssh_key=args.ssh_key)
    except (ReleaseSpecError, ProvenanceError) as exc:
        print(f"[rollout] release provenance REJECTED: {exc}", file=sys.stderr)
        return 2
    except TargetConfigError as exc:
        print(f"[rollout] configuration error: {exc}", file=sys.stderr)
        return 2
    if args.allow_fixture_repository and not args.local:
        print(
            "[rollout] --allow-fixture-repository is rehearsal-only (requires --local)",
            file=sys.stderr,
        )
        return 2
    remote = LocalRemote() if args.local else SshRemote(target)
    op = Operator(
        authorization=args.authorize,
        escrow_confirmation=args.escrow_confirm,
        attestation_path=args.attestation,
        backup_max_age=timedelta(hours=args.backup_max_age_hours),
        allow_fixture_repository=bool(args.allow_fixture_repository and args.local),
    )
    r = Rollout(
        release=release, target=target, remote=remote, operator=op, log=_log, receipt=receipt
    )
    keys_dir = args.keys_dir
    try:
        if args.phase == "preflight":
            r.preflight()
        elif args.phase == "verify-release":
            r.verify_release()
        elif args.phase == "prepare-keys":
            r.prepare_keys(keys_dir=keys_dir)
        elif args.phase == "verify-escrow":
            r.verify_escrow(keys_dir=keys_dir)
        elif args.phase == "stage-release":
            r.stage_release(keys_dir=keys_dir)
        elif args.phase == "backup":
            r.backup()
        elif args.phase == "verify-backup":
            r.verify_backup()
        elif args.phase == "drain":
            r.drain()
        elif args.phase == "prepare-roles":
            r.prepare_roles()
        elif args.phase == "migrate":
            r.migrate()
        elif args.phase == "install-context-keys":
            r.install_context_keys(keys_dir=keys_dir)
        elif args.phase == "recreate-runtime":
            r.recreate_runtime(keys_dir=keys_dir)
        elif args.phase == "validate":
            r.validate(keys_dir=keys_dir)
        elif args.phase == "reopen":
            r.reopen()
        elif args.phase == "go-check":
            r.go_check()
            _log("M12 GO check: PASS")
    except (GateError, RolloutStop, StateError, AttestationError, BackupEvidenceError) as exc:
        print(f"[rollout] STOP ({args.phase}): {exc}", file=sys.stderr)
        return 3
    _log(f"phase {args.phase} complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
