"""Signed-context key registry operations: ``python -m nlw.ctxkeys`` (M11.5 P3B).

One-shot operator/installer commands that run with the OWNER/migration credential
(``DATABASE_MIGRATION_URL``) — never a runtime container's credential — and read
secret material ONLY from files (never argv, never env values):

  install  --class api|worker|scheduler --key-id ID --secret-file PATH [--activate-at ISO]
           Idempotent by key id: an existing row with the SAME class and material is
           a no-op; a DIFFERENT class or material for that id FAILS (never replaced).
  revoke   --key-id ID [--retire-at ISO]
           Explicit revocation (immediately) or a scheduled retirement (overlap).
  list     Non-secret inventory: id, class, status, activation/retirement, fingerprint.
  check    --class ... --key-id ID --secret-file PATH
           Verifies the registry holds an ACTIVE key of that class whose material
           matches the file (by sha256), without printing anything secret.

File-only commands (NO database; production key preparation, M12A-Prep §E):

  prepare      --dir DIR --class C --owner UID[:GID]
           Generate a fresh 32-byte random key for ONE class into DIR/<class>.key
           (umask 077, then chown to the container user and chmod 0400; DIR is
           created 0700 root-owned). Refuses to overwrite an existing file or to
           write through a symlink/directory. Prints only "prepared <class> <fp>"
           where <fp> is the sha256 fingerprint — never material.
  fingerprint  --dir DIR --key-id-api ID --key-id-worker ID --key-id-scheduler ID
           Strictly validates each key file's placement (regular file, 0400,
           owner uid, >=32 bytes hex) and prints "<class> <key_id> <sha256>" lines
           for the escrow attestation / rollout gate. Never prints material.
  verify-files --dir DIR [--owner UID]
           Placement checks only (exit 0 iff all three files are valid).

Every lifecycle change appends to ``ctx_key_events`` (id, class, event, actor) —
never material. Exit codes: 0 ok, 1 operation failed, 2 usage, 3 mismatch.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import secrets
import stat
import sys
from datetime import datetime
from pathlib import Path

import psycopg
import structlog

from nlw.tenancy.signing import (
    ContextSigningError,
    SecretBytes,
    load_key_file,
)

log = structlog.get_logger(__name__)

_CLASSES = ("api", "worker", "scheduler")


class KeyMismatch(RuntimeError):
    """The registry already holds this key id with different class/material."""


def _owner_url() -> str:
    url = os.environ.get("DATABASE_MIGRATION_URL") or os.environ.get("NLW_CTX_ADMIN_DATABASE_URL")
    if not url:
        raise SystemExit("DATABASE_MIGRATION_URL (owner credential) is required")
    return url.replace("+psycopg", "", 1)


def _actor() -> str:
    return os.environ.get("NLW_CTX_OPERATOR") or os.environ.get("USER") or "unknown"


def install_key(
    conn: psycopg.Connection,
    *,
    key_class: str,
    key_id: str,
    secret: SecretBytes,
    activate_at: datetime | None,
    actor: str,
) -> str:
    """Install (idempotent by id). Returns 'installed' | 'unchanged'. Raises KeyMismatch."""
    if key_class not in _CLASSES:
        raise ValueError("invalid key class")
    digest = hashlib.sha256(secret.reveal()).hexdigest()
    with conn.transaction():
        row = conn.execute(
            "SELECT key_class, secret_sha256 FROM ctx_keys WHERE key_id = %s FOR UPDATE",
            (key_id,),
        ).fetchone()
        if row is not None:
            if row[0] == key_class and row[1] == digest:
                return "unchanged"
            raise KeyMismatch(f"key id {key_id!r} exists with different class or material")
        conn.execute(
            "INSERT INTO ctx_keys (key_id, key_class, secret, secret_sha256, status, activated_at)"
            " VALUES (%s, %s, %s, %s, 'active', COALESCE(%s, now()))",
            (key_id, key_class, secret.reveal(), digest, activate_at),
        )
        conn.execute(
            "INSERT INTO ctx_key_events (key_id, key_class, event, actor) VALUES (%s, %s, %s, %s)",
            (key_id, key_class, "installed", actor),
        )
    return "installed"


def revoke_key(
    conn: psycopg.Connection, *, key_id: str, retire_at: datetime | None, actor: str
) -> str:
    """Immediate revocation (default) or scheduled retirement for a rotation overlap."""
    with conn.transaction():
        row = conn.execute(
            "SELECT key_class, status FROM ctx_keys WHERE key_id = %s FOR UPDATE", (key_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown key id {key_id!r}")
        key_class = row[0]
        if retire_at is not None:
            conn.execute(
                "UPDATE ctx_keys SET retired_at = %s WHERE key_id = %s", (retire_at, key_id)
            )
            event = "retired"
        else:
            conn.execute(
                "UPDATE ctx_keys SET status = 'revoked', revoked_at = now() WHERE key_id = %s",
                (key_id,),
            )
            event = "revoked"
        conn.execute(
            "INSERT INTO ctx_key_events (key_id, key_class, event, actor) VALUES (%s, %s, %s, %s)",
            (key_id, key_class, event, actor),
        )
    return event


def list_keys(conn: psycopg.Connection) -> list[tuple[object, ...]]:
    return conn.execute(
        "SELECT key_id, key_class, status, activated_at, retired_at, revoked_at, "
        "left(secret_sha256, 16) FROM ctx_keys ORDER BY created_at"
    ).fetchall()


def check_key(
    conn: psycopg.Connection, *, key_class: str, key_id: str, secret: SecretBytes
) -> bool:
    digest = hashlib.sha256(secret.reveal()).hexdigest()
    row = conn.execute(
        "SELECT 1 FROM ctx_keys WHERE key_id = %s AND key_class = %s AND secret_sha256 = %s "
        "AND status = 'active' AND activated_at <= now() "
        "AND (retired_at IS NULL OR retired_at > now())",
        (key_id, key_class, digest),
    ).fetchone()
    return row is not None


def _parse_dt(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


# --- file-only key preparation (no database) ---------------------------------

KEY_FILE_MODE = 0o400
KEY_DIR_MODE = 0o700
_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")


class KeyFileError(RuntimeError):
    """A key file is missing, mis-placed, mis-owned, mis-moded or malformed."""


def _parse_owner(value: str) -> tuple[int, int]:
    uid_s, _, gid_s = value.partition(":")
    if not uid_s.isdigit() or (gid_s and not gid_s.isdigit()):
        raise KeyFileError("--owner must be UID or UID:GID (numeric)")
    uid = int(uid_s)
    return uid, int(gid_s) if gid_s else uid


def validate_key_id(key_id: str) -> str:
    if not _KEY_ID_RE.match(key_id):
        raise KeyFileError("key id must be 3-64 chars of [a-z0-9._-] starting alphanumeric")
    return key_id


def check_key_file_placement(path: Path, *, owner_uid: int | None) -> None:
    """Strict placement rules for a production key file. Never reads content
    beyond what is needed to validate its format."""
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise KeyFileError(f"missing key file: {path.name}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise KeyFileError(f"key file is a symlink: {path.name}")
    if not stat.S_ISREG(st.st_mode):
        raise KeyFileError(f"key file is not a regular file: {path.name}")
    if stat.S_IMODE(st.st_mode) != KEY_FILE_MODE:
        raise KeyFileError(
            f"key file mode is {stat.S_IMODE(st.st_mode):04o}, want 0400: {path.name}"
        )
    if owner_uid is not None and st.st_uid != owner_uid:
        raise KeyFileError(f"key file owner uid {st.st_uid} != {owner_uid}: {path.name}")
    if st.st_size == 0:
        raise KeyFileError(f"key file is empty: {path.name}")
    raw = path.read_text(encoding="ascii", errors="strict").strip()
    if len(raw) < 64 or len(raw) % 2 or any(c not in "0123456789abcdefABCDEF" for c in raw):
        raise KeyFileError(f"key file is not >=32 bytes of hex: {path.name}")


def file_fingerprint(path: Path) -> str:
    raw = path.read_text(encoding="ascii").strip()
    return hashlib.sha256(bytes.fromhex(raw)).hexdigest()


def prepare_key_file(directory: Path, key_class: str, *, owner: tuple[int, int]) -> str:
    """Create DIR/<class>.key with fresh random material; return its fingerprint.
    Refuses to touch an existing path. The directory is created 0700 (owned by
    the caller, expected root) if absent; an existing directory keeps its
    owner but must be 0700 and not a symlink."""
    if key_class not in _CLASSES:
        raise KeyFileError("invalid key class")
    if directory.is_symlink():
        raise KeyFileError("key directory must not be a symlink")
    if directory.exists():
        if not directory.is_dir():
            raise KeyFileError("key directory path exists and is not a directory")
        if stat.S_IMODE(directory.stat().st_mode) != KEY_DIR_MODE:
            raise KeyFileError(f"key directory mode must be 0700: {directory}")
    else:
        directory.mkdir(mode=KEY_DIR_MODE, parents=False)
        os.chmod(directory, KEY_DIR_MODE)
    target = directory / f"{key_class}.key"
    if target.exists() or target.is_symlink():
        raise KeyFileError(f"refusing to overwrite existing {target.name}")
    material = secrets.token_hex(32)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(material + "\n")
        os.chown(target, owner[0], owner[1])
        os.chmod(target, KEY_FILE_MODE)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    fp = hashlib.sha256(bytes.fromhex(material)).hexdigest()
    del material
    return fp


def _add_file_commands(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    prep = sub.add_parser("prepare")
    prep.add_argument("--dir", required=True)
    prep.add_argument("--class", dest="key_class", choices=_CLASSES, required=True)
    prep.add_argument("--owner", required=True, help="container UID[:GID], e.g. 10001:10001")
    fpr = sub.add_parser("fingerprint")
    fpr.add_argument("--dir", required=True)
    for c in _CLASSES:
        fpr.add_argument(f"--key-id-{c}", required=True)
    fpr.add_argument("--owner", default="10001", help="expected file owner UID")
    fpr.add_argument("--insecure-permissions", action="store_true", help="tests/drills only")
    vf = sub.add_parser("verify-files")
    vf.add_argument("--dir", required=True)
    vf.add_argument("--owner", default="10001")


def _run_file_command(args: argparse.Namespace) -> int:
    directory = Path(args.dir)
    if args.cmd == "prepare":
        fp = prepare_key_file(directory, args.key_class, owner=_parse_owner(args.owner))
        print(f"prepared {args.key_class} {fp}")
        return 0
    owner_uid = _parse_owner(args.owner)[0]
    if args.cmd == "fingerprint" and args.insecure_permissions:
        owner_uid_opt: int | None = None
    else:
        owner_uid_opt = owner_uid
    for c in _CLASSES:
        path = directory / f"{c}.key"
        if args.cmd == "fingerprint" and args.insecure_permissions:
            load_key_file(path, strict_permissions=False)  # format only
        else:
            check_key_file_placement(path, owner_uid=owner_uid_opt)
        if args.cmd == "fingerprint":
            kid = validate_key_id(getattr(args, f"key_id_{c}"))
            print(f"{c} {kid} {file_fingerprint(path)}")
    if args.cmd == "verify-files":
        print("key files: OK")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m nlw.ctxkeys")
    sub = p.add_subparsers(dest="cmd", required=True)
    _add_file_commands(sub)
    ins = sub.add_parser("install")
    ins.add_argument("--class", dest="key_class", choices=_CLASSES, required=True)
    ins.add_argument("--key-id", required=True)
    ins.add_argument("--secret-file", required=True)
    ins.add_argument("--activate-at", default=None)
    ins.add_argument("--insecure-permissions", action="store_true", help="tests/drills only")
    rev = sub.add_parser("revoke")
    rev.add_argument("--key-id", required=True)
    rev.add_argument("--retire-at", default=None)
    sub.add_parser("list")
    chk = sub.add_parser("check")
    chk.add_argument("--class", dest="key_class", choices=_CLASSES, required=True)
    chk.add_argument("--key-id", required=True)
    chk.add_argument("--secret-file", required=True)
    chk.add_argument("--insecure-permissions", action="store_true", help="tests/drills only")
    args = p.parse_args(argv)

    if args.cmd in ("prepare", "fingerprint", "verify-files"):
        try:
            return _run_file_command(args)
        except (KeyFileError, ContextSigningError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)  # names only; never material
            return 1

    try:
        with psycopg.connect(_owner_url()) as conn:
            if args.cmd == "install":
                secret = load_key_file(
                    args.secret_file, strict_permissions=not args.insecure_permissions
                )
                outcome = install_key(
                    conn,
                    key_class=args.key_class,
                    key_id=args.key_id,
                    secret=secret,
                    activate_at=_parse_dt(args.activate_at),
                    actor=_actor(),
                )
                log.info(
                    "ctxkeys.install", key_id=args.key_id, key_class=args.key_class, outcome=outcome
                )
                print(f"{outcome}: {args.key_id} ({args.key_class})")
                return 0
            if args.cmd == "revoke":
                event = revoke_key(
                    conn, key_id=args.key_id, retire_at=_parse_dt(args.retire_at), actor=_actor()
                )
                # NB: ``event`` is structlog's reserved kwarg — never pass it by name.
                log.info("ctxkeys.revoke", key_id=args.key_id, outcome=event)
                print(f"{event}: {args.key_id}")
                return 0
            if args.cmd == "list":
                for row in list_keys(conn):
                    print("\t".join("" if v is None else str(v) for v in row))
                return 0
            secret = load_key_file(
                args.secret_file, strict_permissions=not args.insecure_permissions
            )
            ok = check_key(conn, key_class=args.key_class, key_id=args.key_id, secret=secret)
            print(f"{'ok' if ok else 'MISMATCH'}: {args.key_id} ({args.key_class})")
            return 0 if ok else 3
    except KeyMismatch as exc:
        print(f"MISMATCH: {exc}", file=sys.stderr)
        return 3
    except (ContextSigningError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
