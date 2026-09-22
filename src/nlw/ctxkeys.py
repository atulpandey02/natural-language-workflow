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

Every lifecycle change appends to ``ctx_key_events`` (id, class, event, actor) —
never material. Exit codes: 0 ok, 1 operation failed, 2 usage, 3 mismatch.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from datetime import datetime

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


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m nlw.ctxkeys")
    sub = p.add_subparsers(dest="cmd", required=True)
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
