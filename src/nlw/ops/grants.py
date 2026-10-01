"""Operator tooling for workspace-creation grants (Phase 2 B01, migration 0022).

Founding a workspace requires a grant for the founder's email. Grants live in a
platform table that no runtime role can read or write; operators manage them
with the OWNER credential (``DATABASE_MIGRATION_URL``), exactly like
``python -m nlw.ctxkeys``::

    python -m nlw.ops.grants add --email founder@example.com --expires-in 72h --note "pilot 3"
    python -m nlw.ops.grants list [--all]
    python -m nlw.ops.grants revoke --id <grant-uuid>

A grant is single-use: the database consumes it when the workspace is created
and records ``workspace.created`` in ``authz_audit_events``. Grants are never
deleted; revocation and consumption are recorded on the row. Structured logs
carry grant ids only, never email addresses.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import uuid
from datetime import timedelta
from typing import Any

import psycopg
import structlog

log = structlog.get_logger(__name__)

MAX_EXPIRY = timedelta(days=30)
_DURATION = re.compile(r"^(\d{1,4})([hd])$")
# Deliberately permissive: the identity provider verifies the address; this
# only rejects obvious operator typos before they become an unusable grant.
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class GrantError(ValueError):
    """An operator input or state error (message is safe to print)."""


def normalize_email(email: str) -> str:
    """The same normalisation the database applies: ``lower(btrim(email))``."""
    value = email.strip().lower()
    if not _EMAIL.match(value) or len(value) > 320:
        raise GrantError("not a valid email address")
    return value


def parse_expiry(text: str) -> timedelta:
    """``72h`` / ``7d``; must be positive and at most 30 days."""
    m = _DURATION.match(text.strip())
    if not m:
        raise GrantError("expiry must look like 72h or 7d")
    n, unit = int(m.group(1)), m.group(2)
    delta = timedelta(hours=n) if unit == "h" else timedelta(days=n)
    if delta <= timedelta(0) or delta > MAX_EXPIRY:
        raise GrantError("expiry must be between 1h and 30d")
    return delta


def _actor() -> str:
    actor = os.environ.get("NLW_OPERATOR") or os.environ.get("USER") or ""
    if not actor.strip():
        raise GrantError("set NLW_OPERATOR to the operator's name")
    return actor.strip()[:200]


def _owner_url() -> str:
    url = os.environ.get("DATABASE_MIGRATION_URL")
    if not url:
        raise SystemExit("DATABASE_MIGRATION_URL (owner credential) is required")
    return url.replace("+psycopg", "", 1)


def add_grant(
    conn: psycopg.Connection[Any],
    *,
    email: str,
    expires_in: timedelta,
    granted_by: str,
    note: str | None = None,
) -> uuid.UUID:
    """Create one open grant. Refuses a second open grant for the same email."""
    if note is not None and len(note) > 200:
        raise GrantError("note must be at most 200 characters")
    grant_id = uuid.uuid4()
    try:
        with conn.transaction():
            conn.execute(
                "INSERT INTO workspace_creation_grants "
                "(id, email_normalized, granted_by, note, expires_at) "
                "VALUES (%s, %s, %s, %s, now() + %s)",
                (grant_id, normalize_email(email), granted_by, note, expires_in),
            )
    except psycopg.errors.UniqueViolation as exc:
        raise GrantError("an open grant for this email already exists") from exc
    return grant_id


def revoke_grant(conn: psycopg.Connection[Any], *, grant_id: uuid.UUID, revoked_by: str) -> None:
    """Revoke an open grant. A consumed or already-revoked grant is refused."""
    with conn.transaction():
        cur = conn.execute(
            "UPDATE workspace_creation_grants SET revoked_at = now(), revoked_by = %s "
            "WHERE id = %s AND consumed_at IS NULL AND revoked_at IS NULL",
            (revoked_by, grant_id),
        )
        if cur.rowcount != 1:
            raise GrantError("no open grant with that id")


def list_grants(conn: psycopg.Connection[Any], *, include_closed: bool) -> list[tuple[Any, ...]]:
    return conn.execute(
        "SELECT id, email_normalized, granted_by, created_at, expires_at, "
        "CASE WHEN consumed_at IS NOT NULL THEN 'consumed' "
        "     WHEN revoked_at IS NOT NULL THEN 'revoked' "
        "     WHEN expires_at <= now() THEN 'expired' ELSE 'open' END, "
        "consumed_workspace_id FROM workspace_creation_grants "
        "WHERE %s OR (consumed_at IS NULL AND revoked_at IS NULL) "
        "ORDER BY created_at",
        (include_closed,),
    ).fetchall()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m nlw.ops.grants")
    sub = p.add_subparsers(dest="cmd", required=True)
    add = sub.add_parser("add")
    add.add_argument("--email", required=True)
    add.add_argument("--expires-in", default="72h")
    add.add_argument("--note", default=None)
    lst = sub.add_parser("list")
    lst.add_argument("--all", action="store_true", help="include consumed/revoked grants")
    rev = sub.add_parser("revoke")
    rev.add_argument("--id", required=True)
    args = p.parse_args(argv)

    try:
        with psycopg.connect(_owner_url()) as conn:
            if args.cmd == "add":
                gid = add_grant(
                    conn,
                    email=args.email,
                    expires_in=parse_expiry(args.expires_in),
                    granted_by=_actor(),
                    note=args.note,
                )
                log.info("grants.add", grant_id=str(gid))
                print(f"granted: {gid}")
                return 0
            if args.cmd == "revoke":
                try:
                    gid = uuid.UUID(args.id)
                except ValueError as exc:
                    raise GrantError("--id must be a UUID") from exc
                revoke_grant(conn, grant_id=gid, revoked_by=_actor())
                log.info("grants.revoke", grant_id=str(gid))
                print(f"revoked: {gid}")
                return 0
            for row in list_grants(conn, include_closed=args.all):
                print("\t".join("" if v is None else str(v) for v in row))
            return 0
    except GrantError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
