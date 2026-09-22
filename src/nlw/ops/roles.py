"""Idempotent runtime-role provisioning for EXISTING databases (M12A-Prep §D).

Fresh volumes get every role from ``docker/postgres/initdb/00-roles.sh``. A
database created before P3A/P3B lacks ``nlw_membership_admin`` and
``nlw_ctx_verifier``; migration 0015/0016 then fails because they own objects.
This module creates ONLY those two NOLOGIN roles with their exact attributes,
verifies every other nlw role still has the attributes the security model
expects, and fails on any incompatible existing role instead of altering it.
It grants nothing on application tables — that belongs to the migrations.

    python -m nlw.ops.roles verify   # read-only; exit 0 iff the model holds
    python -m nlw.ops.roles ensure   # create the two missing roles, then verify

Runs with the owner/migration credential (``DATABASE_MIGRATION_URL``), e.g.
through the Compose ``migrate`` service, never with a runtime role.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass

import psycopg
import structlog
from psycopg import sql

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class RoleModel:
    canlogin: bool
    superuser: bool
    bypassrls: bool
    createdb: bool = False
    createrole: bool = False


# The complete expected model. Attribute drift on ANY of these is an error.
EXPECTED: dict[str, RoleModel] = {
    "nlw_app": RoleModel(True, False, False),
    "nlw_worker": RoleModel(True, False, False),
    "nlw_scheduler": RoleModel(True, False, False),
    "nlw_rls_bypass": RoleModel(False, False, True),
    "nlw_workspace_bootstrap": RoleModel(False, False, True),
    "nlw_membership_admin": RoleModel(False, False, True),
    "nlw_ctx_verifier": RoleModel(False, False, False),
}
# Only these may be CREATED here (the P3A/P3B owners); all others must pre-exist.
PROVISIONABLE = ("nlw_membership_admin", "nlw_ctx_verifier")
# The owner must be a member of each NOLOGIN owner role to (re)assign ownership.
OWNER_MEMBER_OF = ("nlw_rls_bypass", "nlw_workspace_bootstrap", *PROVISIONABLE)
_CREATE_SQL = {
    "nlw_membership_admin": (
        "CREATE ROLE nlw_membership_admin NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE"
    ),
    "nlw_ctx_verifier": (
        "CREATE ROLE nlw_ctx_verifier NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"
    ),
}


class RoleProvisioningError(RuntimeError):
    pass


def _libpq(url: str) -> str:
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


def read_roles(conn: psycopg.Connection) -> dict[str, RoleModel]:
    rows = conn.execute(
        "SELECT rolname, rolcanlogin, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole "
        "FROM pg_roles WHERE rolname LIKE 'nlw\\_%' ORDER BY rolname"
    ).fetchall()
    return {r[0]: RoleModel(r[1], r[2], r[3], r[4], r[5]) for r in rows}


def read_memberships(conn: psycopg.Connection) -> dict[str, set[str]]:
    """role -> set of roles that are members of it."""
    rows = conn.execute(
        "SELECT r.rolname, m.rolname FROM pg_auth_members am "
        "JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member "
        "WHERE r.rolname LIKE 'nlw\\_%'"
    ).fetchall()
    out: dict[str, set[str]] = {}
    for role, member in rows:
        out.setdefault(role, set()).add(member)
    return out


def owner_role(conn: psycopg.Connection) -> str:
    return str(conn.execute("SELECT current_user").fetchone()[0])  # type: ignore[index]


def verify_roles(conn: psycopg.Connection, *, require_all: bool) -> list[str]:
    """Return a list of problems (empty == model holds). ``require_all=False``
    tolerates the two provisionable roles being absent (pre-upgrade state)."""
    roles = read_roles(conn)
    members = read_memberships(conn)
    owner = owner_role(conn)
    problems: list[str] = []
    for name, want in EXPECTED.items():
        got = roles.get(name)
        if got is None:
            if name in PROVISIONABLE and not require_all:
                continue
            problems.append(f"{name}: missing")
            continue
        if got != want:
            problems.append(f"{name}: attributes {got} != expected {want} (refusing to alter)")
    for name in roles:
        if name not in EXPECTED:
            problems.append(f"{name}: unexpected nlw_* role")
    # Memberships: runtime login roles must be members of nothing; the owner
    # must be a member of each existing NOLOGIN owner role; nothing else.
    for name, mem in members.items():
        allowed = {owner} if name in OWNER_MEMBER_OF else set()
        extra = mem - allowed
        if extra:
            problems.append(f"{name}: unexpected members {sorted(extra)}")
    for name in OWNER_MEMBER_OF:
        if name in roles and owner not in members.get(name, set()):
            problems.append(f"{name}: owner {owner} is not a member (cannot reassign ownership)")
    return problems


def ensure_roles(conn: psycopg.Connection) -> list[str]:
    """Create the missing provisionable roles (idempotent) and grant them to the
    owner; then verify the whole model. Returns the names created."""
    pre = verify_roles(conn, require_all=False)
    if pre:
        raise RoleProvisioningError("existing role model is incompatible: " + "; ".join(pre))
    roles = read_roles(conn)
    owner = owner_role(conn)
    created: list[str] = []
    with conn.transaction():
        for name in PROVISIONABLE:
            if name not in roles:
                conn.execute(_CREATE_SQL[name])
                created.append(name)
            # GRANT is idempotent (NOTICE if already a member). Identifiers are
            # composed, never interpolated (platform SQL-injection guard).
            conn.execute(
                sql.SQL("GRANT {} TO {}").format(sql.Identifier(name), sql.Identifier(owner))
            )
    post = verify_roles(conn, require_all=True)
    if post:
        raise RoleProvisioningError("role model invalid after provisioning: " + "; ".join(post))
    return created


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="nlw.ops.roles")
    p.add_argument("cmd", choices=("verify", "ensure"))
    p.add_argument("--require-all", action="store_true", help="verify: P3A/P3B roles must exist")
    a = p.parse_args(argv)
    url = os.environ.get("DATABASE_MIGRATION_URL", "")
    if not url:
        print("DATABASE_MIGRATION_URL is required (owner credential)", file=sys.stderr)
        return 2
    try:
        with psycopg.connect(_libpq(url), autocommit=True) as conn:
            if a.cmd == "verify":
                problems = verify_roles(conn, require_all=a.require_all)
                for pr in problems:
                    print(f"PROBLEM: {pr}")
                print("roles: OK" if not problems else f"roles: {len(problems)} problem(s)")
                return 0 if not problems else 1
            created = ensure_roles(conn)
            log.info("roles.ensure", created=created)
            print(f"roles: ensured (created: {', '.join(created) or 'none'})")
            return 0
    except RoleProvisioningError as exc:
        print(f"roles FAILED: {exc}", file=sys.stderr)
        return 3
    except psycopg.Error as exc:
        print(f"roles FAILED: {type(exc).__name__}", file=sys.stderr)  # sanitized
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
