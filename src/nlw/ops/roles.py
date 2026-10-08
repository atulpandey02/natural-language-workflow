"""Idempotent runtime-role provisioning for EXISTING databases (M12A-Prep §D).

Fresh volumes get every role from ``docker/postgres/initdb/00-roles.sh``. A
database created before P3A/P3B lacks ``nlw_membership_admin`` and
``nlw_ctx_verifier``; migration 0015/0016 then fails because they own objects.
A database created before ADR-031 lacks ``nlw_ingest``; migration 0026 grants
to it (and 0027 to ``nlw_ingest_dispatch``, ADR-032). This module creates ONLY
those roles, NOLOGIN, with their exact attributes (the ingest runtime and its
dispatcher stay dormant NOLOGIN runtime roles until they are explicitly enabled,
owner decision O-6), verifies every other nlw role still has
the attributes the security model expects, and fails on any incompatible
existing role instead of altering it. It grants nothing on application tables —
that belongs to the migrations.

    python -m nlw.ops.roles verify   # read-only; exit 0 iff the model holds
    python -m nlw.ops.roles ensure   # create the missing roles, then verify

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
    # Dormant ingest runtime (ADR-031) and its dispatcher (ADR-032): NOLOGIN
    # until enabled (O-6).
    "nlw_ingest": RoleModel(False, False, False),
    "nlw_ingest_dispatch": RoleModel(False, False, False),
}
# The ONE other model a role may have: an ENABLED ingest runtime (a LOGIN role,
# as development/CI create it from NLW_INGEST_DB_PASSWORD). Still never
# superuser/bypassrls/createdb/createrole. Deployed gates are stricter.
ENABLED_VARIANTS: dict[str, RoleModel] = {
    "nlw_ingest": RoleModel(True, False, False),
    "nlw_ingest_dispatch": RoleModel(True, False, False),
}
# The NOLOGIN object owners this module may create (P3A/P3B) ...
OWNER_PROVISIONABLE = ("nlw_membership_admin", "nlw_ctx_verifier")
# ... and the dormant runtime roles (ADR-031/032). All others must pre-exist.
PROVISIONABLE = (*OWNER_PROVISIONABLE, "nlw_ingest", "nlw_ingest_dispatch")
# The owner must be a member of each NOLOGIN owner role to (re)assign ownership.
# Never of a runtime role.
OWNER_MEMBER_OF = ("nlw_rls_bypass", "nlw_workspace_bootstrap", *OWNER_PROVISIONABLE)
_CREATE_SQL = {
    "nlw_membership_admin": (
        "CREATE ROLE nlw_membership_admin NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE"
    ),
    "nlw_ctx_verifier": (
        "CREATE ROLE nlw_ctx_verifier NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"
    ),
    "nlw_ingest": (
        "CREATE ROLE nlw_ingest NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT"
    ),
    "nlw_ingest_dispatch": (
        "CREATE ROLE nlw_ingest_dispatch NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB "
        "NOCREATEROLE NOINHERIT"
    ),
}


class RoleProvisioningError(RuntimeError):
    pass


# The EXACT explicit privileges of the ingest runtime role (migration 0026,
# ADR-031): "<table>:<PRIV>" for table grants, "<table>:<PRIV>:<column>" for
# column grants. Anything missing or extra is a deployment error (rollout gate,
# restore validation). Read with ``INGEST_GRANTS_SQL`` (catalog ACLs only, so
# privileges implied by a table grant are not double-counted).
EXPECTED_INGEST_GRANTS: frozenset[str] = frozenset(
    {
        "datasets:SELECT",
        "dataset_versions:SELECT",
        "dataset_profiles:SELECT",
        "dataset_profiles:INSERT",
        "dataset_events:SELECT",
        "dataset_events:INSERT",
        "dataset_processing_requests:SELECT",
        *(
            f"dataset_versions:UPDATE:{c}"
            for c in (
                "status",
                "processing_lease_token",
                "processing_lease_expires_at",
                "storage_object_key",
                "rejection_code",
            )
        ),
        *(
            f"dr_restore_events:SELECT:{c}"
            for c in ("id", "restored_at", "validation_completed_at", "runtime_enabled_at")
        ),
    }
)


def _grants_sql(role: str, *, functions: bool = False) -> str:
    """Explicit table, column (and optionally function) ACL entries of ``role``
    in ``public``. ``role`` is a module constant, never input."""
    where = f"WHERE r.rolname = '{role}'"
    parts = [
        "SELECT c.relname || ':' || a.privilege_type FROM pg_class c "
        "CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_roles r ON r.oid = a.grantee "
        f"{where} AND c.relnamespace = 'public'::regnamespace",
        "SELECT c.relname || ':' || a.privilege_type || ':' || att.attname "
        "FROM pg_attribute att JOIN pg_class c ON c.oid = att.attrelid "
        "CROSS JOIN LATERAL aclexplode(att.attacl) a JOIN pg_roles r ON r.oid = a.grantee "
        f"{where} AND c.relnamespace = 'public'::regnamespace",
    ]
    if functions:
        parts.append(
            "SELECT p.proname || ':' || a.privilege_type FROM pg_proc p "
            "CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_roles r ON r.oid = a.grantee "
            f"{where} AND p.pronamespace = 'public'::regnamespace"
        )
    return " UNION ALL ".join(parts) + " ORDER BY 1"


INGEST_GRANTS_SQL = _grants_sql("nlw_ingest")


def ingest_grant_problems(actual: set[str]) -> list[str]:
    """Missing and excessive ingest privileges (empty == exact)."""
    problems = [f"nlw_ingest missing {g}" for g in sorted(EXPECTED_INGEST_GRANTS - actual)]
    problems += [f"nlw_ingest has extra {g}" for g in sorted(actual - EXPECTED_INGEST_GRANTS)]
    return problems


# The EXACT explicit privileges of the dataset dispatcher (migration 0027,
# ADR-032): the recovery-lock columns and EXECUTE on its one function, nothing
# on any dataset table. Same encoding as above plus "<function>:EXECUTE" for
# explicitly granted functions in ``public``.
EXPECTED_DISPATCH_GRANTS: frozenset[str] = frozenset(
    {
        "dataset_dispatch_pending:EXECUTE",
        *(
            f"dr_restore_events:SELECT:{c}"
            for c in ("id", "restored_at", "validation_completed_at", "runtime_enabled_at")
        ),
    }
)
DISPATCH_GRANTS_SQL = _grants_sql("nlw_ingest_dispatch", functions=True)


def dispatch_grant_problems(actual: set[str]) -> list[str]:
    """Missing and excessive dispatcher privileges (empty == exact)."""
    want = EXPECTED_DISPATCH_GRANTS
    problems = [f"nlw_ingest_dispatch missing {g}" for g in sorted(want - actual)]
    problems += [f"nlw_ingest_dispatch has extra {g}" for g in sorted(actual - want)]
    return problems


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
        if got != want and got != ENABLED_VARIANTS.get(name):
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
    """Create the missing provisionable roles (idempotent), grant the owner roles
    to the owner (never the runtime role); then verify the whole model. Returns
    the names created."""
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
            if name not in OWNER_PROVISIONABLE:
                continue
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
    p.add_argument(
        "--require-all", action="store_true", help="verify: provisionable roles must exist"
    )
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
