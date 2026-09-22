"""Least-privilege proof for the dedicated manage_membership owner (M11.5 P3A+ B).

``manage_membership`` is owned by ``nlw_membership_admin`` — a dedicated NOLOGIN
role created solely to own that one function, so the identity-bootstrap owner
(``nlw_workspace_bootstrap``) does not also become a general membership admin.

These tests pin its EXACT blast radius: it may only read/write ``memberships`` and
INSERT into ``authz_audit_events``; it can touch nothing else (no user email /
auth-provider identity, connectors, workflows, runs, actions, schedules, approvals,
invitations, backup/recovery state), cannot rewrite/erase the audit, is NOLOGIN and
NOSUPERUSER, and owns no other function. Regression guard against a future grant
silently widening it.
"""

from types import SimpleNamespace

import psycopg
import pytest

pytestmark = pytest.mark.integration

_OWNER = "nlw_membership_admin"

# Exactly the privileges the function needs — nothing else.
_ALLOWED = {
    ("memberships", "SELECT"),
    ("memberships", "UPDATE"),
    ("memberships", "DELETE"),
    ("authz_audit_events", "INSERT"),
}

# Sensitive tables the owner must NOT be able to reach at all.
_FORBIDDEN_TABLES = (
    "users",
    "connectors",
    "workflows",
    "workflow_versions",
    "workflow_runs",
    "step_runs",
    "external_actions",
    "schedules",
    "approvals",
    "workspace_invitations",
    "dr_restore_events",
    "plan_proposals",
)


def _has(c: psycopg.Connection, table: str, priv: str) -> bool:
    row = c.execute("SELECT has_table_privilege(%s, %s, %s)", (_OWNER, table, priv)).fetchone()
    return bool(row and row[0])


def test_membership_admin_is_nologin_nosuperuser(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT rolcanlogin, rolsuper, rolbypassrls FROM pg_roles WHERE rolname=%s", (_OWNER,)
        ).fetchone()
    assert row is not None, "nlw_membership_admin role is missing"
    canlogin, super_, bypassrls = row
    assert canlogin is False, "owner must be NOLOGIN"
    assert super_ is False, "owner must be NOSUPERUSER"
    # BYPASSRLS is required (memberships + authz_audit_events are FORCE RLS and the
    # function does its own authorization). Documented, and its reach is pinned below.
    assert bypassrls is True


def test_membership_admin_has_exactly_the_needed_grants(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.owner_libpq) as c:
        # It HAS precisely the allowed privileges on the two tables it uses.
        for table, priv in _ALLOWED:
            assert _has(c, table, priv), f"{_OWNER} missing required {priv} on {table}"
        # It does NOT hold INSERT on memberships (accept is a different owner's job)
        # nor UPDATE/DELETE on the audit (append-only).
        assert not _has(c, "memberships", "INSERT")
        assert not _has(c, "authz_audit_events", "SELECT")
        assert not _has(c, "authz_audit_events", "UPDATE")
        assert not _has(c, "authz_audit_events", "DELETE")


def test_membership_admin_cannot_touch_sensitive_tables(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.owner_libpq) as c:
        offenders = [
            f"{t}:{p}"
            for t in _FORBIDDEN_TABLES
            for p in ("SELECT", "INSERT", "UPDATE", "DELETE")
            if _has(c, t, p)
        ]
    assert offenders == [], f"{_OWNER} has unexpected access: {offenders}"


def test_membership_admin_owns_only_manage_membership(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.owner_libpq) as c:
        rows = c.execute(
            "SELECT p.proname FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner "
            "JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE r.rolname=%s AND n.nspname='public' ORDER BY p.proname",
            (_OWNER,),
        ).fetchall()
    owned = [str(r[0]) for r in rows]
    assert owned == ["manage_membership"], f"{_OWNER} owns unexpected functions: {owned}"


def test_membership_admin_cannot_execute_other_privileged_functions(
    pg_stack: SimpleNamespace,
) -> None:
    # It must not be able to EXECUTE the other SECURITY DEFINER helpers (e.g. the
    # invitation-accept function or the identity/workspace bootstrap functions).
    with psycopg.connect(pg_stack.owner_libpq) as c:
        for sig in (
            "accept_workspace_invitation(text)",
            "resolve_or_create_user(text, text)",
        ):
            row = c.execute(
                "SELECT has_function_privilege(%s, %s, 'EXECUTE')", (_OWNER, sig)
            ).fetchone()
            assert row is not None and row[0] is False, f"{_OWNER} can execute {sig}"
