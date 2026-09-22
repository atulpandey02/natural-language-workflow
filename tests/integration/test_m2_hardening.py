"""M2b policy hardening (migration 0005): no direct membership writes, no
cross-tenant reads via forged/unsigned context, atomic workspace bootstrap."""

import uuid
from types import SimpleNamespace

import psycopg
import pytest

from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

_TENANT_TABLES = (
    "workspaces",
    "memberships",
    "workflows",
    "workflow_versions",
    "workflow_runs",
    "step_runs",
)


def test_app_cannot_insert_membership(pg_stack: SimpleNamespace) -> None:
    """Direct self-insertion into an existing tenant must be denied (no grant)."""
    member = pg_stack.seed_member()  # existing tenant B
    attacker = pg_stack.seed_user()
    with (
        psycopg.connect(pg_stack.app_libpq) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        pg_stack.apply_ctx(c, pg_stack.sign(Purpose.API_IDENTITY, user_id=attacker))
        c.execute(
            "INSERT INTO memberships (id, user_id, workspace_id, role) VALUES (%s,%s,%s,'owner')",
            (uuid.uuid4(), attacker, member.tenant_id),
        )


def test_app_cannot_insert_workspace_directly(pg_stack: SimpleNamespace) -> None:
    attacker = pg_stack.seed_user()
    with (
        psycopg.connect(pg_stack.app_libpq) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        pg_stack.apply_ctx(c, pg_stack.sign(Purpose.API_IDENTITY, user_id=attacker))
        c.execute(
            "INSERT INTO workspaces (id, name, slug) VALUES (%s,%s,%s)",
            (uuid.uuid4(), "x", f"x-{uuid.uuid4()}"),
        )


def test_workspace_bootstrap_creates_exactly_one_owner_membership(
    pg_stack: SimpleNamespace,
) -> None:
    user_id = pg_stack.seed_user()
    with psycopg.connect(pg_stack.app_libpq) as c:
        pg_stack.apply_ctx(c, pg_stack.sign(Purpose.API_IDENTITY, user_id=user_id))
        row = c.execute(
            "SELECT create_workspace_for_current_user(%s, %s)", ("Acme", f"acme-{uuid.uuid4()}")
        ).fetchone()
        c.commit()
    assert row is not None
    workspace_id = row[0]
    with psycopg.connect(pg_stack.owner_libpq) as c:
        members = c.execute(
            "SELECT user_id, role FROM memberships WHERE workspace_id=%s", (workspace_id,)
        ).fetchall()
    assert members == [(user_id, "owner")]


def test_nonmember_cannot_read_m2_tables_via_forged_gucs(pg_stack: SimpleNamespace) -> None:
    member = pg_stack.seed_member()  # tenant B, member userB
    attacker = pg_stack.seed_user()  # not a member of B
    with psycopg.connect(pg_stack.app_libpq) as c:
        # A SIGNED (attacker, tenant B) pair: authentic signature, no membership.
        pg_stack.apply_ctx(
            c, pg_stack.sign(Purpose.API_REQUEST, user_id=attacker, tenant_id=member.tenant_id)
        )
        ws = c.execute(
            "SELECT count(*) FROM workspaces WHERE id=%s", (member.tenant_id,)
        ).fetchone()
        mem = c.execute(
            "SELECT count(*) FROM memberships WHERE workspace_id=%s", (member.tenant_id,)
        ).fetchone()
        c.rollback()
    assert ws is not None and ws[0] == 0
    assert mem is not None and mem[0] == 0


def test_member_can_read_own_workspace(pg_stack: SimpleNamespace) -> None:
    member = pg_stack.seed_member()
    with psycopg.connect(pg_stack.app_libpq) as c:
        pg_stack.apply_ctx(c, pg_stack.sign(Purpose.API_IDENTITY, user_id=member.user_id))
        ws = c.execute(
            "SELECT count(*) FROM workspaces WHERE id=%s", (member.tenant_id,)
        ).fetchone()
        c.rollback()
    assert ws is not None and ws[0] == 1


def test_no_public_policies_on_tenant_tables(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.owner_libpq) as c:
        rows = c.execute(
            "SELECT tablename, policyname, roles FROM pg_policies "
            "WHERE schemaname='public' AND tablename = ANY(%s)",
            (list(_TENANT_TABLES),),
        ).fetchall()
    assert rows, "expected policies to exist"
    for tablename, policyname, roles in rows:
        assert "public" not in roles, f"{tablename}.{policyname} applies to PUBLIC: {roles}"
        # Trusted least-privilege runtime roles only (M8 adds nlw_scheduler).
        assert set(roles) <= {
            "nlw_app",
            "nlw_worker",
            "nlw_scheduler",
        }, f"{tablename}.{policyname} roles={roles}"


def test_bypass_role_is_read_only(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.owner_libpq) as c:
        for table in ("memberships", "workflow_runs"):
            for priv in ("INSERT", "UPDATE", "DELETE"):
                row = c.execute(
                    "SELECT has_table_privilege('nlw_rls_bypass', %s, %s)", (table, priv)
                ).fetchone()
                assert row is not None and row[0] is False, f"nlw_rls_bypass has {priv} on {table}"
