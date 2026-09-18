"""Database-enforced tenant isolation (RLS), proven at the SQL layer.

Seeds two tenants as the owner, then connects as the restricted ``nlw_app`` role
and shows that RLS — not application code — makes tenant B's rows invisible.
"""

import uuid
from types import SimpleNamespace

import psycopg
import pytest

pytestmark = pytest.mark.integration


def _seed(owner_libpq: str) -> tuple[uuid.UUID, uuid.UUID]:
    a_ws, b_ws = uuid.uuid4(), uuid.uuid4()
    a_user, b_user = uuid.uuid4(), uuid.uuid4()
    with psycopg.connect(owner_libpq, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s),(%s,%s,%s)",
            (a_user, "a-sub", "a@x.io", b_user, "b-sub", "b@x.io"),
        )
        conn.execute(
            "INSERT INTO workspaces (id, name, slug) VALUES (%s,%s,%s),(%s,%s,%s)",
            (a_ws, "A", "a-slug", b_ws, "B", "b-slug"),
        )
        conn.execute(
            "INSERT INTO memberships (id, user_id, workspace_id, role) "
            "VALUES (%s,%s,%s,'owner'),(%s,%s,%s,'owner')",
            (uuid.uuid4(), a_user, a_ws, uuid.uuid4(), b_user, b_ws),
        )
    return a_ws, b_ws


def test_rls_scopes_reads_to_the_active_tenant(pg_stack: SimpleNamespace) -> None:
    a_ws, b_ws = _seed(pg_stack.owner_libpq)

    # As the restricted role, scoped to tenant A via the tenant GUC:
    with psycopg.connect(pg_stack.app_libpq) as conn:  # transaction (autocommit off)
        conn.execute("SELECT set_config('app.tenant_id', %s, true)", (str(a_ws),))
        ws_ids = {r[0] for r in conn.execute("SELECT id FROM workspaces").fetchall()}
        mem_ws = {r[0] for r in conn.execute("SELECT workspace_id FROM memberships").fetchall()}
        conn.rollback()

    assert a_ws in ws_ids and b_ws not in ws_ids
    assert a_ws in mem_ws and b_ws not in mem_ws


def test_rls_denies_when_no_tenant_context(pg_stack: SimpleNamespace) -> None:
    _seed(pg_stack.owner_libpq)
    with psycopg.connect(pg_stack.app_libpq) as conn:
        workspaces = conn.execute("SELECT count(*) FROM workspaces").fetchone()
        memberships = conn.execute("SELECT count(*) FROM memberships").fetchone()
        conn.rollback()
    assert workspaces is not None and workspaces[0] == 0
    assert memberships is not None and memberships[0] == 0


def test_runtime_role_cannot_bypass_rls(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as conn:
        row = conn.execute(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'nlw_app'"
        ).fetchone()
    assert row is not None
    assert row == (False, False)
