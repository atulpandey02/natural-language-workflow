"""Database-enforced tenant isolation (RLS), proven at the SQL layer.

Seeds two tenants (each with its own member) and shows that, as the restricted
``nlw_app`` role, RLS — not application code — makes another tenant's rows
invisible. `nlw_app` visibility is membership-bound (0004/0005), so a member of
tenant A sees A's workspace and their own membership, never tenant B's.
"""

import uuid
from types import SimpleNamespace

import psycopg
import pytest

pytestmark = pytest.mark.integration


def _seed(owner_libpq: str) -> SimpleNamespace:
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
    return SimpleNamespace(a_ws=a_ws, b_ws=b_ws, a_user=a_user, b_user=b_user)


def test_rls_scopes_reads_to_membership(pg_stack: SimpleNamespace) -> None:
    seeded = _seed(pg_stack.owner_libpq)

    # As nlw_app acting as user A: sees A's workspace + own membership, never B's.
    with psycopg.connect(pg_stack.app_libpq) as conn:  # transaction (autocommit off)
        conn.execute("SELECT set_config('app.user_id', %s, true)", (str(seeded.a_user),))
        ws_ids = {r[0] for r in conn.execute("SELECT id FROM workspaces").fetchall()}
        mem_ws = {r[0] for r in conn.execute("SELECT workspace_id FROM memberships").fetchall()}
        conn.rollback()

    assert seeded.a_ws in ws_ids and seeded.b_ws not in ws_ids
    assert seeded.a_ws in mem_ws and seeded.b_ws not in mem_ws


def test_rls_denies_when_no_context(pg_stack: SimpleNamespace) -> None:
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
