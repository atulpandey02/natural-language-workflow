"""Offboarding foundation: every public table is classified against the plan's
offboarding matrix, and the inventory counts one workspace's rows only."""

import uuid
from types import SimpleNamespace

import psycopg
import pytest

from nlw.ops import offboarding

pytestmark = pytest.mark.integration


def test_every_table_at_head_is_classified(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.owner_libpq) as conn:
        assert offboarding.unclassified_tables(conn) == []
        assert offboarding.scope_mismatches(conn) == []


def test_inventory_counts_only_the_requested_workspace(pg_stack: SimpleNamespace) -> None:
    a = pg_stack.seed_member("owner")
    b = pg_stack.seed_member("owner")
    pg_stack.add_membership(a.tenant_id, "member")
    with psycopg.connect(pg_stack.owner_libpq) as conn:
        conn.execute(
            "INSERT INTO workflows (id, tenant_id, name) VALUES (%s, %s, 'wf')",
            (uuid.uuid4(), a.tenant_id),
        )
        conn.commit()
        inv_a = offboarding.inventory(conn, a.tenant_id)
        inv_b = offboarding.inventory(conn, b.tenant_id)
    assert inv_a["tables"]["memberships"]["rows"] == 2
    assert inv_a["tables"]["workspaces"]["rows"] == 1
    assert inv_a["tables"]["workflows"]["rows"] == 1
    assert inv_b["tables"]["workflows"]["rows"] == 0
    assert inv_b["tables"]["memberships"]["rows"] == 1
    assert "users" not in inv_a["tables"]  # platform tables are not tenant data
    assert inv_a["tables"]["external_actions"]["on_offboarding"].startswith("retain")
