"""Phase 2 migrations 0022-0024: up/down/up with the documented down-state.

``pg_stack`` starts at head, and the older reversibility tests only re-upgrade
to 0016, so neither Phase 2 revision was ever upgraded again after a downgrade.
This pins the behaviour the grants runbook and ADR-028 document:

- downgrading 0024 drops the three dataset metadata tables, their guard
  functions and 8 policies (53 left) — and with them any dataset metadata, which
  is why the runbook forbids it on a live environment;
- downgrading 0023 drops ``plan_outcome_events`` and its 2 policies (51 left);
- downgrading 0022 drops the grant ledger and ``has_workspace_creation_grant``
  and restores the UNGATED bootstrap (why the runbook forbids it on a live
  environment and the restore validator reports it);
- re-upgrading restores the gated bootstrap, the empty ledger and 61 policies.
"""

from types import SimpleNamespace

import psycopg
import pytest
from alembic import command
from alembic.config import Config

pytestmark = [pytest.mark.integration, pytest.mark.workspace_grants_enforced]

_BEFORE_PHASE2 = "0021_analytics_handoff"
_AFTER_0022 = "0022_workspace_creation_grants"
_AFTER_0023 = "0023_plan_outcome_events"
_DATASET_TABLES = ("datasets", "dataset_versions", "dataset_events")


def _posture(owner_libpq: str) -> dict[str, object]:
    with psycopg.connect(owner_libpq) as conn:

        def one(sql: str) -> object:
            row = conn.execute(sql).fetchone()
            assert row is not None
            return row[0]

        return {
            "revision": one("SELECT version_num FROM alembic_version"),
            "grants_table": one("SELECT to_regclass('public.workspace_creation_grants')"),
            "events_table": one("SELECT to_regclass('public.plan_outcome_events')"),
            "helper": one(
                "SELECT count(*) FROM pg_proc WHERE proname='has_workspace_creation_grant'"
            ),
            "bootstrap_gated": one(
                "SELECT bool_and(prosrc LIKE '%workspace_creation_grants%' "
                "AND prosrc LIKE '%42501%') FROM pg_proc "
                "WHERE proname='create_workspace_for_current_user'"
            ),
            "bootstrap_overloads": one(
                "SELECT count(*) FROM pg_proc WHERE proname='create_workspace_for_current_user'"
            ),
            "policies": one("SELECT count(*) FROM pg_policies WHERE schemaname='public'"),
            "dataset_tables": one(
                "SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace "
                "AND relname IN ('datasets','dataset_versions','dataset_events')"
            ),
            "dataset_funcs": one(
                "SELECT count(*) FROM pg_proc WHERE proname IN "
                "('dataset_guard','dataset_version_guard','dataset_consistency_check')"
            ),
        }


def test_phase2_revisions_go_up_down_up_with_the_documented_down_state(
    pg_stack: SimpleNamespace,
) -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", pg_stack.owner_sa)

    head = _posture(pg_stack.owner_libpq)
    assert head["revision"] == "0024_dataset_lifecycle"
    assert head["bootstrap_gated"] is True and head["bootstrap_overloads"] == 1
    assert head["helper"] == 1 and head["policies"] == 61
    assert head["dataset_tables"] == 3 and head["dataset_funcs"] == 3

    command.downgrade(cfg, _AFTER_0023)
    pre = _posture(pg_stack.owner_libpq)
    assert pre["revision"] == _AFTER_0023 and pre["policies"] == 53
    assert pre["dataset_tables"] == 0 and pre["dataset_funcs"] == 0
    assert pre["events_table"] is not None

    command.downgrade(cfg, _AFTER_0022)
    mid = _posture(pg_stack.owner_libpq)
    assert mid["events_table"] is None and mid["policies"] == 51
    assert mid["grants_table"] is not None and mid["bootstrap_gated"] is True

    command.downgrade(cfg, _BEFORE_PHASE2)
    down = _posture(pg_stack.owner_libpq)
    assert down["revision"] == _BEFORE_PHASE2
    assert down["grants_table"] is None and down["helper"] == 0
    assert down["bootstrap_overloads"] == 1
    assert down["bootstrap_gated"] is False  # the documented, ungated pre-0022 body
    assert down["policies"] == 51

    command.upgrade(cfg, "head")
    again = _posture(pg_stack.owner_libpq)
    assert again == head
    with psycopg.connect(pg_stack.owner_libpq) as conn:
        row = conn.execute("SELECT count(*) FROM workspace_creation_grants").fetchone()
    assert row == (0,)


def test_0023_to_0024_upgrade_preserves_existing_data_and_starts_empty(
    pg_stack: SimpleNamespace,
) -> None:
    """The live path: a populated 0023 database gains empty, forced-RLS dataset
    tables; nothing that existed before is rewritten."""
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", pg_stack.owner_sa)
    command.downgrade(cfg, _AFTER_0023)
    member = pg_stack.seed_member("owner")  # pilot-shaped data at 0023

    def snapshot() -> tuple[object, ...]:
        with psycopg.connect(pg_stack.owner_libpq) as conn:
            rows = conn.execute(
                "SELECT (SELECT count(*) FROM workspaces), (SELECT count(*) FROM memberships), "
                "(SELECT count(*) FROM users), (SELECT count(*) FROM plan_outcome_events), "
                "(SELECT md5(string_agg(id::text || name || slug, ',' ORDER BY id)) "
                "FROM workspaces)"
            ).fetchone()
        assert rows is not None
        return tuple(rows)

    before = snapshot()
    command.upgrade(cfg, "head")
    assert snapshot() == before
    with psycopg.connect(pg_stack.owner_libpq) as conn:
        for table in _DATASET_TABLES:
            flags = conn.execute(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE oid = to_regclass(%s)",
                (f"public.{table}",),
            ).fetchone()
            assert flags == (True, True), table
        counts = conn.execute(
            "SELECT (SELECT count(*) FROM datasets), (SELECT count(*) FROM dataset_versions), "
            "(SELECT count(*) FROM dataset_events)"
        ).fetchone()
        assert counts == (0, 0, 0)
        assert conn.execute(
            "SELECT count(*) FROM memberships WHERE workspace_id = %s", (member.tenant_id,)
        ).fetchone() == (1,)
