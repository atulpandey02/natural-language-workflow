"""Phase 2 migrations 0022 and 0023: up/down/up with the documented down-state.

``pg_stack`` starts at head, and the older reversibility tests only re-upgrade
to 0016, so neither Phase 2 revision was ever upgraded again after a downgrade.
This pins the behaviour the grants runbook and ADR-028 document:

- downgrading 0023 drops ``plan_outcome_events`` and its 2 policies (51 left);
- downgrading 0022 drops the grant ledger and ``has_workspace_creation_grant``
  and restores the UNGATED bootstrap (why the runbook forbids it on a live
  environment and the restore validator reports it);
- re-upgrading restores the gated bootstrap, the empty ledger and 53 policies.
"""

from types import SimpleNamespace

import psycopg
import pytest
from alembic import command
from alembic.config import Config

pytestmark = [pytest.mark.integration, pytest.mark.workspace_grants_enforced]

_BEFORE_PHASE2 = "0021_analytics_handoff"
_AFTER_0022 = "0022_workspace_creation_grants"


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
        }


def test_phase2_revisions_go_up_down_up_with_the_documented_down_state(
    pg_stack: SimpleNamespace,
) -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", pg_stack.owner_sa)

    head = _posture(pg_stack.owner_libpq)
    assert head["revision"] == "0023_plan_outcome_events"
    assert head["bootstrap_gated"] is True and head["bootstrap_overloads"] == 1
    assert head["helper"] == 1 and head["policies"] == 53

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
