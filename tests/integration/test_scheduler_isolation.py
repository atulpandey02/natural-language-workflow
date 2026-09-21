"""Scheduler role secret-isolation (M8, req 11).

nlw_scheduler is LOGIN NOSUPERUSER NOBYPASSRLS with least-privilege grants. It
must be able to read schedules/workflow_runs but must NOT be able to read
connectors (secret_ref/config), step_runs I/O, plan_proposals, or memberships —
so it can never see secrets or business payloads.
"""

from types import SimpleNamespace

import psycopg
import pytest

pytestmark = pytest.mark.integration


def _denied(scheduler_libpq: str, sql: str) -> bool:
    try:
        with psycopg.connect(scheduler_libpq) as c:
            c.execute(sql).fetchall()
        return False
    except psycopg.errors.InsufficientPrivilege:
        return True


def test_scheduler_role_is_not_superuser_or_bypassrls(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.scheduler_libpq) as c:
        row = c.execute(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname='nlw_scheduler'"
        ).fetchone()
    assert row == (False, False)


def test_scheduler_cannot_read_connectors_or_secrets(pg_stack: SimpleNamespace) -> None:
    # No grant on connectors at all -> cannot see secret_ref/config.
    assert _denied(pg_stack.scheduler_libpq, "SELECT secret_ref FROM connectors")
    assert _denied(pg_stack.scheduler_libpq, "SELECT * FROM connectors")


def test_scheduler_cannot_read_step_io_or_proposals(pg_stack: SimpleNamespace) -> None:
    # P1D grants the reconciler a COLUMN-RESTRICTED SELECT on step_runs
    # (id, tenant_id, run_id, step_id, status) to bind approvals to the blocked
    # step — but step I/O (input/output/error) stays UNREADABLE.
    assert _denied(pg_stack.scheduler_libpq, "SELECT input, output FROM step_runs")
    assert _denied(pg_stack.scheduler_libpq, "SELECT error FROM step_runs")
    assert _denied(pg_stack.scheduler_libpq, "SELECT * FROM step_runs")
    assert _denied(pg_stack.scheduler_libpq, "SELECT prompt_len FROM plan_proposals")
    assert _denied(pg_stack.scheduler_libpq, "SELECT * FROM memberships")


def test_scheduler_can_read_its_own_tables(pg_stack: SimpleNamespace) -> None:
    # These are the only tables it needs; reads must succeed (no exception).
    with psycopg.connect(pg_stack.scheduler_libpq) as c:
        c.execute("SELECT id FROM schedules").fetchall()
        c.execute("SELECT id FROM workflow_runs").fetchall()
        c.execute("SELECT id FROM external_actions").fetchall()
        c.execute("SELECT id FROM approvals").fetchall()
        # Only the non-I/O columns needed for approval-to-step binding (P1D).
        c.execute("SELECT run_id, step_id, status FROM step_runs").fetchall()
