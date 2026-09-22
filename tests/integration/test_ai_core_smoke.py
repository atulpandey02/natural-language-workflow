"""AI-core end-to-end smoke on real Postgres (M12B-A, Part K).

Exercises the durable back half of the pipeline on real persisted state and the
deterministic grounded result on top of it:

    persisted workflow version  ->  queued/durable execution  ->  checkpointed
    step_runs  ->  grounded run summary

plus the failure/resume smoke: a failed step ends the run, a re-advance repeats
no completed work, and the grounded summary reports FAILED/SKIPPED (never
success). The plan->feasibility->materialize front half is covered by
test_plans_api.py; here we start from a materialized version, as the worker does.
"""

import uuid
from types import SimpleNamespace

import psycopg
import pytest

from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.domain.workflow import RunStatus, StepStatus, WorkflowPlan
from nlw.engine.execution import execute_advancement
from nlw.engine.runs import create_run, create_workflow_with_version
from nlw.engine.summary import ActionView, RunOutcome, StepOutcome, StepView, summarize_run
from nlw.tenancy.keys import process_signer
from nlw.tenancy.session import apply_signed_context_sync
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration


@pytest.fixture
def sms(pg_stack: SimpleNamespace) -> object:
    app_engine = create_sync_engine(pg_stack.settings)
    worker_engine = create_sync_engine(pg_stack.worker_settings)
    try:
        yield SimpleNamespace(
            app=create_sync_sessionmaker(app_engine),
            worker=create_sync_sessionmaker(worker_engine),
        )
    finally:
        app_engine.dispose()
        worker_engine.dispose()


def _plan(steps: list[dict[str, object]]) -> WorkflowPlan:
    return WorkflowPlan.model_validate({"steps": steps})


def _seed(
    app_sm: object, user_id: uuid.UUID, tenant_id: uuid.UUID, plan: WorkflowPlan
) -> uuid.UUID:
    with app_sm() as s, s.begin():  # type: ignore[operator]
        apply_signed_context_sync(
            s, process_signer(Purpose.API_REQUEST).sign(user_id=user_id, tenant_id=tenant_id)
        )
        wf, ver = create_workflow_with_version(s, tenant_id, "wf", plan)
        run = create_run(s, tenant_id, wf.id, ver.id)
        return run.id


def _drive(sms: SimpleNamespace, run_id: uuid.UUID, limit: int = 8) -> list[str]:
    results = []
    for _ in range(limit):
        outcome = execute_advancement(sms.worker, run_id)
        results.append(outcome.result)
        if outcome.result in ("completed", "failed", "noop"):
            break
    return results


def _summary(owner_libpq: str, run_id: uuid.UUID, plan: WorkflowPlan) -> object:
    with psycopg.connect(owner_libpq) as c:
        run_status = c.execute(
            "SELECT status FROM workflow_runs WHERE id=%s", (run_id,)
        ).fetchone()[0]
        step_rows = c.execute(
            "SELECT step_id, tool, status, error, output FROM step_runs WHERE run_id=%s", (run_id,)
        ).fetchall()
        action_rows = c.execute(
            "SELECT step_id, status FROM external_actions WHERE run_id=%s", (run_id,)
        ).fetchall()
    steps = [
        StepView(
            step_id=r[0],
            tool=r[1],
            status=StepStatus(r[2]),
            error=r[3],
            has_output=r[4] is not None,
        )
        for r in step_rows
    ]
    actions = [ActionView(step_id=r[0], status=r[1]) for r in action_rows]
    return summarize_run(run_status=RunStatus(run_status), plan=plan, steps=steps, actions=actions)


def test_smoke_request_to_grounded_result(pg_stack: SimpleNamespace, sms: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    plan = _plan(
        [
            {"id": "a", "tool": "fake.echo", "args": {"note": "one"}},
            {"id": "b", "tool": "fake.echo", "args": {"note": "two"}, "depends_on": ["a"]},
            {"id": "c", "tool": "fake.echo", "args": {"note": "three"}, "depends_on": ["b"]},
        ]
    )
    run_id = _seed(sms.app, m.user_id, m.tenant_id, plan)
    assert _drive(sms, run_id)[-1] == "completed"

    summary = _summary(pg_stack.owner_libpq, run_id, plan)
    assert summary.outcome == RunOutcome.COMPLETED
    assert summary.succeeded == 3 and summary.failed == 0 and summary.unknown == 0
    assert all(s.outcome == StepOutcome.SUCCESS for s in summary.steps)
    assert "completed successfully" in summary.headline


def test_smoke_failure_resume_grounded_no_repeat(
    pg_stack: SimpleNamespace, sms: SimpleNamespace
) -> None:
    m = pg_stack.seed_member()
    plan = _plan(
        [
            {"id": "a", "tool": "fake.echo", "args": {"note": "ok"}},
            {"id": "b", "tool": "fake.fail", "depends_on": ["a"]},
            {"id": "c", "tool": "fake.echo", "args": {"note": "never"}, "depends_on": ["b"]},
        ]
    )
    run_id = _seed(sms.app, m.user_id, m.tenant_id, plan)
    # a advances, b fails the run.
    first = _drive(sms, run_id)
    assert first[-1] == "failed"
    # A re-advance repeats no completed work (idempotent recovery).
    assert execute_advancement(sms.worker, run_id).result == "noop"

    with psycopg.connect(pg_stack.owner_libpq) as c:
        a_attempt = c.execute(
            "SELECT attempt FROM step_runs WHERE run_id=%s AND step_id='a'", (run_id,)
        ).fetchone()[0]
    assert a_attempt == 1  # completed step not re-run

    summary = _summary(pg_stack.owner_libpq, run_id, plan)
    assert summary.outcome == RunOutcome.FAILED
    outcomes = {s.step_id: s.outcome for s in summary.steps}
    assert outcomes["a"] == StepOutcome.SUCCESS
    assert outcomes["b"] == StepOutcome.FAILED
    assert outcomes["c"] == StepOutcome.SKIPPED  # never ran; not reported as success
    assert summary.succeeded == 1 and summary.failed == 1 and summary.skipped == 1
    assert "success" not in summary.headline.lower()
