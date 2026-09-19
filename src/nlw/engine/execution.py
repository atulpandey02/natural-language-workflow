"""Durable single-step advancement.

One ``advance_run`` = one transaction: resolve tenant (via the worker-only
SECURITY DEFINER resolver), set the tenant GUC, lock the run ``FOR UPDATE``,
execute exactly one step, checkpoint, COMMIT. Enqueueing the next advancement is
a separate, injectable step done AFTER commit (``process_advance``) so a crash
between commit and enqueue is recovered by redelivery of the still-unacked
message. Postgres is authoritative; the message carries only ``run_id``.
"""

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from nlw.db.models import StepRun, WorkflowRun, WorkflowVersion
from nlw.domain.workflow import (
    RunStatus,
    StepStatus,
    WorkflowPlan,
    all_succeeded,
    any_failed,
    select_next_step,
)
from nlw.tenancy.session import set_current_tenant_sync
from nlw.tools.fake import ToolExecutionError, UnknownToolError, run_tool

Result = Literal["advanced", "completed", "failed", "noop"]


@dataclass(frozen=True)
class AdvanceOutcome:
    result: Result
    enqueue_next: bool
    step_id: str | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def _resolve_tenant(session: Session, run_id: uuid.UUID) -> uuid.UUID | None:
    """Worker-only bootstrap: run_id -> tenant_id via the SECURITY DEFINER
    resolver. Returns no business data; NULL means the run does not exist."""
    result = session.execute(
        text("SELECT resolve_run_tenant(:rid)"), {"rid": str(run_id)}
    ).scalar_one_or_none()
    return result


def execute_advancement(
    session_factory: sessionmaker[Session], run_id: uuid.UUID
) -> AdvanceOutcome:
    """Advance a run by exactly one step inside a single locked transaction."""
    with session_factory() as session, session.begin():
        tenant_id = _resolve_tenant(session, run_id)
        if tenant_id is None:
            return AdvanceOutcome("noop", enqueue_next=False)
        set_current_tenant_sync(session, tenant_id)

        run = session.execute(
            select(WorkflowRun).where(WorkflowRun.id == run_id).with_for_update()
        ).scalar_one_or_none()
        if run is None:
            return AdvanceOutcome("noop", enqueue_next=False)
        if run.status in (RunStatus.COMPLETED, RunStatus.FAILED):
            return AdvanceOutcome("noop", enqueue_next=False)

        version = session.get(WorkflowVersion, run.workflow_version_id)
        if version is None:
            return AdvanceOutcome("noop", enqueue_next=False)
        plan = WorkflowPlan.model_validate(version.plan)

        step_rows = list(
            session.execute(select(StepRun).where(StepRun.run_id == run_id)).scalars().all()
        )
        states: dict[str, StepStatus] = {s.step_id: StepStatus(s.status) for s in step_rows}

        if run.status == RunStatus.PENDING:
            run.status = RunStatus.RUNNING
            run.started_at = _now()

        if any_failed(states):
            run.status = RunStatus.FAILED
            run.finished_at = _now()
            return AdvanceOutcome("failed", enqueue_next=False)

        nxt = select_next_step(plan, states)
        if nxt is None:
            if all_succeeded(plan, states):
                run.status = RunStatus.COMPLETED
                run.finished_at = _now()
                return AdvanceOutcome("completed", enqueue_next=False)
            # Nothing runnable, nothing failed, not all done: invalid/stuck plan
            # (feasibility validation in M6 prevents this). Do not loop forever.
            return AdvanceOutcome("noop", enqueue_next=False)

        step = next((s for s in step_rows if s.step_id == nxt.id), None)
        if step is None:
            step = StepRun(
                tenant_id=tenant_id,
                run_id=run_id,
                step_id=nxt.id,
                tool=nxt.tool,
                status=StepStatus.RUNNING,
                attempt=1,
                input=nxt.args,
                started_at=_now(),
            )
            session.add(step)
        else:
            step.status = StepStatus.RUNNING
            step.attempt = step.attempt + 1
            step.started_at = _now()

        try:
            output = run_tool(nxt.tool, nxt.args)
        except (ToolExecutionError, UnknownToolError) as exc:
            step.status = StepStatus.FAILED
            step.error = str(exc)
            step.finished_at = _now()
            run.status = RunStatus.FAILED
            run.finished_at = _now()
            return AdvanceOutcome("failed", enqueue_next=False, step_id=nxt.id)

        step.status = StepStatus.SUCCESS
        step.output = output
        step.finished_at = _now()
        return AdvanceOutcome("advanced", enqueue_next=True, step_id=nxt.id)


def process_advance(
    session_factory: sessionmaker[Session],
    run_id: uuid.UUID,
    enqueue: Callable[[uuid.UUID], None],
) -> AdvanceOutcome:
    """Run one advancement, then (only after commit) enqueue the next one.

    ``enqueue`` is injectable for testing. Any enqueue error PROPAGATES: the
    invocation must fail (so the message is retried) rather than appear handled.
    The step is already durably committed, so the retry skips it and continues.
    """
    outcome = execute_advancement(session_factory, run_id)
    if outcome.enqueue_next:
        enqueue(run_id)
    return outcome
