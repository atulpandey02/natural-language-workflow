"""Run read endpoints (M10 support).

- ``GET /runs``               list the tenant's runs (paginated, filterable)
- ``GET /runs/{id}``          run detail
- ``GET /runs/{id}/steps``    step statuses + a BOUNDED output preview
- ``GET /runs/{id}/actions``  external-action audit (secret-free by construction)

All reads are tenant/RLS-scoped and hard-paginated. Step output is returned only
as a size-capped preview (never raw/unrestricted); connector secrets, secret_ref,
auth headers, and raw action request/response bodies are never exposed.
"""

import json
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.api.deps import get_session, get_tenant_context
from nlw.api.schemas import ExternalActionOut, RunOut, StepRunOut
from nlw.db.models import ExternalAction, StepRun, WorkflowRun, WorkflowVersion
from nlw.db.repositories import RunRepository
from nlw.domain.workflow import RunStatus, StepStatus, WorkflowPlan
from nlw.engine.summary import ActionView, RunSummary, StepView, summarize_run
from nlw.observability import metrics
from nlw.tenancy.context import TenantContext

router = APIRouter()

# Hard cap on the serialized step-output preview (bytes).
_OUTPUT_PREVIEW_CAP = 4000


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def _bounded_output(output: dict[str, Any] | None) -> tuple[dict[str, Any] | None, bool]:
    """Return (preview, truncated). Over-cap output collapses to a marker."""
    if output is None:
        return None, False
    if len(json.dumps(output, default=str)) > _OUTPUT_PREVIEW_CAP:
        return {"_truncated": True}, True
    return output, False


def _run_out(r: WorkflowRun) -> RunOut:
    return RunOut(
        id=r.id,
        workflow_id=r.workflow_id,
        workflow_version_id=r.workflow_version_id,
        status=r.status,
        trigger=r.trigger,
        schedule_id=r.schedule_id,
        scheduled_for=_iso(r.scheduled_for),
        error=r.error,
        started_at=_iso(r.started_at),
        finished_at=_iso(r.finished_at),
        created_at=r.created_at.isoformat(),
    )


def _step_out(s: StepRun) -> StepRunOut:
    preview, truncated = _bounded_output(s.output)
    return StepRunOut(
        step_id=s.step_id,
        tool=s.tool,
        status=s.status,
        attempt=s.attempt,
        error=s.error,
        started_at=_iso(s.started_at),
        finished_at=_iso(s.finished_at),
        output_preview=preview,
        output_truncated=truncated,
    )


def _action_out(a: ExternalAction) -> ExternalActionOut:
    return ExternalActionOut(
        step_id=a.step_id,
        tool=a.tool,
        destination_summary=a.destination_summary,
        status=a.status,
        attempts=a.attempts,
        error_class=a.error_class,
        http_status=a.http_status,
        last_attempt_at=_iso(a.last_attempt_at),
        next_attempt_at=_iso(a.next_attempt_at),
    )


@router.get("/runs", response_model=list[RunOut])
async def list_runs(
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
    workflow_id: uuid.UUID | None = Query(default=None),
    run_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> list[RunOut]:
    rows = await RunRepository(session).list_for_tenant(
        ctx.tenant_id, limit=limit, offset=offset, workflow_id=workflow_id, status=run_status
    )
    return [_run_out(r) for r in rows]


async def _load_run(run_id: uuid.UUID, ctx: TenantContext, session: AsyncSession) -> WorkflowRun:
    run = await RunRepository(session).get(run_id, ctx.tenant_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    return run


@router.get("/runs/{run_id}", response_model=RunOut)
async def get_run(
    run_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> RunOut:
    return _run_out(await _load_run(run_id, ctx, session))


@router.get("/runs/{run_id}/steps", response_model=list[StepRunOut])
async def get_run_steps(
    run_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> list[StepRunOut]:
    await _load_run(run_id, ctx, session)  # 404 if not the tenant's run
    steps = await RunRepository(session).steps(run_id, ctx.tenant_id)
    return [_step_out(s) for s in steps]


@router.get("/runs/{run_id}/actions", response_model=list[ExternalActionOut])
async def get_run_actions(
    run_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> list[ExternalActionOut]:
    await _load_run(run_id, ctx, session)
    actions = await RunRepository(session).actions(run_id, ctx.tenant_id)
    return [_action_out(a) for a in actions]


@router.get("/runs/{run_id}/summary", response_model=RunSummary)
async def get_run_summary(
    run_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> RunSummary:
    """Deterministic, grounded run summary (M12B-A, Part H).

    Reads only the immutable plan + persisted step/action state; makes no model
    call and mutates nothing. It never reports FAILED/SKIPPED/UNKNOWN as success.
    """
    run = await _load_run(run_id, ctx, session)
    version = await session.get(WorkflowVersion, run.workflow_version_id)
    if version is None:  # pragma: no cover - version is FK-pinned and immutable
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run version not found")
    plan = WorkflowPlan.model_validate(version.plan)
    repo = RunRepository(session)
    step_rows = await repo.steps(run_id, ctx.tenant_id)
    action_rows = await repo.actions(run_id, ctx.tenant_id)
    steps = [
        StepView(
            step_id=s.step_id,
            tool=s.tool,
            status=StepStatus(s.status),
            error=s.error,
            has_output=s.output is not None,
        )
        for s in step_rows
    ]
    actions = [ActionView(step_id=a.step_id, status=a.status) for a in action_rows]
    summary = summarize_run(
        run_status=RunStatus(run.status), plan=plan, steps=steps, actions=actions
    )
    metrics.record_run_summary(summary.outcome.value)
    return summary
