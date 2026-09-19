"""Approval endpoints (M7).

- ``GET  /approvals``               list the tenant's pending approvals, each with
                                    a bounded, secret-free action preview.
- ``POST /approvals/{id}/approve``  admin/owner only; CAS + resume the run.
- ``POST /approvals/{id}/reject``   admin/owner only; CAS + fail the run.

Decisions are compare-and-set and recovery-safe: repeating the same decision is
idempotent and re-enqueues the run, so a lost enqueue can be re-driven. The API
mutates ONLY the approvals row (RLS also requires admin/owner and
``decided_by = app.user_id``); the worker remains the sole run/step writer.
"""

import json
import uuid
from typing import Any, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.api.deps import get_session, get_tenant_context, rate_limit, require_role
from nlw.api.schemas import ApprovalDecisionOut, ApprovalOut
from nlw.db.models import Approval, WorkflowVersion
from nlw.db.repositories import ApprovalRepository
from nlw.domain.workflow import WorkflowPlan
from nlw.tenancy.context import Role, TenantContext
from nlw.tenancy.session import set_current_tenant, set_current_user

router = APIRouter()
log = structlog.get_logger(__name__)

_PREVIEW_MAX_CHARS = 4000
# Admin/owner is required to decide an approval (also enforced by RLS).
_require_admin = require_role(Role.ADMIN)


async def _preview_for(session: AsyncSession, approval: Approval) -> dict[str, Any]:
    """Derive a bounded, secret-free preview from the immutable workflow version.

    Uses the run's version plan step args (workflow/user content). Never contains
    connector secrets/secret_ref/tokens (those live only on the connector side).
    """
    from nlw.db.models import WorkflowRun

    run = await session.get(WorkflowRun, approval.run_id)
    if run is None:
        return {}
    version = await session.get(WorkflowVersion, run.workflow_version_id)
    if version is None:
        return {}
    try:
        plan = WorkflowPlan.model_validate(version.plan)
        step = plan.step(approval.step_id)
    except (ValueError, KeyError):
        return {}
    args = step.args
    if len(json.dumps(args, default=str)) > _PREVIEW_MAX_CHARS:
        return {"tool": step.tool, "args": {"_truncated": True}}
    return {"tool": step.tool, "args": args}


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


@router.get("/approvals", response_model=list[ApprovalOut])
async def list_approvals(
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> list[ApprovalOut]:
    approvals = await ApprovalRepository(session).list_for_tenant(ctx.tenant_id, pending_only=True)
    out: list[ApprovalOut] = []
    for a in approvals:
        out.append(
            ApprovalOut(
                id=a.id,
                run_id=a.run_id,
                step_id=a.step_id,
                tool=a.tool,
                connector_name=a.connector_name,
                status=a.status,
                requested_at=_iso(a.requested_at),
                decided_at=_iso(a.decided_at),
                preview=await _preview_for(session, a),
            )
        )
    return out


def _enqueue_advance(request: Request, run_id: uuid.UUID) -> None:
    """Enqueue a resume. Import lazily so the API only wires the broker when used."""
    from nlw.worker.actors import advance_run

    advance_run.send(str(run_id))


async def _decide(
    request: Request,
    approval_id: uuid.UUID,
    ctx: TenantContext,
    target: Literal["approved", "rejected"],
) -> ApprovalDecisionOut:
    # Dedicated session with explicit commit so the decision is durable BEFORE we
    # enqueue; an enqueue failure then surfaces as 503 (resume not claimed).
    sessionmaker = request.app.state.sessionmaker
    async with sessionmaker() as session, session.begin():
        await set_current_user(session, ctx.user_id)
        await set_current_tenant(session, ctx.tenant_id)
        outcome, run_id = await ApprovalRepository(session).decide(
            approval_id, ctx.tenant_id, ctx.user_id, target
        )
    if outcome == "not_found":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found")
    if outcome == "conflict":
        raise HTTPException(status.HTTP_409_CONFLICT, "approval already decided")

    assert run_id is not None
    try:
        _enqueue_advance(request, run_id)
    except Exception as exc:  # infrastructure — do NOT claim the resume succeeded
        log.error(
            "approval.enqueue_failed", approval_id=str(approval_id), error_class=type(exc).__name__
        )
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "decision saved but resume could not be scheduled"
        ) from exc

    log.info(
        "approval.decided",
        approval_id=str(approval_id),
        tenant_id=str(ctx.tenant_id),
        status=target,
        outcome=outcome,
    )
    return ApprovalDecisionOut(id=approval_id, status=target, resumed=True)


@router.post(
    "/approvals/{approval_id}/approve",
    response_model=ApprovalDecisionOut,
    dependencies=[Depends(rate_limit("approvals", "write"))],
)
async def approve(
    approval_id: uuid.UUID,
    request: Request,
    ctx: TenantContext = Depends(_require_admin),
) -> ApprovalDecisionOut:
    return await _decide(request, approval_id, ctx, "approved")


@router.post(
    "/approvals/{approval_id}/reject",
    response_model=ApprovalDecisionOut,
    dependencies=[Depends(rate_limit("approvals", "write"))],
)
async def reject(
    approval_id: uuid.UUID,
    request: Request,
    ctx: TenantContext = Depends(_require_admin),
) -> ApprovalDecisionOut:
    return await _decide(request, approval_id, ctx, "rejected")
