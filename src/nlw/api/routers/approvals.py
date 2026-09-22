"""Approval endpoints (M7).

- ``GET  /approvals``               list the tenant's pending approvals, each with
                                    a bounded, secret-free action preview.
- ``POST /approvals/{id}/approve``  admin/owner only; CAS + resume the run.
- ``POST /approvals/{id}/reject``   admin/owner only; CAS + fail the run.

Decisions are compare-and-set and recovery-safe: repeating the same decision is
idempotent and re-enqueues the run, so a lost enqueue can be re-driven. The API
mutates ONLY the approvals row (RLS also requires admin/owner and
``decided_by = public.ctx_user_id()`` from the signed request context); the
worker remains the sole run/step writer.
"""

import json
import uuid
from typing import Any, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.api.deps import get_ctx_signer, get_session, get_tenant_context, rate_limit, require_role
from nlw.api.schemas import ApprovalDecisionOut, ApprovalOut
from nlw.db.models import Approval, WorkflowVersion
from nlw.db.repositories import ApprovalRepository, AuditRepository
from nlw.domain.workflow import WorkflowPlan
from nlw.tenancy.context import Role, TenantContext, role_at_least
from nlw.tenancy.session import set_request_context
from nlw.tenancy.signing import Purpose
from nlw.tools.action_schemas import MAX_REVIEWABLE_ACTION_PAYLOAD_BYTES

router = APIRouter()
log = structlog.get_logger(__name__)

# Admin/owner is required to decide an approval (also enforced by RLS).
_require_admin = require_role(Role.ADMIN)


async def _effective_destination(
    session: AsyncSession, approval: Approval, step: Any
) -> str | None:
    """The non-secret effective destination from the APPROVED connector (by id):
    webhook host (no path/query/credentials) or Slack channel."""
    from nlw.connectors.http_guard import SsrfError, validate_url
    from nlw.db.models import Connector

    connector = await session.get(Connector, approval.connector_id)
    if connector is None:
        return None
    config = connector.config if isinstance(connector.config, dict) else {}
    if approval.tool == "webhook.send":
        try:
            host, _port = validate_url(str(config.get("url", "")))
        except (SsrfError, Exception):
            return None
        return host
    if approval.tool == "slack.send_message":
        args = step.args if isinstance(step.args, dict) else {}
        ch = args.get("channel") or config.get("default_channel")
        return str(ch) if ch else None
    return None


async def _preview_for(
    session: AsyncSession, approval: Approval
) -> tuple[dict[str, Any], str | None, bool]:
    """Derive a bounded, secret-free preview from the immutable workflow version.

    Returns ``(preview, destination, payload_review_blocked)``. The preview uses
    the run's version plan step args (workflow/user content) and NEVER contains
    connector secrets/secret_ref/tokens. The effective destination comes from the
    APPROVED connector. A payload exceeding the safe review size is NOT shown and
    marks ``payload_review_blocked`` (the action must not be approved unseen).
    """
    from nlw.db.models import WorkflowRun

    run = await session.get(WorkflowRun, approval.run_id)
    if run is None:
        return ({"tool": approval.tool, "args": None}, None, True)
    version = await session.get(WorkflowVersion, run.workflow_version_id)
    if version is None:
        return ({"tool": approval.tool, "args": None}, None, True)
    try:
        plan = WorkflowPlan.model_validate(version.plan)
        step = plan.step(approval.step_id)
    except (ValueError, KeyError):
        return ({"tool": approval.tool, "args": None}, None, True)
    destination = await _effective_destination(session, approval, step)
    args = step.args
    blocked = (
        len(json.dumps(args, default=str).encode("utf-8")) > MAX_REVIEWABLE_ACTION_PAYLOAD_BYTES
    )
    preview = {"tool": step.tool, "args": None if blocked else args}
    return (preview, destination, blocked)


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


@router.get("/approvals", response_model=list[ApprovalOut])
async def list_approvals(
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> list[ApprovalOut]:
    approvals = await ApprovalRepository(session).list_for_tenant(ctx.tenant_id, pending_only=True)
    # The viewer may decide only when eligible (admin/owner) AND not the requester.
    is_admin = role_at_least(ctx.role, Role.ADMIN)
    out: list[ApprovalOut] = []
    for a in approvals:
        preview, destination, blocked = await _preview_for(session, a)
        can_decide = (
            is_admin
            and a.status == "pending"
            and a.requested_by_user_id is not None
            and a.requested_by_user_id != ctx.user_id
        )
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
                requested_by_user_id=a.requested_by_user_id,
                viewer_can_decide=can_decide,
                destination=destination,
                payload_review_blocked=blocked,
                preview=preview,
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
        await set_request_context(session, get_ctx_signer(request, Purpose.API_REQUEST), ctx)
        outcome, run_id = await ApprovalRepository(session).decide(
            approval_id, ctx.tenant_id, ctx.user_id, target
        )
        # Append-only audit, in the SAME transaction as the decision and ONLY on a
        # genuine terminal transition (idempotent re-drives add no event).
        if outcome == "transitioned":
            await AuditRepository(session).emit(
                tenant_id=ctx.tenant_id,
                event_type=f"approval.{target}",
                actor_user_id=ctx.user_id,
                subject_id=approval_id,
            )
    if outcome == "not_found":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found")
    if outcome == "self_approval":
        # Separation of duties: the requester of an action cannot decide it.
        log.info("approval.self_approval_denied", approval_id=str(approval_id))
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "you cannot decide an approval you requested"
        )
    if outcome == "requester_unknown":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "approval has no recorded requester and cannot be decided; re-request the action",
        )
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
    session: AsyncSession = Depends(get_session),
) -> ApprovalDecisionOut:
    # An action whose payload is too large to review safely must NOT be approved
    # unseen (P1C). It can only be rejected. This is defence-in-depth on top of
    # the materialization-time payload bound.
    approval = await ApprovalRepository(session).get(approval_id, ctx.tenant_id)
    if approval is not None and approval.status == "pending":
        _preview, _dest, blocked = await _preview_for(session, approval)
        if blocked:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "action payload exceeds the safe review size and cannot be approved unseen",
            )
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
