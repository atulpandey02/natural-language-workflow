"""Workflow read endpoints + manual run trigger (M10 support).

- ``GET  /workflows``               list the tenant's workflows (paginated)
- ``GET  /workflows/{id}``          workflow + its current pinned version plan
- ``GET  /workflow-versions/{id}``  a specific immutable version plan
- ``POST /workflows/{id}/runs``     idempotent manual "Run now"

All reads are tenant/RLS-scoped and hard-paginated. The plan is workflow
definition content only (never secrets). Manual run creation is idempotent
(Idempotency-Key) and commit-before-enqueue: if the enqueue fails after commit,
the durable PENDING run is left for M8 reconciliation to re-drive.
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.api.capability import build_tenant_view
from nlw.api.deps import (
    get_app_settings,
    get_ctx_signer,
    get_session,
    get_tenant_context,
    rate_limit,
)
from nlw.api.schemas import (
    RunCreateOut,
    WorkflowDetailOut,
    WorkflowOut,
    WorkflowProvenanceOut,
    WorkflowVersionOut,
)
from nlw.core.config import Settings
from nlw.db.repositories import PlanProposalRepository, RunRepository, WorkflowRepository
from nlw.domain.workflow import WorkflowPlan
from nlw.feasibility.limits import DEFAULT_LIMITS
from nlw.feasibility.revalidation import revalidate_plan
from nlw.observability import metrics
from nlw.planner.provenance import ProvenanceIntegrityError, verify_request_provenance
from nlw.tenancy.context import TenantContext
from nlw.tenancy.session import set_request_context
from nlw.tenancy.signing import Purpose

router = APIRouter()
log = structlog.get_logger(__name__)

_IDEMPOTENCY_KEY_MAX = 200
# Reserved prefix for scheduler-internal namespaces. A client Idempotency-Key must
# not use it, so a manual key can never be confused with (or shadow) scheduler
# state. Scheduled runs no longer store any client key (see scheduler/due.py); this
# is defence-in-depth keeping the two namespaces unambiguous (P1D).
_RESERVED_IDEMPOTENCY_PREFIX = "sched:"


def _enqueue_advance(run_id: uuid.UUID) -> None:
    """Enqueue the first advancement. Imported lazily; patch seam for tests."""
    from nlw.worker.actors import advance_run

    advance_run.send(str(run_id))


def _version_out(version: object) -> WorkflowVersionOut:
    v = version
    return WorkflowVersionOut(
        id=v.id,  # type: ignore[attr-defined]
        workflow_id=v.workflow_id,  # type: ignore[attr-defined]
        version=v.version,  # type: ignore[attr-defined]
        plan=v.plan,  # type: ignore[attr-defined]
    )


@router.get("/workflows", response_model=list[WorkflowOut])
async def list_workflows(
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> list[WorkflowOut]:
    rows = await WorkflowRepository(session).list_for_tenant(
        ctx.tenant_id, limit=limit, offset=offset
    )
    return [
        WorkflowOut(
            id=w.id,
            name=w.name,
            current_version_id=w.current_version_id,
            created_at=w.created_at.isoformat(),
        )
        for w in rows
    ]


@router.get("/workflows/{workflow_id}", response_model=WorkflowDetailOut)
async def get_workflow(
    workflow_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> WorkflowDetailOut:
    repo = WorkflowRepository(session)
    workflow = await repo.get(workflow_id, ctx.tenant_id)
    if workflow is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workflow not found")
    current = None
    if workflow.current_version_id is not None:
        version = await repo.get_version(workflow.current_version_id, ctx.tenant_id)
        current = _version_out(version) if version is not None else None
    return WorkflowDetailOut(
        id=workflow.id,
        name=workflow.name,
        current_version_id=workflow.current_version_id,
        created_at=workflow.created_at.isoformat(),
        current_version=current,
    )


@router.get("/workflow-versions/{version_id}", response_model=WorkflowVersionOut)
async def get_workflow_version(
    version_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> WorkflowVersionOut:
    version = await WorkflowRepository(session).get_version(version_id, ctx.tenant_id)
    if version is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workflow version not found")
    return _version_out(version)


@router.get("/workflow-versions/{version_id}/provenance", response_model=WorkflowProvenanceOut)
async def get_workflow_provenance(
    version_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> WorkflowProvenanceOut:
    """The original NL request + planner identity + feasibility decision that
    produced this version (M12B-A). Read-only, tenant-scoped, authorized-member
    only. Not a list endpoint; never logs the request text."""
    version = await WorkflowRepository(session).get_version(version_id, ctx.tenant_id)
    if version is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workflow version not found")
    proposal = await PlanProposalRepository(session).get_by_version(version_id, ctx.tenant_id)
    if proposal is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no provenance for this version")
    # Verify the stored digest against the stored request before serving it, so a
    # tampered request is detected rather than returned (fail closed). The error
    # carries only the proposal id, never the request text.
    try:
        verify_request_provenance(
            proposal.request_text, proposal.request_sha256, proposal_id=proposal.id
        )
    except ProvenanceIntegrityError as exc:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "request provenance integrity check failed"
        ) from exc
    return WorkflowProvenanceOut(
        workflow_version_id=version_id,
        request_text=proposal.request_text,
        request_sha256=proposal.request_sha256,
        provider=proposal.provider,
        model=proposal.model,
        planner_contract_version=proposal.planner_contract_version,
        status=proposal.status,
        created_at=proposal.created_at.isoformat(),
    )


@router.post(
    "/workflows/{workflow_id}/runs",
    response_model=RunCreateOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("runs", "write"))],
)
async def create_run(
    workflow_id: uuid.UUID,
    request: Request,
    ctx: TenantContext = Depends(get_tenant_context),
    settings: Settings = Depends(get_app_settings),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> RunCreateOut:
    """Idempotent manual run of the workflow's CURRENT pinned version.

    A repeat with the same Idempotency-Key returns the same durable run (so
    retries/double-clicks never create duplicates).
    """
    if not idempotency_key or len(idempotency_key) > _IDEMPOTENCY_KEY_MAX:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Idempotency-Key header is required (<= 200 chars)",
        )
    if idempotency_key.startswith(_RESERVED_IDEMPOTENCY_PREFIX):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Idempotency-Key must not use the reserved 'sched:' prefix",
        )

    # Dedicated session with explicit commit so the run is durable BEFORE we
    # enqueue; an enqueue failure then surfaces as 503 while the PENDING run
    # remains recoverable by M8 reconciliation.
    sessionmaker = request.app.state.sessionmaker
    async with sessionmaker() as session, session.begin():
        await set_request_context(session, get_ctx_signer(request, Purpose.API_REQUEST), ctx)
        repo = WorkflowRepository(session)
        workflow = await repo.get(workflow_id, ctx.tenant_id)
        if workflow is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "workflow not found")
        if workflow.current_version_id is None:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "workflow has no materialized version to run"
            )
        # STALE_PLAN gate (M12B-A): re-validate the pinned plan against CURRENT
        # authoritative state BEFORE creating a run, so execution fails closed
        # before any tool is invoked when a referenced connector/tool changed.
        version = await repo.get_version(workflow.current_version_id, ctx.tenant_id)
        if version is not None:
            # Registry compatibility for an ALREADY-materialized version: demo tools
            # stay executable here even when hidden from new planning.
            view, all_tool_names = await build_tenant_view(
                session, ctx.tenant_id, settings, purpose="execution_compat"
            )
            reval = revalidate_plan(
                WorkflowPlan.model_validate(version.plan), view, DEFAULT_LIMITS, all_tool_names
            )
            if not reval.fresh:
                metrics.record_stale_plan(reval.outcome.value, reval.reason_code)
                log.info(
                    "run.blocked_stale",
                    tenant_id=str(ctx.tenant_id),
                    workflow_id=str(workflow_id),
                    outcome=reval.outcome.value,
                    reason_code=reval.reason_code,
                )
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    detail={"code": reval.outcome.value, "message": reval.message},
                )
        run, created = await RunRepository(session).create_manual(
            tenant_id=ctx.tenant_id,
            workflow_id=workflow_id,
            workflow_version_id=workflow.current_version_id,
            idempotency_key=idempotency_key,
            initiated_by_user_id=ctx.user_id,
        )
        run_id = run.id
        run_status = run.status

    # AFTER commit: enqueue the first advancement. Re-enqueue even on an
    # idempotent hit so a previously-lost enqueue can be re-driven.
    try:
        _enqueue_advance(run_id)
    except Exception as exc:  # infrastructure — run is durable + recoverable
        log.error("run.enqueue_failed", run_id=str(run_id), error_class=type(exc).__name__)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "run created but could not be scheduled; it will be recovered automatically",
        ) from exc

    log.info(
        "run.manual_created",
        run_id=str(run_id),
        tenant_id=str(ctx.tenant_id),
        workflow_id=str(workflow_id),
        idempotent_hit=not created,
    )
    return RunCreateOut(run_id=run_id, status=run_status, idempotent_hit=not created)
