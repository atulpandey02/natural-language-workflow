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

from nlw.api.deps import get_app_settings, get_session, get_tenant_context, rate_limit
from nlw.api.schemas import (
    RunCreateOut,
    WorkflowDetailOut,
    WorkflowOut,
    WorkflowVersionOut,
)
from nlw.core.config import Settings
from nlw.db.repositories import RunRepository, WorkflowRepository
from nlw.tenancy.context import TenantContext
from nlw.tenancy.session import set_current_tenant, set_current_user

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
        await set_current_user(session, ctx.user_id)
        await set_current_tenant(session, ctx.tenant_id)
        repo = WorkflowRepository(session)
        workflow = await repo.get(workflow_id, ctx.tenant_id)
        if workflow is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "workflow not found")
        if workflow.current_version_id is None:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "workflow has no materialized version to run"
            )
        run, created = await RunRepository(session).create_manual(
            tenant_id=ctx.tenant_id,
            workflow_id=workflow_id,
            workflow_version_id=workflow.current_version_id,
            idempotency_key=idempotency_key,
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
