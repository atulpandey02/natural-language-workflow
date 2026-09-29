"""Identity and workspace endpoints.

- ``GET  /me``                current user (auth required)
- ``GET  /workspaces``        workspaces the caller belongs to
- ``POST /workspaces``        found a workspace + owner membership (requires an
                              operator-issued workspace-creation grant)
- ``GET  /workspaces/current`` resolve the tenant context for X-Workspace-Id
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.api import db_errors
from nlw.api.deps import (
    get_app_settings,
    get_current_user,
    get_session,
    get_tenant_context,
    rate_limit_user,
)
from nlw.api.schemas import TenantContextOut, UserOut, WorkspaceCreate, WorkspaceOut
from nlw.core.config import Settings
from nlw.db.models import User
from nlw.db.repositories import WorkspaceRepository
from nlw.tenancy.context import Role, TenantContext

log = structlog.get_logger(__name__)

router = APIRouter()

WORKSPACE_CREATION_NOT_GRANTED = "WORKSPACE_CREATION_NOT_GRANTED"
WORKSPACE_CREATION_CLOSED = "WORKSPACE_CREATION_CLOSED"


def _not_granted() -> HTTPException:
    return HTTPException(
        status.HTTP_403_FORBIDDEN,
        {
            "code": WORKSPACE_CREATION_NOT_GRANTED,
            "message": "creating a workspace requires an invitation from your administrator",
        },
    )


def _slugify(name: str) -> str:
    base = "".join(c if c.isalnum() else "-" for c in name.lower()).strip("-") or "workspace"
    return f"{base}-{uuid.uuid4().hex[:8]}"


@router.get("/me", response_model=UserOut)
async def read_me(user: User = Depends(get_current_user)) -> User:
    return user


@router.get("/workspaces", response_model=list[WorkspaceOut])
async def list_workspaces(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[WorkspaceOut]:
    rows = await WorkspaceRepository(session).list_for_user(user.id)
    return [WorkspaceOut(id=ws.id, name=ws.name, slug=ws.slug, role=role) for ws, role in rows]


@router.post(
    "/workspaces",
    response_model=WorkspaceOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_user("workspaces_create"))],
)
async def create_workspace(
    body: WorkspaceCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_app_settings),
) -> WorkspaceOut:
    # Founding a tenant is operator-granted (Phase 2 B01). The DATABASE is the
    # authority: the SECURITY DEFINER bootstrap consumes one grant for the
    # caller's email and raises 42501 without one. The pre-check below only lets
    # the API answer with a clear 403 before attempting it; a grant that
    # disappears between the two is still refused by the function.
    if settings.workspace_creation_mode == "closed":
        log.info("workspace.create_refused", reason="closed")
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            {
                "code": WORKSPACE_CREATION_CLOSED,
                "message": "creating workspaces is disabled on this deployment",
            },
        )
    slug = _slugify(body.name)
    try:
        granted = (await session.execute(text("SELECT has_workspace_creation_grant()"))).scalar()
        if granted is not True:
            log.info("workspace.create_refused", reason="no_grant")
            raise _not_granted()
        # The bootstrap creates a NEW workspace plus exactly the creator's owner
        # membership, atomically. nlw_app has no direct workspaces/memberships
        # write privilege, so it cannot add itself to an existing workspace.
        result = await session.execute(
            text("SELECT create_workspace_for_current_user(:name, :slug)"),
            {"name": body.name, "slug": slug},
        )
        workspace_id: uuid.UUID = result.scalar_one()
    except SQLAlchemyError as exc:
        # The request transaction is rolled back by ``get_session``: a refused
        # bootstrap consumes nothing and creates nothing.
        if db_errors.sqlstate(exc) == db_errors.SQLSTATE_INSUFFICIENT_PRIVILEGE:
            log.info("workspace.create_refused", reason="no_grant_in_db")
            raise _not_granted() from exc
        if db_errors.is_unavailable(exc):
            raise db_errors.unavailable(exc, "workspace.create") from exc
        db_errors.log_unexpected(exc, "workspace.create")
        raise
    log.info("workspace.created", workspace_id=str(workspace_id), user_id=str(user.id))
    return WorkspaceOut(id=workspace_id, name=body.name, slug=slug, role=Role.OWNER.value)


@router.get("/workspaces/current", response_model=TenantContextOut)
async def read_current_workspace(
    ctx: TenantContext = Depends(get_tenant_context),
) -> TenantContextOut:
    return TenantContextOut(tenant_id=ctx.tenant_id, role=ctx.role.value)
