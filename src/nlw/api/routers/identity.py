"""Identity and workspace endpoints.

- ``GET  /me``                current user (auth required)
- ``GET  /workspaces``        workspaces the caller belongs to
- ``POST /workspaces``        create a workspace + owner membership
- ``GET  /workspaces/current`` resolve the tenant context for X-Workspace-Id
"""

import uuid

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.api.deps import get_current_user, get_session, get_tenant_context
from nlw.api.schemas import TenantContextOut, UserOut, WorkspaceCreate, WorkspaceOut
from nlw.db.models import User
from nlw.db.repositories import MembershipRepository, WorkspaceRepository
from nlw.tenancy.context import Role, TenantContext

router = APIRouter()


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


@router.post("/workspaces", response_model=WorkspaceOut, status_code=status.HTTP_201_CREATED)
async def create_workspace(
    body: WorkspaceCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> WorkspaceOut:
    workspace = await WorkspaceRepository(session).create(body.name, _slugify(body.name))
    await MembershipRepository(session).create(user.id, workspace.id, Role.OWNER)
    await session.commit()
    return WorkspaceOut(
        id=workspace.id, name=workspace.name, slug=workspace.slug, role=Role.OWNER.value
    )


@router.get("/workspaces/current", response_model=TenantContextOut)
async def read_current_workspace(
    ctx: TenantContext = Depends(get_tenant_context),
) -> TenantContextOut:
    return TenantContextOut(tenant_id=ctx.tenant_id, role=ctx.role.value)
