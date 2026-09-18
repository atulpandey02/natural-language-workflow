"""FastAPI dependency wiring for auth and tenancy.

Keeps HTTP concerns here; the verification and role logic live in ``nlw.auth``
and ``nlw.tenancy``. Status codes follow the M2a failure matrix:

- 401 missing/invalid token
- 400 missing/invalid ``X-Workspace-Id``
- 403 authenticated but not a member (or insufficient role); also 403 for a
  non-existent workspace, to avoid cross-tenant enumeration.
"""

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from nlw.auth.provider import AuthedIdentity, AuthProvider, InvalidTokenError
from nlw.db.models import User
from nlw.db.repositories import MembershipRepository, UserRepository
from nlw.tenancy.context import Role, TenantContext, role_at_least

_bearer = HTTPBearer(auto_error=False)


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    sessionmaker = request.app.state.sessionmaker
    async with sessionmaker() as session:
        yield session


def get_auth_provider(request: Request) -> AuthProvider:
    provider: AuthProvider = request.app.state.auth_provider
    return provider


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    provider: AuthProvider = Depends(get_auth_provider),
    session: AsyncSession = Depends(get_session),
) -> User:
    if credentials is None or not credentials.credentials:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    try:
        # Verification is sync (cached JWKS + CPU); run off the event loop.
        identity: AuthedIdentity = await run_in_threadpool(
            provider.verify_token, credentials.credentials
        )
    except InvalidTokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from exc
    return await UserRepository(session).get_or_create(identity.sub, identity.email)


async def get_tenant_context(
    x_workspace_id: str | None = Header(default=None),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> TenantContext:
    if x_workspace_id is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "X-Workspace-Id header required")
    try:
        workspace_id = uuid.UUID(x_workspace_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "X-Workspace-Id must be a UUID") from exc

    membership = await MembershipRepository(session).get(user.id, workspace_id)
    if membership is None:
        # Same response whether the workspace is foreign or nonexistent.
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not a member of the workspace")
    return TenantContext(user_id=user.id, tenant_id=workspace_id, role=Role(membership.role))


def require_role(minimum: Role) -> Callable[[TenantContext], Awaitable[TenantContext]]:
    async def dependency(ctx: TenantContext = Depends(get_tenant_context)) -> TenantContext:
        if not role_at_least(ctx.role, minimum):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        return ctx

    return dependency
