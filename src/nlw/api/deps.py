"""FastAPI dependency wiring for auth and tenancy.

Keeps HTTP concerns here; the verification and role logic live in ``nlw.auth``
and ``nlw.tenancy``. Status codes follow the M2a failure matrix:

- 401 missing/invalid token
- 400 missing/invalid ``X-Workspace-Id``
- 403 authenticated but not a member (or insufficient role); also 403 for a
  non-existent workspace, to avoid cross-tenant enumeration.
"""

import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Literal

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from nlw.auth.provider import AuthedIdentity, AuthProvider, InvalidTokenError
from nlw.core.config import Settings
from nlw.db.models import User
from nlw.db.repositories import MembershipRepository, UserRepository
from nlw.observability import metrics
from nlw.planner.provider import LLMProvider
from nlw.ratelimit.limiter import RateLimitBackendError, RateLimiter, RateLimitExceeded
from nlw.tenancy.context import Role, TenantContext, role_at_least
from nlw.tenancy.session import set_current_tenant, set_current_user

_bearer = HTTPBearer(auto_error=False)


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    # One transaction per request so that SET LOCAL app.* GUCs (set below) apply
    # to every query and are discarded when the transaction ends — pooled
    # connections never carry tenant context into a later request.
    sessionmaker = request.app.state.sessionmaker
    session = sessionmaker()
    async with session:
        # session.begin() acquires a pooled connection; timing it captures pool
        # checkout wait (rises under saturation, ~0 with headroom) — M11 capacity.
        start = time.perf_counter()
        async with session.begin():
            metrics.observe_db_checkout_wait(time.perf_counter() - start)
            yield session


def get_auth_provider(request: Request) -> AuthProvider:
    provider: AuthProvider = request.app.state.auth_provider
    return provider


def get_app_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_llm_provider(request: Request) -> LLMProvider:
    provider: LLMProvider = request.app.state.llm_provider
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
    user = await UserRepository(session).get_or_create(identity.sub, identity.email)
    # Identity is established: set app.user_id so RLS "own row" policies apply.
    await set_current_user(session, user.id)
    return user


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

    # Membership is confirmed via the "own row" policy (app.user_id), NOT by
    # trusting the requested workspace. Only after confirmation do we activate
    # the tenant GUC, so a non-member can never widen their access by asking.
    membership = await MembershipRepository(session).get(user.id, workspace_id)
    if membership is None:
        # Same response whether the workspace is foreign or nonexistent.
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not a member of the workspace")
    await set_current_tenant(session, workspace_id)
    return TenantContext(user_id=user.id, tenant_id=workspace_id, role=Role(membership.role))


def require_role(minimum: Role) -> Callable[[TenantContext], Awaitable[TenantContext]]:
    async def dependency(ctx: TenantContext = Depends(get_tenant_context)) -> TenantContext:
        if not role_at_least(ctx.role, minimum):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        return ctx

    return dependency


RateLimitKind = Literal["plans", "write"]


def rate_limit(
    endpoint: str, kind: RateLimitKind
) -> Callable[[Request, TenantContext], Awaitable[None]]:
    """Per-tenant AND per-user fixed-window limit for a cost/mutating endpoint.

    Cost-bearing endpoints fail CLOSED (503) if the limiter backend is down
    (unless ``rate_limit_fail_open`` is set); over-limit callers get 429 with a
    ``Retry-After`` header.
    """

    async def dependency(
        request: Request, ctx: TenantContext = Depends(get_tenant_context)
    ) -> None:
        settings: Settings = request.app.state.settings
        if not settings.rate_limit_enabled:
            return
        limiter: RateLimiter = request.app.state.rate_limiter
        per_min = (
            settings.rate_limit_plans_per_min
            if kind == "plans"
            else settings.rate_limit_writes_per_min
        )
        try:
            await limiter.check(f"nlw:rl:{endpoint}:t:{ctx.tenant_id.hex}", per_min)
            await limiter.check(f"nlw:rl:{endpoint}:u:{ctx.user_id.hex}", per_min)
        except RateLimitExceeded as exc:
            metrics.record_rate_limit_rejected(endpoint)
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "rate limit exceeded",
                headers={"Retry-After": str(exc.retry_after)},
            ) from exc
        except RateLimitBackendError as exc:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "rate limiter unavailable"
            ) from exc

    return dependency
