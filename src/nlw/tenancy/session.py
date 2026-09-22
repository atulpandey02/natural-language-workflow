"""Apply a SIGNED, transaction-local database context (M11.5 P3B, ADR-024).

RLS no longer trusts bare ``app.user_id`` / ``app.tenant_id``. Every tenant-aware
transaction instead carries the ``app.ctx_*`` settings produced by a
``ContextSigner`` (purpose-bound, expiring, HMAC-tagged); PostgreSQL verifies the
tag in ``app_ctx_claims()`` before exposing any claim to a policy.

All settings are applied with ``set_config(name, value, true)`` — transaction-local
— so commit or rollback discards them and a pooled connection never carries a
context into a later transaction (``nlw.db.session`` additionally RESETs on
check-in as defence in depth). A new transaction ALWAYS needs a freshly signed
context; there is no session-level variant on purpose.
"""

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from nlw.tenancy.context import TenantContext
from nlw.tenancy.signing import ALL_GUCS, ContextSigner, Purpose, SignedContext

# One round trip, one CONSTANT statement (never built from strings — see
# tests/unit/test_sql_injection_guard.py): every GUC name is a literal, every
# value a bound parameter. The order is ALL_GUCS; tests/unit pin the two together.
_APPLY_SQL = text(
    "SELECT "
    "set_config('app.ctx_v', :v0, true), "
    "set_config('app.ctx_kid', :v1, true), "
    "set_config('app.ctx_role', :v2, true), "
    "set_config('app.ctx_purpose', :v3, true), "
    "set_config('app.ctx_user', :v4, true), "
    "set_config('app.ctx_tenant', :v5, true), "
    "set_config('app.ctx_run', :v6, true), "
    "set_config('app.ctx_iat', :v7, true), "
    "set_config('app.ctx_exp', :v8, true), "
    "set_config('app.ctx_nonce', :v9, true), "
    "set_config('app.ctx_mac', :v10, true)"
)


def _params(ctx: SignedContext) -> dict[str, str]:
    gucs = ctx.as_gucs()
    return {f"v{i}": gucs[name] for i, name in enumerate(ALL_GUCS)}


async def apply_signed_context(session: AsyncSession, ctx: SignedContext) -> None:
    """Set the signed context for the CURRENT transaction (async)."""
    await session.execute(_APPLY_SQL, _params(ctx))


def apply_signed_context_sync(session: Session, ctx: SignedContext) -> None:
    """Set the signed context for the CURRENT transaction (sync: worker/scheduler)."""
    session.execute(_APPLY_SQL, _params(ctx))


async def set_identity_context(
    session: AsyncSession, signer: ContextSigner, user_id: uuid.UUID
) -> None:
    """``api_identity``: verified human, no workspace (self rows + membership discovery)."""
    if signer.purpose is not Purpose.API_IDENTITY:
        raise ValueError("identity context requires an api_identity signer")
    await apply_signed_context(session, signer.sign(user_id=user_id))


async def set_request_context(
    session: AsyncSession, signer: ContextSigner, ctx: TenantContext
) -> None:
    """``api_request``: verified human + the workspace whose membership was confirmed."""
    if signer.purpose is not Purpose.API_REQUEST:
        raise ValueError("request context requires an api_request signer")
    await apply_signed_context(session, signer.sign(user_id=ctx.user_id, tenant_id=ctx.tenant_id))


def set_worker_context_sync(
    session: Session, signer: ContextSigner, tenant_id: uuid.UUID, run_id: uuid.UUID
) -> None:
    """``worker_execution``: the claimed run's tenant + run (rows bound to that run)."""
    if signer.purpose is not Purpose.WORKER_EXECUTION:
        raise ValueError("worker context requires a worker_execution signer")
    apply_signed_context_sync(session, signer.sign(tenant_id=tenant_id, run_id=run_id))


def set_worker_context_default(session: Session, tenant_id: uuid.UUID, run_id: uuid.UUID) -> None:
    """Worker context using the process-registered worker signer (fail closed)."""
    from nlw.tenancy.keys import process_signer

    set_worker_context_sync(session, process_signer(Purpose.WORKER_EXECUTION), tenant_id, run_id)


def set_scheduler_context_sync(session: Session, signer: ContextSigner) -> None:
    """``scheduler_reconcile``: cross-tenant scan/reconcile, no human, no tenant."""
    if signer.purpose is not Purpose.SCHEDULER_RECONCILE:
        raise ValueError("scheduler context requires a scheduler_reconcile signer")
    apply_signed_context_sync(session, signer.sign())
