"""Signed-context readiness self-check (M11.5 P3B).

Each runtime proves, at readiness time, that the key it holds is the key the
database verifies with: it signs a throwaway context for its own purpose and asks
``app_ctx_claims()`` to verify it. A NULL result means the key id is unknown /
revoked, the material differs, the purpose/role binding is wrong, or the migration
is not applied — all of which must surface as NOT READY (every tenant query would
fail closed). Nothing secret is sent or returned; the sentinel identifiers are
fixed nil UUIDs, and the tag is transaction-local and discarded on rollback.
"""

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.orm import Session

from nlw.observability import metrics
from nlw.tenancy.session import apply_signed_context, apply_signed_context_sync
from nlw.tenancy.signing import ContextSigner, Purpose

_NIL = uuid.UUID(int=0)
_PROBE_SQL = text("SELECT (public.app_ctx_claims()).purpose")


def _sentinel(signer: ContextSigner) -> dict[str, uuid.UUID | None]:
    if signer.purpose is Purpose.API_IDENTITY:
        return {"user_id": _NIL}
    if signer.purpose is Purpose.API_REQUEST:
        return {"user_id": _NIL, "tenant_id": _NIL}
    if signer.purpose is Purpose.WORKER_EXECUTION:
        return {"tenant_id": _NIL, "run_id": _NIL}
    return {}


class SignedContextNotVerifiable(RuntimeError):
    """The database did not verify a context signed with this runtime's key."""


def _outcome(signer: ContextSigner, got: object) -> None:
    """Record the self-check result (bounded labels: purpose + valid/invalid) and
    raise on mismatch. The message names the key id for the operator log only."""
    ok = got == str(signer.purpose)
    metrics.record_ctx_verification(str(signer.purpose), ok, "not_verified")
    if not ok:
        raise SignedContextNotVerifiable(
            f"database did not verify a {signer.purpose} context for key id {signer.key_id!r}"
        )


async def check_signed_context(engine: AsyncEngine, signer: ContextSigner) -> None:
    try:
        async with engine.connect() as conn, conn.begin():
            session = AsyncSession(bind=conn)
            await apply_signed_context(session, signer.sign(**_sentinel(signer)))
            got = (await conn.execute(_PROBE_SQL)).scalar_one_or_none()
            await conn.rollback()
    except Exception:
        metrics.record_ctx_verification(str(signer.purpose), False, "db_error")
        raise
    _outcome(signer, got)


def check_signed_context_sync(session: Session, signer: ContextSigner) -> None:
    try:
        with session.begin():
            apply_signed_context_sync(session, signer.sign(**_sentinel(signer)))
            got = session.execute(_PROBE_SQL).scalar_one_or_none()
            session.rollback()
    except Exception:
        metrics.record_ctx_verification(str(signer.purpose), False, "db_error")
        raise
    _outcome(signer, got)
