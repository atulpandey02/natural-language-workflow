"""Concurrency-safe per-tenant resource caps (M9, req 3).

A naive count-then-insert races: two concurrent creates can both read
``count == cap-1`` and both insert, breaching the cap. We serialize
quota-sensitive creation with a transaction-scoped Postgres advisory lock keyed
by (resource type, tenant). Within the SAME transaction we then count under RLS
and enforce the cap before inserting, so at most one creation proceeds at a time
per (tenant, resource). The lock auto-releases at commit/rollback — no schema
change required (M9 stays migration-free).
"""

import hashlib
import uuid

from sqlalchemy import Select, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.db.models import Connector, Schedule, Workflow


class QuotaExceededError(Exception):
    """A per-tenant resource cap has been reached."""

    def __init__(self, resource: str, cap: int) -> None:
        super().__init__(f"{resource} limit of {cap} reached for this workspace")
        self.resource = resource
        self.cap = cap


def _lock_key(resource: str, tenant_id: uuid.UUID) -> int:
    """Stable signed 64-bit advisory-lock key for (resource, tenant)."""
    digest = hashlib.sha1(f"{resource}:{tenant_id.hex}".encode()).digest()[:8]
    return int.from_bytes(digest, byteorder="big", signed=True)


async def enforce_cap(
    session: AsyncSession,
    *,
    resource: str,
    tenant_id: uuid.UUID,
    cap: int,
    count_stmt: Select[tuple[int]],
) -> None:
    """Acquire the per-(resource, tenant) lock, count under RLS, enforce the cap.

    Must run inside the caller's create transaction so the lock is held until the
    insert commits.
    """
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:k)"), {"k": _lock_key(resource, tenant_id)}
    )
    current = (await session.execute(count_stmt)).scalar_one()
    if current >= cap:
        raise QuotaExceededError(resource, cap)


def connectors_count_stmt(tenant_id: uuid.UUID) -> Select[tuple[int]]:
    return select(func.count()).select_from(Connector).where(Connector.tenant_id == tenant_id)


def schedules_count_stmt(tenant_id: uuid.UUID) -> Select[tuple[int]]:
    return select(func.count()).select_from(Schedule).where(Schedule.tenant_id == tenant_id)


def workflows_count_stmt(tenant_id: uuid.UUID) -> Select[tuple[int]]:
    return select(func.count()).select_from(Workflow).where(Workflow.tenant_id == tenant_id)
