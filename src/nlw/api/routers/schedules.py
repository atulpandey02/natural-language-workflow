"""Schedule endpoints (M8).

- ``POST /schedules``        admin/owner: attach a structured recurrence to a
                             materialized workflow (pins the current version).
- ``GET  /schedules``        member: list the tenant's schedules.
- ``GET  /schedules/{id}``   member.
- ``PATCH /schedules/{id}``  admin/owner: update recurrence / enable.
- ``DELETE /schedules/{id}`` admin/owner: DISABLE (retains history).

The LLM never creates schedules; recurrence is deterministically validated here.
``created_by`` is server-owned; admin/owner is enforced by role AND RLS.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.api.deps import get_app_settings, get_session, get_tenant_context, rate_limit, require_role
from nlw.api.schemas import ScheduleCreate, ScheduleOut, ScheduleUpdate
from nlw.core.config import Settings
from nlw.db.models import Schedule, Workflow
from nlw.db.quota import QuotaExceededError, enforce_cap, schedules_count_stmt
from nlw.db.repositories import ScheduleRepository
from nlw.scheduler.recurrence import Frequency, Recurrence, RecurrenceError, next_occurrence
from nlw.tenancy.context import Role, TenantContext

router = APIRouter()
_require_admin = require_role(Role.ADMIN)


def _recurrence(
    timezone: str, frequency: str, minute: int, hour: int | None, day_of_week: int | None
) -> Recurrence:
    try:
        return Recurrence(
            timezone=timezone,
            frequency=Frequency(frequency),
            minute=minute,
            hour=hour,
            day_of_week=day_of_week,
        )
    except (RecurrenceError, ValueError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _to_out(s: Schedule) -> ScheduleOut:
    return ScheduleOut(
        id=s.id,
        workflow_id=s.workflow_id,
        workflow_version_id=s.workflow_version_id,
        timezone=s.timezone,
        frequency=s.frequency,
        minute=s.minute,
        hour=s.hour,
        day_of_week=s.day_of_week,
        enabled=s.enabled,
        next_run_at=s.next_run_at.isoformat(),
        last_scheduled_for=_iso(s.last_scheduled_for),
    )


@router.post(
    "/schedules",
    response_model=ScheduleOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("schedules_create", "write"))],
)
async def create_schedule(
    body: ScheduleCreate,
    ctx: TenantContext = Depends(_require_admin),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_app_settings),
) -> ScheduleOut:
    workflow = (
        await session.execute(
            select(Workflow).where(
                Workflow.id == body.workflow_id, Workflow.tenant_id == ctx.tenant_id
            )
        )
    ).scalar_one_or_none()
    if workflow is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workflow not found")
    if workflow.current_version_id is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "workflow has no materialized version"
        )

    # Concurrency-safe per-tenant schedule cap (advisory-locked count+insert).
    try:
        await enforce_cap(
            session,
            resource="schedules",
            tenant_id=ctx.tenant_id,
            cap=settings.max_schedules_per_tenant,
            count_stmt=schedules_count_stmt(ctx.tenant_id),
        )
    except QuotaExceededError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    rec = _recurrence(body.timezone, body.frequency, body.minute, body.hour, body.day_of_week)
    now = datetime.now(UTC)
    schedule = Schedule(
        tenant_id=ctx.tenant_id,
        workflow_id=workflow.id,
        workflow_version_id=workflow.current_version_id,  # pin immutable version (req 1)
        timezone=body.timezone,
        frequency=body.frequency,
        minute=body.minute,
        hour=body.hour,
        day_of_week=body.day_of_week,
        enabled=True,
        next_run_at=next_occurrence(rec, now),
        created_by=ctx.user_id,  # server-owned (req 6)
    )
    await ScheduleRepository(session).create(schedule)
    return _to_out(schedule)


@router.get("/schedules", response_model=list[ScheduleOut])
async def list_schedules(
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> list[ScheduleOut]:
    schedules = await ScheduleRepository(session).list_for_tenant(ctx.tenant_id)
    return [_to_out(s) for s in schedules]


@router.get("/schedules/{schedule_id}", response_model=ScheduleOut)
async def get_schedule(
    schedule_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> ScheduleOut:
    s = await ScheduleRepository(session).get(schedule_id, ctx.tenant_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    return _to_out(s)


@router.patch(
    "/schedules/{schedule_id}",
    response_model=ScheduleOut,
    dependencies=[Depends(rate_limit("schedules_update", "write"))],
)
async def update_schedule(
    schedule_id: uuid.UUID,
    body: ScheduleUpdate,
    ctx: TenantContext = Depends(_require_admin),
    session: AsyncSession = Depends(get_session),
) -> ScheduleOut:
    s = await ScheduleRepository(session).get(schedule_id, ctx.tenant_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")

    fields: dict[str, Any] = body.model_dump(exclude_unset=True)
    for attr in ("timezone", "frequency", "minute", "hour", "day_of_week", "enabled"):
        if attr in fields:
            setattr(s, attr, fields[attr])
    # Re-validate + recompute next_run_at if any recurrence field changed.
    if fields.keys() & {"timezone", "frequency", "minute", "hour", "day_of_week"}:
        rec = _recurrence(s.timezone, s.frequency, s.minute, s.hour, s.day_of_week)
        s.next_run_at = next_occurrence(rec, datetime.now(UTC))
    await session.flush()
    return _to_out(s)


@router.delete("/schedules/{schedule_id}", response_model=ScheduleOut)
async def disable_schedule(
    schedule_id: uuid.UUID,
    ctx: TenantContext = Depends(_require_admin),
    session: AsyncSession = Depends(get_session),
) -> ScheduleOut:
    """Disable (soft) rather than destroy — retains run history/audit (D7)."""
    s = await ScheduleRepository(session).get(schedule_id, ctx.tenant_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    s.enabled = False
    await session.flush()
    return _to_out(s)
