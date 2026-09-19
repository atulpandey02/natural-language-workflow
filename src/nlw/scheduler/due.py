"""Due-schedule scan: claim due schedules, create runs exactly-once, advance
next_run_at — all in one transaction (M8, ADR-015).

Exactly-once is guaranteed by ``FOR UPDATE SKIP LOCKED`` on the claim plus
``UNIQUE(schedule_id, scheduled_for)`` on the run. Run creation + next_run_at
advancement commit atomically; enqueue happens AFTER commit (caller's job).
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from nlw.db.models import Schedule, WorkflowRun
from nlw.scheduler.recurrence import Frequency, Recurrence, latest_occurrence, next_occurrence


@dataclass(frozen=True)
class CreatedRun:
    run_id: uuid.UUID
    tenant_id: uuid.UUID
    schedule_id: uuid.UUID
    scheduled_for: datetime


def _recurrence(s: Schedule) -> Recurrence:
    return Recurrence(
        timezone=s.timezone,
        frequency=Frequency(s.frequency),
        minute=s.minute,
        hour=s.hour,
        day_of_week=s.day_of_week,
    )


def scan_due(
    session: Session,
    now: datetime,
    *,
    catchup_window_s: int,
    batch_limit: int,
) -> list[CreatedRun]:
    """One due-scan transaction. Returns runs created (to enqueue after commit)."""
    due = (
        session.execute(
            select(Schedule)
            .where(Schedule.enabled.is_(True), Schedule.next_run_at <= now)
            .order_by(Schedule.next_run_at)
            .with_for_update(skip_locked=True)
            .limit(batch_limit)
        )
        .scalars()
        .all()
    )

    created: list[CreatedRun] = []
    catchup = timedelta(seconds=catchup_window_s)
    for s in due:
        rec = _recurrence(s)
        scheduled_for = latest_occurrence(rec, now)
        run_made = False

        if scheduled_for is not None and (now - scheduled_for) <= catchup:
            run_id = uuid.uuid4()
            key = f"sched:{s.id}:{scheduled_for.isoformat()}"
            stmt = (
                pg_insert(WorkflowRun)
                .values(
                    id=run_id,
                    tenant_id=s.tenant_id,  # matching tenant (req 8)
                    workflow_id=s.workflow_id,
                    workflow_version_id=s.workflow_version_id,  # pinned version (req 8)
                    status="PENDING",
                    trigger="schedule",  # enforced trigger (req 8)
                    schedule_id=s.id,
                    scheduled_for=scheduled_for,
                    idempotency_key=key,
                )
                .on_conflict_do_nothing(constraint="uq_run_schedule_occurrence")
                .returning(WorkflowRun.id)
            )
            inserted = session.execute(stmt).scalar_one_or_none()
            if inserted is not None:
                run_made = True
                created.append(CreatedRun(run_id, s.tenant_id, s.id, scheduled_for))

        # Advance to the next future occurrence. last_scheduled_for updates ONLY
        # when a run was actually created (req 10).
        s.next_run_at = next_occurrence(rec, now)
        if run_made and scheduled_for is not None:
            s.last_scheduled_for = scheduled_for
        s.updated_at = now

    return created
