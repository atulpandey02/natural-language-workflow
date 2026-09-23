"""Due-schedule scan: claim due schedules, create runs exactly-once, advance
next_run_at — all in one transaction (M8, ADR-015).

Exactly-once is guaranteed by ``FOR UPDATE SKIP LOCKED`` on the claim plus
``UNIQUE(schedule_id, scheduled_for)`` on the run. Run creation + next_run_at
advancement commit atomically; enqueue happens AFTER commit (caller's job).
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from nlw.db.models import Schedule, WorkflowRun
from nlw.observability import metrics
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
            .where(
                Schedule.enabled.is_(True),
                Schedule.next_run_at <= now,
                # Already-blocked schedules are excluded until an admin remediates,
                # so a blocked schedule never re-scans (no unbounded failed work).
                Schedule.blocked_reason.is_(None),
            )
            .order_by(Schedule.next_run_at)
            .with_for_update(skip_locked=True)
            .limit(batch_limit)
        )
        .scalars()
        .all()
    )

    created: list[CreatedRun] = []
    already_existed = 0
    catchup = timedelta(seconds=catchup_window_s)
    for s in due:
        rec = _recurrence(s)
        scheduled_for = latest_occurrence(rec, now)
        run_made = False

        # Fail-closed authorization (M12B, Part 4): the creator must still be an
        # active member with a sufficient role. The check is a SECURITY DEFINER
        # function (nlw_scheduler cannot read memberships). The model never decides.
        block_reason = session.execute(
            text("SELECT schedule_creator_block_reason(:sid)"), {"sid": str(s.id)}
        ).scalar_one_or_none()
        if block_reason is not None:
            # Create NO run and enqueue nothing; record a stable blocked state +
            # low-cardinality metric, and advance next_run_at so a later remediation
            # resumes cleanly. The schedule is now excluded until an admin unblocks.
            s.blocked_reason = block_reason
            s.blocked_at = now
            s.next_run_at = next_occurrence(rec, now)
            s.updated_at = now
            metrics.record_schedule_blocked(block_reason)
            continue

        if scheduled_for is not None and (now - scheduled_for) <= catchup:
            run_id = uuid.uuid4()
            # Scheduled-run uniqueness comes SOLELY from the immutable occurrence
            # identity (schedule_id, scheduled_for) via uq_run_schedule_occurrence.
            # We deliberately leave idempotency_key NULL so a scheduled run never
            # occupies the CLIENT idempotency namespace (uq_run_tenant_idempotency):
            # a user-supplied Idempotency-Key can never collide with, suppress, or
            # be mistaken for a scheduled occurrence (P1D). NULLs are distinct, so
            # many scheduled runs per tenant coexist.
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
                    idempotency_key=None,
                    # P3A: the responsible human for a scheduled run is the immutable
                    # schedule creator — denormalized here so the worker (which has no
                    # schedules access) can set the approval requester from the run.
                    initiated_by_user_id=s.created_by,
                )
                .on_conflict_do_nothing(constraint="uq_run_schedule_occurrence")
                .returning(WorkflowRun.id)
            )
            inserted = session.execute(stmt).scalar_one_or_none()
            if inserted is not None:
                run_made = True
                created.append(CreatedRun(run_id, s.tenant_id, s.id, scheduled_for))
            else:
                # The occurrence's run already existed: a concurrent scheduler or a
                # restart re-scanning the same occurrence -> idempotent no-op.
                already_existed += 1

        # Advance to the next future occurrence. last_scheduled_for updates ONLY
        # when a run was actually created (req 10).
        s.next_run_at = next_occurrence(rec, now)
        if run_made and scheduled_for is not None:
            s.last_scheduled_for = scheduled_for
        s.updated_at = now

    metrics.record_scheduler_occurrence_exists(already_existed)
    return created
