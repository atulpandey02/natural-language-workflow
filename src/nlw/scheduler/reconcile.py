"""Stale-run reconciliation (M8, ADR-015).

Recovery eligibility is reconstructed entirely from PostgreSQL; Redis is used
only as transport for the re-enqueued run_id. It WRITES NOTHING — the worker
remains the sole writer of
run/step/action state, and its M7 resume logic enforces lease / next_attempt_at /
approval, so a re-enqueue can never duplicate a live action or re-run a SUCCESS
step. Re-enqueue is idempotent (M3 FOR UPDATE + idempotent replay).

Eligibility:
- PENDING older than the threshold      -> never enqueued / lost message.
- RUNNING with an in-flight action whose lease is expired AND next_attempt_at is
  due/absent                            -> resume (worker re-attempts safely).
- RUNNING with no in-flight action, stale -> ordinary between-steps stall.
- WAITING_APPROVAL with a decided (approved OR rejected) approval -> lost resume.
Excluded: live lease, future next_attempt_at, pending approval, terminal runs.
"""

import uuid
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

_SQL = text(
    """
    SELECT r.id FROM workflow_runs r
    WHERE
      (r.status = 'PENDING' AND r.created_at < :stale_before)
      OR (r.status = 'RUNNING' AND (
            EXISTS (
                SELECT 1 FROM external_actions e
                WHERE e.run_id = r.id AND e.status = 'pending'
                  AND (e.lease_expires_at IS NULL OR e.lease_expires_at < :now)
                  AND (e.next_attempt_at IS NULL OR e.next_attempt_at <= :now)
            )
            OR (
                NOT EXISTS (
                    SELECT 1 FROM external_actions e2
                    WHERE e2.run_id = r.id AND e2.status = 'pending'
                )
                AND r.updated_at < :stale_before
            )
      ))
      OR (r.status = 'WAITING_APPROVAL' AND EXISTS (
            SELECT 1 FROM approvals a
            WHERE a.run_id = r.id AND a.status IN ('approved', 'rejected')
      ))
    ORDER BY r.updated_at
    LIMIT :batch
    """
)


def find_stuck_runs(
    session: Session,
    now: datetime,
    *,
    pending_threshold_s: int,
    batch_limit: int,
) -> list[uuid.UUID]:
    stale_before = now - timedelta(seconds=pending_threshold_s)
    rows = session.execute(
        _SQL, {"now": now, "stale_before": stale_before, "batch": batch_limit}
    ).scalars()
    return [uuid.UUID(str(r)) for r in rows]
