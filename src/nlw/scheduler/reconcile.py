"""Stale-run reconciliation (M8, ADR-015) + bounded recovery horizon (M9, req 4).

Recovery eligibility is reconstructed entirely from PostgreSQL; Redis is used
only as transport for the re-enqueued run_id. It WRITES NOTHING — the worker
remains the sole writer of run/step/action state, and its M7 resume logic
enforces lease / next_attempt_at / approval, so a re-enqueue can never duplicate
a live action or re-run a SUCCESS step. Re-enqueue is idempotent (M3 FOR UPDATE +
idempotent replay).

Eligibility:
- PENDING older than the threshold      -> never enqueued / lost message.
- RUNNING with an in-flight action whose lease is expired AND next_attempt_at is
  due/absent                            -> resume (worker re-attempts safely).
- RUNNING with no in-flight action, stale -> ordinary between-steps stall.
- WAITING_APPROVAL with a decided (approved OR rejected) approval -> lost resume.
Excluded: live lease, future next_attempt_at, pending approval, terminal runs.

Recovery horizon (M9): a repeatedly recoverable PENDING/RUNNING run that has not
progressed for longer than the horizon is a poisoned-run signal. We STOP
re-enqueuing it (to avoid an infinite re-enqueue loop) but DO NOT mutate it to
FAILED — an operator resolves it via the runbook. WAITING_APPROVAL is EXEMPT
from the horizon: a human may legitimately take arbitrarily long to decide.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

# ``beyond`` marks a PENDING/RUNNING run past the recovery horizon. For such rows
# the reconciler warns + counts instead of re-enqueuing. WAITING_APPROVAL rows
# always report beyond=false (horizon-exempt).
_SQL = text(
    """
    SELECT r.id,
      (CASE
         WHEN r.status = 'PENDING' THEN r.created_at < :horizon_before
         WHEN r.status = 'RUNNING' THEN r.updated_at < :horizon_before
         ELSE false
       END) AS beyond
    FROM workflow_runs r
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


@dataclass(frozen=True)
class StuckRun:
    run_id: uuid.UUID
    beyond_horizon: bool


def find_stuck_runs(
    session: Session,
    now: datetime,
    *,
    pending_threshold_s: int,
    batch_limit: int,
    recovery_horizon_s: int,
) -> list[StuckRun]:
    stale_before = now - timedelta(seconds=pending_threshold_s)
    horizon_before = now - timedelta(seconds=recovery_horizon_s)
    rows = session.execute(
        _SQL,
        {
            "now": now,
            "stale_before": stale_before,
            "horizon_before": horizon_before,
            "batch": batch_limit,
        },
    ).all()
    return [StuckRun(run_id=uuid.UUID(str(r[0])), beyond_horizon=bool(r[1])) for r in rows]
