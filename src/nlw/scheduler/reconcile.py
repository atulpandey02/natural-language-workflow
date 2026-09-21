"""Stale-run reconciliation (M8, ADR-015) + recovery horizon (M9) + eligibility
ordering, progress tracking, and per-tenant fairness (M11.5 P1D, ADR-021).

Recovery eligibility is reconstructed entirely from PostgreSQL; Redis is used only
as transport for the re-enqueued run_id. This module WRITES NOTHING — the worker
remains the sole writer of run/step/action state, and its resume logic enforces
lease / next_attempt_at / approval / UNKNOWN, so a re-enqueue can never duplicate
a live action, re-run a SUCCESS step, or resend an UNKNOWN action. Re-enqueue is
idempotent (the worker's ``FOR UPDATE`` on the run + idempotent replay), so two
reconcilers selecting the same run cause at most one advancement.

Eligibility (a run the reconciler may re-drive):
- PENDING older than the stale threshold      -> never enqueued / lost message.
- RUNNING with an in-flight action whose lease is expired AND next_attempt_at is
  due/absent, and NO unknown action            -> resume (worker re-attempts).
- RUNNING with no in-flight action and no PROGRESS since the stale threshold
  (``last_progress_at``, not the mutable ``updated_at``) -> between-steps stall.
- WAITING_APPROVAL whose CURRENTLY-blocked step's approval is decided
  (approved/rejected) -> lost resume. Bound to the waiting step, never "any
  approval for the run" (a run may have several approval steps / historical rows).
Excluded: live lease, future next_attempt_at, pending approval, terminal runs,
and any run bearing an ``unknown`` (P1C terminal) action.

Ordering & fairness (P1D):
- ALL deterministic eligibility filters (incl. the recovery horizon) run BEFORE
  ORDER BY / LIMIT, so a batch never fills with beyond-horizon/ineligible rows
  while eligible stale rows go unseen.
- A stable order (``progress_at ASC, id ASC``) with a unique tie-breaker.
- ``row_number() OVER (PARTITION BY tenant_id ...)`` caps each tenant at
  ``per_tenant_limit`` rows, then a global ``LIMIT batch_limit`` — so one noisy
  tenant with thousands of stale rows cannot starve a quiet tenant's single row.

Recovery horizon (M9): a stale PENDING/RUNNING run whose progress timestamp is
older than the horizon is a poisoned-run signal. It is EXCLUDED from re-enqueue
(counted into a gauge + one aggregate warning per scan) but NEVER mutated to
FAILED — an operator resolves it via the runbook. WAITING_APPROVAL is horizon
EXEMPT (a human may take arbitrarily long to decide).
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

# The progress timestamp used for staleness/horizon/ordering. PENDING has no
# execution progress yet, so its age is created_at; a started run uses the
# server-stamped last_progress_at (falling back to created_at for rows predating
# the P1D backfill). These are STATIC SQL fragments — no user input is interpolated.
_PROGRESS_AT = (
    "CASE WHEN r.status = 'PENDING' THEN r.created_at "
    "ELSE COALESCE(r.last_progress_at, r.created_at) END"
)

# A run the reconciler could re-drive (all deterministic filters; applied BEFORE
# ORDER BY / LIMIT). Bind params: :now, :stale_before.
_ELIGIBLE_WHERE = """
      (r.status = 'PENDING' AND r.created_at < :stale_before)
      OR (r.status = 'RUNNING'
          -- A P1C UNKNOWN (ambiguous-outcome) action is TERMINAL: never reclaimed,
          -- resumed, or redelivered. (The finalizer also sets the run FAILED, so
          -- such a run is normally already excluded; this is defence-in-depth.)
          AND NOT EXISTS (
                SELECT 1 FROM external_actions eu
                WHERE eu.run_id = r.id AND eu.status = 'unknown'
          )
          AND (
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
                AND COALESCE(r.last_progress_at, r.created_at) < :stale_before
            )
      ))
      -- WAITING_APPROVAL is re-driven ONLY when the CURRENTLY-blocked step's own
      -- approval is decided (bound to the waiting step, never "any approval for
      -- the run"), so a historical/other-step approval cannot re-drive a run whose
      -- current step is still pending.
      OR (r.status = 'WAITING_APPROVAL' AND EXISTS (
            SELECT 1 FROM approvals a
            JOIN step_runs sr ON sr.run_id = r.id AND sr.step_id = a.step_id
            WHERE a.run_id = r.id
              AND sr.status = 'WAITING_APPROVAL'
              AND a.status IN ('approved', 'rejected')
      ))
"""

# Beyond the recovery horizon (PENDING/RUNNING only; WAITING_APPROVAL is exempt).
# Bind param: :horizon_before.
_BEYOND = f"(r.status <> 'WAITING_APPROVAL' AND {_PROGRESS_AT} < :horizon_before)"

# Candidate selection: eligibility + horizon filter FIRST, then per-tenant fairness
# cap, then a deterministic global order + batch limit. The SQL is composed ONLY
# from the static fragments above (no user input) and assigned to a variable before
# text(...) — the sanctioned no-inline-interpolation pattern (test_sql_injection_
# guard). Every runtime value is a bound parameter.
_CANDIDATES_SQL_STR = f"""
    WITH eligible AS (
        SELECT r.id, r.tenant_id, {_PROGRESS_AT} AS progress_at, {_BEYOND} AS beyond
        FROM workflow_runs r
        WHERE {_ELIGIBLE_WHERE}
    ),
    ranked AS (
        SELECT id, progress_at,
               row_number() OVER (
                   PARTITION BY tenant_id ORDER BY progress_at ASC, id ASC
               ) AS rn
        FROM eligible
        WHERE NOT beyond
    )
    SELECT id
    FROM ranked
    WHERE rn <= :per_tenant_limit
    ORDER BY progress_at ASC, id ASC
    LIMIT :batch
    """
_CANDIDATES_SQL = text(_CANDIDATES_SQL_STR)

# Operational counters that do NOT depend on the batch/fairness limits: runs past
# the horizon (a gauge, not an ever-incrementing counter) and rows dropped by the
# per-tenant fairness cap this scan.
_STATS_SQL_STR = f"""
    WITH eligible AS (
        SELECT r.id, r.tenant_id, {_PROGRESS_AT} AS progress_at, {_BEYOND} AS beyond
        FROM workflow_runs r
        WHERE {_ELIGIBLE_WHERE}
    ),
    ranked AS (
        SELECT row_number() OVER (
                   PARTITION BY tenant_id ORDER BY progress_at ASC, id ASC
               ) AS rn
        FROM eligible
        WHERE NOT beyond
    )
    SELECT
      (SELECT count(*) FROM eligible WHERE beyond) AS beyond_count,
      (SELECT count(*) FROM ranked WHERE rn > :per_tenant_limit) AS deferred_count
    """
_STATS_SQL = text(_STATS_SQL_STR)


@dataclass(frozen=True)
class ReconcileBatch:
    """Result of one reconciliation scan.

    ``run_ids`` are the fair, horizon-eligible candidates to re-enqueue.
    ``beyond_horizon`` is how many stale runs were past the recovery horizon and
    deliberately NOT re-enqueued. ``fairness_deferred`` is how many eligible rows
    were dropped by the per-tenant cap this scan (they remain for a later scan).
    """

    run_ids: list[uuid.UUID]
    beyond_horizon: int
    fairness_deferred: int


def find_stuck_runs(
    session: Session,
    now: datetime,
    *,
    pending_threshold_s: int,
    batch_limit: int,
    recovery_horizon_s: int,
    per_tenant_limit: int,
) -> ReconcileBatch:
    stale_before = now - timedelta(seconds=pending_threshold_s)
    horizon_before = now - timedelta(seconds=recovery_horizon_s)
    params = {
        "now": now,
        "stale_before": stale_before,
        "horizon_before": horizon_before,
        "batch": batch_limit,
        "per_tenant_limit": per_tenant_limit,
    }
    run_ids = [uuid.UUID(str(row[0])) for row in session.execute(_CANDIDATES_SQL, params).all()]
    stats = session.execute(_STATS_SQL, params).one()
    return ReconcileBatch(
        run_ids=run_ids,
        beyond_horizon=int(stats[0]),
        fairness_deferred=int(stats[1]),
    )
