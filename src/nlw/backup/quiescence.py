"""Post-restore quiescence (M11.5 P2) — the critical DR correctness step.

A restored snapshot is an OLDER point in time. Between the snapshot and the
original host's failure, external actions and scheduled runs may already have
occurred; the restored database cannot know those outcomes. Before ANY runtime
service starts, we conservatively neutralize restored non-terminal work in one
transaction, connected as the owner/superuser (which bypasses FORCE RLS, so it can
touch every tenant's rows).

Transition matrix (uses only existing enum values):
  - runs  PENDING/RUNNING/WAITING_APPROVAL -> FAILED, error=DR_RESTORE_UNCERTAIN
  - steps PENDING/RUNNING/WAITING_APPROVAL -> FAILED, error=DR_RESTORE_UNCERTAIN
  - external_actions status='pending'       -> 'unknown' (P1C), lease cleared,
        next_attempt_at NULL, external_action_key UNCHANGED
  - external_actions already success/failed/unknown  -> UNCHANGED (never made
        retryable)
  - schedules next_run_at <= cutoff -> recomputed to the next occurrence strictly
        after the cutoff (so occurrences in the snapshot->restore gap are not
        replayed); occurrence rows (workflow_runs) and last_scheduled_for preserved
  - approvals: unchanged (audit preserved). A now-FAILED run is terminal, so no
        pending/historical approval can advance it (execute_advancement no-ops on
        terminal runs).

The operation is IDEMPOTENT: the WHERE clauses match only non-terminal / pre-cutoff
state, so a second run changes nothing. Every run is audited in ``dr_restore_events``
(a re-run that changes nothing records no new event).
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.engine import Engine

from nlw.backup.config import DR_RESTORE_UNCERTAIN
from nlw.engine.actions import ACTION_OUTCOME_UNKNOWN
from nlw.scheduler.recurrence import Frequency, Recurrence, next_occurrence

_QUIESCE_RUNS = text(
    "UPDATE workflow_runs SET status='FAILED', error=:reason, "
    "finished_at=:cutoff, last_progress_at=:cutoff "
    "WHERE status IN ('PENDING','RUNNING','WAITING_APPROVAL')"
)
_QUIESCE_STEPS = text(
    "UPDATE step_runs SET status='FAILED', error=:reason, finished_at=:cutoff "
    "WHERE status IN ('PENDING','RUNNING','WAITING_APPROVAL')"
)
_QUIESCE_ACTIONS = text(
    "UPDATE external_actions SET status='unknown', error_class=:unknown_code, "
    "lease_token=NULL, lease_owner=NULL, lease_expires_at=NULL, next_attempt_at=NULL "
    "WHERE status='pending'"
)
_SELECT_STALE_SCHEDULES = text(
    "SELECT id, timezone, frequency, minute, hour, day_of_week "
    "FROM schedules WHERE next_run_at <= :cutoff"
)
_UPDATE_SCHEDULE = text(
    "UPDATE schedules SET next_run_at=:next_run_at, updated_at=:cutoff WHERE id=:id"
)
_PRIOR_EVENTS = text("SELECT count(*) FROM dr_restore_events")
_INSERT_EVENT = text(
    "INSERT INTO dr_restore_events "
    "(id, cutoff_at, manifest_format, snapshot_id, alembic_revision, app_version, "
    " pg_version, runs_quiesced, steps_quiesced, actions_unknowned, schedules_recomputed, note) "
    "VALUES (gen_random_uuid(), :cutoff, :manifest_format, :snapshot_id, :alembic_revision, "
    " :app_version, :pg_version, :runs, :steps, :actions, :schedules, :note) RETURNING id"
)


@dataclass(frozen=True)
class QuiescenceResult:
    cutoff: datetime
    runs_quiesced: int
    steps_quiesced: int
    actions_unknowned: int
    schedules_recomputed: int
    event_recorded: bool


def quiesce(
    engine: Engine,
    *,
    now: datetime | None = None,
    manifest: dict[str, object] | None = None,
    note: str | None = None,
) -> QuiescenceResult:
    """Run the quiescence transaction as the owner. Returns the counts changed."""
    manifest = manifest or {}
    with engine.begin() as conn:
        cutoff = now or conn.execute(text("SELECT now()")).scalar_one()
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=UTC)

        runs = conn.execute(
            _QUIESCE_RUNS, {"reason": DR_RESTORE_UNCERTAIN, "cutoff": cutoff}
        ).rowcount
        steps = conn.execute(
            _QUIESCE_STEPS, {"reason": DR_RESTORE_UNCERTAIN, "cutoff": cutoff}
        ).rowcount
        actions = conn.execute(_QUIESCE_ACTIONS, {"unknown_code": ACTION_OUTCOME_UNKNOWN}).rowcount

        # Recompute only schedules that could replay a pre-cutoff occurrence.
        stale = conn.execute(_SELECT_STALE_SCHEDULES, {"cutoff": cutoff}).all()
        recomputed = 0
        for row in stale:
            rec = Recurrence(
                timezone=row.timezone,
                frequency=Frequency(row.frequency),
                minute=row.minute,
                hour=row.hour,
                day_of_week=row.day_of_week,
            )
            nxt = next_occurrence(rec, cutoff)  # strictly after cutoff by construction
            conn.execute(_UPDATE_SCHEDULE, {"next_run_at": nxt, "cutoff": cutoff, "id": row.id})
            recomputed += 1

        changed = bool(runs or steps or actions or recomputed)
        prior = int(conn.execute(_PRIOR_EVENTS).scalar_one())
        event_recorded = changed or prior == 0
        if event_recorded:
            conn.execute(
                _INSERT_EVENT,
                {
                    "cutoff": cutoff,
                    "manifest_format": manifest.get("format"),
                    "snapshot_id": manifest.get("snapshot_id"),
                    "alembic_revision": manifest.get("alembic_revision"),
                    "app_version": manifest.get("app_version"),
                    "pg_version": manifest.get("pg_version"),
                    "runs": runs,
                    "steps": steps,
                    "actions": actions,
                    "schedules": recomputed,
                    "note": note,
                },
            )

    return QuiescenceResult(
        cutoff=cutoff,
        runs_quiesced=runs,
        steps_quiesced=steps,
        actions_unknowned=actions,
        schedules_recomputed=recomputed,
        event_recorded=event_recorded,
    )
