# Runs beyond the recovery horizon (poisoned-run guard)

**Symptoms:** `nlw_scheduler_runs_beyond_horizon` gauge > 0; a
`scheduler.runs_beyond_horizon` warning log (count + horizon, no run ids).

**Meaning (M9 req 4; refined M11.5 P1D):** a PENDING/RUNNING run has made no
execution progress for longer than `scheduler_recovery_horizon_s` (default 24h).
Progress is measured by `workflow_runs.last_progress_at` (stamped only on genuine
state-machine advancement) for RUNNING and `created_at` for PENDING — NOT the
mutable `updated_at`, so an actively progressing long run is never falsely flagged.
To avoid an infinite re-enqueue loop, the reconciler **stops re-driving** a
beyond-horizon run. It does **not** mark the run FAILED — a human decides.
(WAITING_APPROVAL runs are exempt from the horizon.)

**Do:**
1. Query PENDING/RUNNING runs with the oldest `last_progress_at` (the log gives a
   count + horizon, deliberately no run ids — keep logs low-cardinality).
2. Inspect safely (see inspect-failed-run) to find why it cannot progress
   (e.g. a dependency permanently unavailable, a poisoned message).
3. Resolve deliberately: fix the dependency and let reconcile pick it up, or
   terminally fail the run through an authorized, audited operator procedure.
   Never bulk-mutate run state casually.

## Related P1D signals

- `nlw_scheduler_reconcile_fairness_deferred_total` rising: one tenant persistently
  has more eligible stale runs than the per-tenant cap
  (`scheduler_reconcile_per_tenant_limit`, default 20). Fair by design (other
  tenants still progress); investigate that tenant's runs if it stays high, and
  consider raising the cap (must stay `<= scheduler_batch_limit`).
- `nlw_scheduler_occurrence_exists_total` rising: due occurrences whose run already
  existed — normal with multiple scheduler instances or restarts (idempotent).
