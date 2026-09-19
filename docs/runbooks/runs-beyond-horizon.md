# Runs beyond the recovery horizon (poisoned-run guard)

**Symptoms:** `nlw_scheduler_runs_beyond_horizon` gauge > 0; a
`scheduler.runs_beyond_horizon` warning log with a sample of run ids.

**Meaning (M9, req 4):** a PENDING/RUNNING run has been repeatedly recoverable for
longer than `scheduler_recovery_horizon_s` (default 24h). To avoid an infinite
re-enqueue loop, the reconciler **stops re-driving it**. It does **not** mark the
run FAILED — a human decides. (WAITING_APPROVAL runs are exempt from the horizon.)

**Do:**
1. Identify the run(s) from the warning log sample (`run_id`).
2. Inspect safely (see inspect-failed-run) to find why it cannot progress
   (e.g. a dependency permanently unavailable, a poisoned message).
3. Resolve deliberately: fix the dependency and let reconcile pick it up (reset
   `updated_at`/state via an authorized, audited path), or terminally fail the run
   through an operator procedure. Never bulk-mutate run state casually.
