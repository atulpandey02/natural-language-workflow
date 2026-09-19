# Scheduler lagging / stopped

**Symptoms:** due runs not created on time; `nlw_scheduler_runs_created_total`
flat; reconcile not running.

**Do:**
1. Check the scheduler container + logs; confirm its metrics port is up.
2. Confirm it connects as `nlw_scheduler` and Postgres/Redis are reachable.
3. Restart it. Due-scan is idempotent (exactly one run row per occurrence via
   SKIP LOCKED + unique constraint), so restarts never double-create runs.
4. Bounded catch-up fires only the latest missed occurrence within the catch-up
   window; large gaps are intentionally not backfilled.
