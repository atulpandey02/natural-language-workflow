# Failure & recovery drills (M11)

`run_drills.sh` injects faults into the staging profile and asserts recovery.
Each drill maps to a runbook (docs/runbooks):

| Drill | Runbook |
|---|---|
| A worker crash | worker-stuck.md |
| B redis outage | redis-unavailable.md |
| C postgres outage | postgres-unavailable.md |
| D scheduler restart | scheduler-lagging.md |
| backup/restore (`backup_restore_drill.sh`) | restore-from-backup.md |
| migration (`migration_drill.sh`) | failed-migration.md |

Windows A(4)/E/F/G/H/I/J/K and the historical crash windows (M3/M7 W1-W3/M8/M10)
are covered by the integration suite (test_crash_windows.py, test_action_execution.py,
test_engine_execution.py, test_scheduler_reconcile.py, test_workflows_api.py) and,
for real providers (Slack/webhook/LLM/Supabase), by the real-VPS checklist.

Run:

    COMPOSE="docker compose -f docker-compose.prod.yml -f docker-compose.e2e.yml -f docker-compose.staging.yml" \
      API=http://127.0.0.1:8080 tests/drills/run_drills.sh
