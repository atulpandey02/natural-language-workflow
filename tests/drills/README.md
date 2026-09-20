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

## Bounded probes

Every readiness probe (drill client and application) is bounded, so a
black-holed dependency can never hang a drill or the endpoint:

- Drill C uses `docker compose pause postgres` — a **black-hole/stalled-socket**
  outage: the TCP connection stays open but `SELECT` never returns. Server-side
  `statement_timeout` cannot fire (Postgres is frozen), so `/health/ready` relies
  on an application-level timeout (`readiness_probe_timeout_s`, default 3s) to
  return a bounded `503`. Drill B (`kill redis`) is a **connection-refused**
  outage by contrast.
- The drill's `ready_code`/`degraded` helpers use `curl --connect-timeout 2
  --max-time 5` and normalize a transport timeout to the `000` sentinel. Outage
  detection accepts `503` **or** a bounded `000`; recovery always requires a real
  `200`.

Run:

    COMPOSE="docker compose -f docker-compose.prod.yml -f docker-compose.e2e.yml -f docker-compose.staging.yml" \
      API=http://127.0.0.1:8000 tests/drills/run_drills.sh
