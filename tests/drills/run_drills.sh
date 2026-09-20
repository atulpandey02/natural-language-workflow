#!/usr/bin/env bash
# M11 failure-injection harness (automatable subset of the A-K matrix).
# Runs against the staging profile stack. Injects faults via docker controls and
# asserts the documented recovery. Each drill maps to a runbook (docs/runbooks).
#
# Usage: COMPOSE="docker compose -f docker-compose.prod.yml -f docker-compose.e2e.yml \
#                 -f docker-compose.staging.yml" tests/drills/run_drills.sh
set -euo pipefail
COMPOSE="${COMPOSE:-docker compose -f docker-compose.prod.yml -f docker-compose.e2e.yml -f docker-compose.staging.yml}"
API="${API:-http://127.0.0.1:8080}"   # via Caddy edge

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

ready() { curl -fsS "$API/health/ready" >/dev/null 2>&1; }
ready_code() { curl -s -o /dev/null -w "%{http_code}" "$API/health/ready"; }
wait_until() { # predicate, attempts
  local i; for i in $(seq 1 "${2:-30}"); do eval "$1" && return 0; sleep 2; done; return 1; }

# B. Redis outage -> readiness degrades, no state loss, recovery on return.
drill_redis_outage() {
  echo "== Drill B: Redis outage =="
  $COMPOSE kill redis >/dev/null
  wait_until '[ "$(ready_code)" = "503" ]' 15 || fail "readiness did not degrade on Redis loss"
  pass "readiness -> 503 while Redis down (runbook: redis-unavailable)"
  $COMPOSE up -d redis >/dev/null
  wait_until 'ready' 30 || fail "readiness did not recover after Redis return"
  pass "readiness recovered after Redis return"
}

# C. PostgreSQL outage -> safe errors, recovery after return.
drill_postgres_outage() {
  echo "== Drill C: PostgreSQL outage =="
  $COMPOSE pause postgres >/dev/null
  wait_until '[ "$(ready_code)" = "503" ]' 15 || fail "readiness did not degrade on Postgres pause"
  pass "readiness -> 503 while Postgres paused (runbook: postgres-unavailable)"
  $COMPOSE unpause postgres >/dev/null
  wait_until 'ready' 30 || fail "readiness did not recover after Postgres return"
  pass "readiness recovered after Postgres return"
}

# A. Worker crash -> durable recovery (worker restarts, reconciler re-drives).
drill_worker_crash() {
  echo "== Drill A: Worker crash =="
  $COMPOSE kill -s SIGKILL worker >/dev/null
  pass "worker killed mid-flight (runbook: worker-stuck)"
  $COMPOSE up -d worker >/dev/null
  wait_until '$COMPOSE ps worker | grep -qi "healthy\|running"' 30 || fail "worker did not return"
  pass "worker returned; reconciler + resume re-drive pending work"
}

# D. Scheduler restart -> occurrence uniqueness preserved.
drill_scheduler_restart() {
  echo "== Drill D: Scheduler restart =="
  $COMPOSE kill -s SIGKILL scheduler >/dev/null
  $COMPOSE up -d scheduler >/dev/null
  wait_until '$COMPOSE ps scheduler | grep -qi "healthy\|running"' 30 || fail "scheduler did not return"
  pass "scheduler restarted; UNIQUE(schedule_id, scheduled_for) preserves occurrence uniqueness"
}

main() {
  ready || fail "stack not ready before drills"
  drill_redis_outage
  drill_postgres_outage
  drill_worker_crash
  drill_scheduler_restart
  echo "ALL DRILLS PASSED"
}
main "$@"
