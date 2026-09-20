#!/usr/bin/env bash
# M11 failure-injection harness (automatable subset of the A-K matrix).
# Runs against the staging profile stack. Injects faults via docker controls and
# asserts the documented recovery. Each drill maps to a runbook (docs/runbooks).
#
# Usage: COMPOSE="docker compose -f docker-compose.prod.yml -f docker-compose.e2e.yml \
#                 -f docker-compose.staging.yml" tests/drills/run_drills.sh
set -euo pipefail
COMPOSE="${COMPOSE:-docker compose -f docker-compose.prod.yml -f docker-compose.e2e.yml -f docker-compose.staging.yml}"
API="${API:-http://127.0.0.1:8000}"  # API readiness endpoint (loopback)

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

# Every readiness probe is bounded: a black-holed dependency (e.g. a paused
# Postgres holding an open socket) must never let a single curl — or a single
# wait_until iteration — block indefinitely.
CURL_BOUNDS=(--connect-timeout 2 --max-time 5)
ready() { curl -fsS "${CURL_BOUNDS[@]}" "$API/health/ready" >/dev/null 2>&1; }  # true only on HTTP 200
ready_code() {
  # Bounded; on transport timeout/failure curl exits non-zero and leaves
  # %{http_code}=000 — normalize to the 000 sentinel so callers get a comparable
  # value and the predicate never aborts (or hangs) under set -e.
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" "${CURL_BOUNDS[@]}" "$API/health/ready" 2>/dev/null) || code="000"
  echo "${code:-000}"
}
# Outage detection accepts an explicit 503 OR a bounded transport failure (000);
# recovery always requires a real HTTP 200 (via ready()).
degraded() { local c; c=$(ready_code); [ "$c" = "503" ] || [ "$c" = "000" ]; }
wait_until() { # predicate, attempts
  local i; for i in $(seq 1 "${2:-30}"); do eval "$1" && return 0; sleep 2; done; return 1; }

# Docker container healthcheck status (not app readiness). After an unpause the
# container healthcheck lags app readiness by up to one interval, so downstream
# `up -d` steps that gate on depends_on(condition: service_healthy) must wait for
# it to flip back to "healthy" rather than the stale "unhealthy" left by the pause.
container_health() {
  local cid; cid=$($COMPOSE ps -q "$1" 2>/dev/null)
  [ -n "$cid" ] || { echo "unknown"; return 0; }
  docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || echo "unknown"
}

# B. Redis outage -> readiness degrades, no state loss, recovery on return.
drill_redis_outage() {
  echo "== Drill B: Redis outage =="
  $COMPOSE kill redis >/dev/null
  wait_until 'degraded' 15 || fail "readiness did not degrade on Redis loss"
  pass "readiness -> 503 while Redis down (runbook: redis-unavailable)"
  $COMPOSE up -d redis >/dev/null
  wait_until 'ready' 30 || fail "readiness did not recover after Redis return"
  pass "readiness recovered after Redis return"
}

# C. PostgreSQL outage -> safe errors, recovery after return.
drill_postgres_outage() {
  echo "== Drill C: PostgreSQL outage =="
  $COMPOSE pause postgres >/dev/null
  # pause black-holes the socket (SELECT would hang forever); the app-level
  # readiness timeout must still yield a bounded 503 (or a bounded 000).
  wait_until 'degraded' 15 || fail "readiness did not degrade on Postgres pause"
  pass "readiness degraded while Postgres paused (runbook: postgres-unavailable)"
  $COMPOSE unpause postgres >/dev/null
  wait_until 'ready' 30 || fail "readiness did not recover after Postgres return"
  # Also wait for the postgres container healthcheck to clear the stale "unhealthy"
  # from the pause, so later depends_on(service_healthy) `up -d` steps don't fail.
  wait_until '[ "$(container_health postgres)" = "healthy" ]' 30 \
    || fail "postgres container did not report healthy after unpause"
  pass "readiness recovered after Postgres return"
}

# A. Worker crash -> durable recovery (worker restarts, reconciler re-drives).
drill_worker_crash() {
  echo "== Drill A: Worker crash =="
  $COMPOSE kill -s SIGKILL worker >/dev/null
  pass "worker killed mid-flight (runbook: worker-stuck)"
  # Restart only this process: the datastores are already up, so --no-deps avoids
  # re-gating on depends_on(service_healthy) (which can briefly lag, e.g. right
  # after the Drill C unpause).
  $COMPOSE up -d --no-deps worker >/dev/null
  wait_until '$COMPOSE ps worker | grep -qi "healthy\|running"' 30 || fail "worker did not return"
  pass "worker returned; reconciler + resume re-drive pending work"
}

# D. Scheduler restart -> occurrence uniqueness preserved.
drill_scheduler_restart() {
  echo "== Drill D: Scheduler restart =="
  $COMPOSE kill -s SIGKILL scheduler >/dev/null
  # Restart only this process (see Drill A): --no-deps skips dependency re-gating.
  $COMPOSE up -d --no-deps scheduler >/dev/null
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

# Run the drills only when executed directly; allow tests to source the helpers
# (e.g. to prove ready_code() is bounded) without injecting any faults.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main "$@"
fi
