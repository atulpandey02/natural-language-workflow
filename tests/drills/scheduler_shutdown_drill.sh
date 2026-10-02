#!/usr/bin/env bash
# Real-container scheduler shutdown drill (production-shaped Compose).
#
# Runs the scheduler exactly as staging does (docker-compose.prod.yml +
# docker-compose.staging.yml, the immutable backend image, APP_ENV=staging,
# signed-context key file, its own nlw_scheduler role) in an ISOLATED throwaway
# Compose project, then stops it the way the rollout `drain` phase does
# (`docker compose stop scheduler`, Docker's default grace period) and requires:
#   - exit code 0 (never 137 = SIGKILL after the grace period);
#   - the stop returns well inside the grace period;
#   - no queue message is produced while/after shutting down (empty Redis queue).
# Rounds: idle steady state, stop during initialization, repeated SIGTERM.
#
#   NLW_IMAGE=<backend image> tests/drills/scheduler_shutdown_drill.sh
#
# Synthetic credentials and keys are generated per run, never printed, and
# removed with the project (volumes included) on exit.
#
#   tests/drills/scheduler_shutdown_drill.sh --verdict ELAPSED_MS EXIT_CODE "ALLOWED" QUEUE_LEN MAX_STOP_S
# evaluates only the PASS/FAIL rule below (no Docker), for deterministic tests.
set -euo pipefail

# PASS only if the exit code is allowed, the stop finished inside MAX_STOP_S,
# and the Redis queue length is an integer equal to 0 (missing/malformed fails).
verdict() { # elapsed_ms exit_code allowed_codes queue_len max_stop_s
  local elapsed_ms="$1" code="$2" allowed=" $3 " qlen="$4" max_s="$5"
  if [[ "$allowed" != *" $code "* ]]; then echo FAIL; return; fi
  if ! [[ "$elapsed_ms" =~ ^[0-9]+$ ]] || [ "$elapsed_ms" -ge $((max_s * 1000)) ]; then echo FAIL; return; fi
  if ! [[ "$qlen" =~ ^[0-9]+$ ]] || [ "$qlen" -ne 0 ]; then echo FAIL; return; fi
  echo PASS
}
if [ "${1:-}" = "--verdict" ]; then
  shift
  verdict "$@"
  exit 0
fi

: "${NLW_IMAGE:?set NLW_IMAGE to the backend image under test}"
PROJECT="${DRILL_PROJECT:-nlw-sched-shutdown-drill}"
GRACE_S="${DRILL_GRACE_S:-10}"       # Linux Docker Engine default stop timeout (staging); passed explicitly
                                     # because some local engines (Docker Desktop) default to a shorter one
MAX_STOP_S="${DRILL_MAX_STOP_S:-8}"  # required upper bound for a clean exit (conservative, < GRACE_S)
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/nlw-sched-drill.XXXXXX")"
COMPOSE="docker compose -p $PROJECT --env-file $WORK/env -f $ROOT/docker-compose.prod.yml -f $ROOT/docker-compose.staging.yml"

cleanup() {
  $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

rand() { openssl rand -hex 16; }
OWNER_PW="drill_owner_$(rand)"
APP_PW="drill_app_$(rand)"
WORKER_PW="drill_worker_$(rand)"
SCHED_PW="drill_sched_$(rand)"
mkdir -p "$WORK/keys"
chmod 755 "$WORK/keys"
# Throwaway signed-context keys, written by a root, network-less container from
# the image under test so they are owned by the container user (10001) with mode
# 400 — exactly what `ctxkeys prepare` produces — on Linux and Docker Desktop alike.
docker run --rm --user 0:0 --network none -v "$WORK/keys:/k" --entrypoint python "$NLW_IMAGE" -c '
import os, secrets
for c in ("api", "worker", "scheduler"):
    path = f"/k/{c}.key"
    with open(path, "w") as f:
        f.write(secrets.token_hex(32) + "\n")
    os.chown(path, 10001, 10001)
    os.chmod(path, 0o400)
'
umask 077
cat > "$WORK/env" <<EOF
NLW_IMAGE=$NLW_IMAGE
NLW_WEB_IMAGE=${NLW_WEB_IMAGE:-unused-in-this-drill}
POSTGRES_PASSWORD=$OWNER_PW
NLW_APP_DB_PASSWORD=$APP_PW
NLW_WORKER_DB_PASSWORD=$WORKER_PW
NLW_SCHEDULER_DB_PASSWORD=$SCHED_PW
DATABASE_URL=postgresql+psycopg://nlw_app:$APP_PW@postgres:5432/nlw
DATABASE_MIGRATION_URL=postgresql+psycopg://nlw:$OWNER_PW@postgres:5432/nlw
WORKER_DATABASE_URL=postgresql+psycopg://nlw_worker:$WORKER_PW@postgres:5432/nlw
SCHEDULER_DATABASE_URL=postgresql+psycopg://nlw_scheduler:$SCHED_PW@postgres:5432/nlw
REDIS_URL=redis://redis:6379/0
PUBLIC_HOSTNAME=localhost
WORKSPACE_COOKIE_SECRET=drill-cookie-secret
NLW_CTX_KEYS_DIR=$WORK/keys
NLW_CTX_API_KEY_ID=drill-api
NLW_CTX_WORKER_KEY_ID=drill-worker
NLW_CTX_SCHEDULER_KEY_ID=drill-scheduler
EOF

echo "== Scheduler shutdown drill (image ${NLW_IMAGE}, grace ${GRACE_S}s, bound ${MAX_STOP_S}s) =="
$COMPOSE up -d postgres redis >/dev/null
for _ in $(seq 1 60); do $COMPOSE exec -T postgres pg_isready -U nlw -d nlw >/dev/null 2>&1 && break; sleep 1; done
$COMPOSE --profile migration run --rm migrate >/dev/null
for c in api worker scheduler; do
  id_var="NLW_CTX_$(echo "$c" | tr a-z A-Z)_KEY_ID"
  $COMPOSE --profile migration run --rm --no-deps -v "$WORK/keys:/run/nlw/keys:ro" \
    -e NLW_CTX_OPERATOR=shutdown-drill migrate python -m nlw.ctxkeys install \
    --class "$c" --key-id "$(grep "^$id_var=" "$WORK/env" | cut -d= -f2)" \
    --secret-file "/run/nlw/keys/$c.key" >/dev/null
done

queue_len() { $COMPOSE exec -T redis redis-cli LLEN dramatiq:default | tr -d '[:space:]'; }
cid() { $COMPOSE ps -aq scheduler; }
exit_code() { docker inspect -f '{{.State.ExitCode}}' "$(cid)"; }
wait_healthy() {
  for _ in $(seq 1 90); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$(cid)" 2>/dev/null)" = "healthy" ] && return 0
    sleep 1
  done
  echo "FAIL: scheduler never became healthy" >&2
  $COMPOSE logs --no-color --tail 40 scheduler >&2
  return 1
}
now_ms() { python3 -c 'import time; print(int(time.monotonic() * 1000))'; }

fail=0
record() { # name elapsed_ms code [allowed exit codes, default "0"]
  local secs qlen result
  secs=$(python3 -c "print(f'{$2/1000:.2f}')")
  qlen=$(queue_len 2>/dev/null || true) # captured ONCE; judged and printed from this value
  result=$(verdict "$2" "$3" "${4:-0}" "$qlen" "$MAX_STOP_S")
  [ "$result" = PASS ] || fail=1
  echo "round=$1 stop_s=$secs exit_code=$3 queue_len=${qlen:-<missing>} $result"
}

# Round 1: idle steady state (fresh DB: nothing due, nothing in flight).
$COMPOSE up -d --no-deps scheduler >/dev/null
wait_healthy
sleep 3 # well inside the scan sleep, after at least one completed tick
t0=$(now_ms); $COMPOSE stop -t "$GRACE_S" scheduler >/dev/null; t1=$(now_ms)
record idle $((t1 - t0)) "$(exit_code)"

# Round 2: stop during initialization (before the main loop starts).
$COMPOSE up -d --no-deps scheduler >/dev/null
sleep 0.3
t0=$(now_ms); $COMPOSE stop -t "$GRACE_S" scheduler >/dev/null; t1=$(now_ms)
# 0 = graceful (handler already installed); 143 = terminated by the SIGTERM that
# init (tini) forwarded before the handler existed: immediate and nothing started.
# Never 137 (SIGKILL at the grace period).
record init $((t1 - t0)) "$(exit_code)" "0 143"

# Round 3: repeated SIGTERM must be safe and still exit cleanly.
$COMPOSE up -d --no-deps scheduler >/dev/null
wait_healthy
docker kill -s TERM "$(cid)" >/dev/null
docker kill -s TERM "$(cid)" >/dev/null 2>&1 || true # may already be exiting
t0=$(now_ms)
for _ in $(seq 1 $((GRACE_S * 10))); do
  [ "$(docker inspect -f '{{.State.Running}}' "$(cid)")" = "false" ] && break
  sleep 0.1
done
t1=$(now_ms)
if [ "$(docker inspect -f '{{.State.Running}}' "$(cid)")" = "true" ]; then
  $COMPOSE stop -t "$GRACE_S" scheduler >/dev/null # do not leave it running; the round already failed
  echo "round=repeated-sigterm still running after ${GRACE_S}s FAIL"
  fail=1
else
  record repeated-sigterm $((t1 - t0)) "$(exit_code)"
fi

echo "-- scheduler log (shutdown lines only) --"
$COMPOSE logs --no-color scheduler 2>/dev/null | grep -E 'scheduler\.(start|shutdown|stop)' | sed -E 's/^[^|]*\| //' | tail -10 || true
[ "$fail" = 0 ] && echo "scheduler shutdown drill: PASS" || { echo "scheduler shutdown drill: FAIL"; exit 1; }
