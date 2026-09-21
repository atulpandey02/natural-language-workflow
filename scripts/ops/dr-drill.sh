#!/usr/bin/env bash
# Disposable disaster-recovery drill (M11.5 P2, ADR-022).
#
# Fully local + disposable: builds the app + backup images, stands up MinIO (an
# S3-compatible fixture — NOT a real provider), a SOURCE Postgres, and a fresh
# DEST Postgres, then exercises the real encrypted backup -> destroy source ->
# restore -> quiesce -> validate flow and measures backup/restore/RTO/RPO.
#
# EVIDENCE LABEL: this proves the mechanism against MinIO/local Docker. It does
# NOT prove a real off-host provider or a real VPS restore (those are operator
# gates in docs/runbooks/dr-real-vps-checklist.md).
#
# Every destructive action is scoped to a UNIQUELY named project + its own
# volumes/network; no workspace root, home dir, unresolved var, or glob is ever a
# destructive target.
set -euo pipefail

cd "$(dirname "$0")/../.."
REPO="$(pwd)"

SUFFIX="$(date +%Y%m%d%H%M%S)-$$"
PROJ="nlwdrill-${SUFFIX}"
NET="${PROJ}-net"
BUCKET="nlwdrill"
RESTIC_REPOSITORY="s3:http://${PROJ}-minio:9000/${BUCKET}"
S3_KEY="drillkey"
S3_SECRET="drillsecret123"
REPO_PW="drill-repo-password"
APP_IMG="nlw:drill"
BAK_IMG="nlw-backup:drill"

# All resource names begin with ${PROJ}- so cleanup can never match anything else.
cleanup() {
  echo "--- cleanup (${PROJ}) ---"
  docker rm -f "${PROJ}-minio" "${PROJ}-srcdb" "${PROJ}-destdb" "${PROJ}-destdb2" \
    "${PROJ}-redis" >/dev/null 2>&1 || true
  docker volume rm "${PROJ}-srcdata" "${PROJ}-destdata" "${PROJ}-destdata2" \
    "${PROJ}-miniodata" "${PROJ}-gate" >/dev/null 2>&1 || true
  docker network rm "${NET}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

_run_owner_db() {  # name, volume -> a fresh postgres:16 with bootstrapped roles
  local name="$1" vol="$2"
  docker run -d --name "${name}" --network "${NET}" \
    -e POSTGRES_USER=nlw -e POSTGRES_PASSWORD=nlw -e POSTGRES_DB=nlw \
    -e NLW_APP_DB_PASSWORD=nlw_app -e NLW_WORKER_DB_PASSWORD=nlw_worker \
    -e NLW_SCHEDULER_DB_PASSWORD=nlw_scheduler \
    -v "${vol}:/var/lib/postgresql/data" \
    -v "${REPO}/docker/postgres/initdb:/docker-entrypoint-initdb.d:ro" \
    postgres:16 >/dev/null
}

_wait_db() {  # name
  for _ in $(seq 1 30); do
    if docker exec "$1" pg_isready -U nlw -d nlw >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  echo "db $1 did not become ready" >&2; docker logs "$1" | tail -20 >&2; exit 1
}

_restic_env=(-e "RESTIC_REPOSITORY=${RESTIC_REPOSITORY}" -e "RESTIC_PASSWORD=${REPO_PW}" \
  -e "AWS_ACCESS_KEY_ID=${S3_KEY}" -e "AWS_SECRET_ACCESS_KEY=${S3_SECRET}")

echo "=== building images ==="
docker build -t "${APP_IMG}" "${REPO}" >/dev/null
docker build -t "${BAK_IMG}" -f "${REPO}/docker/backup/Dockerfile" --build-arg "NLW_IMAGE=${APP_IMG}" "${REPO}" >/dev/null

echo "=== network + MinIO (S3-compatible fixture) ==="
docker network create "${NET}" >/dev/null
docker run -d --name "${PROJ}-minio" --network "${NET}" \
  -e "MINIO_ROOT_USER=${S3_KEY}" -e "MINIO_ROOT_PASSWORD=${S3_SECRET}" \
  -v "${PROJ}-miniodata:/data" minio/minio server /data >/dev/null
sleep 5
docker run --rm --network "${NET}" --entrypoint sh minio/mc -c \
  "mc alias set d http://${PROJ}-minio:9000 ${S3_KEY} ${S3_SECRET} && mc mb -p d/${BUCKET}" >/dev/null
echo "  [ok] bucket ${BUCKET} created in the off-host fixture"

echo "=== SOURCE db: migrate + seed 2 tenants ==="
_run_owner_db "${PROJ}-srcdb" "${PROJ}-srcdata"; _wait_db "${PROJ}-srcdb"
docker run --rm --network "${NET}" \
  -e "DATABASE_MIGRATION_URL=postgresql+psycopg://nlw:nlw@${PROJ}-srcdb:5432/nlw" \
  "${APP_IMG}" alembic upgrade head >/dev/null
docker run --rm --network "${NET}" -v "${REPO}/scripts:/scripts:ro" "${APP_IMG}" \
  python /scripts/ops/dr_drill_seed.py seed --url "postgresql://nlw:nlw@${PROJ}-srcdb:5432/nlw"

echo "=== (F1) ordinary DB (no restore event) permits normal startup ==="
# The migrated+seeded SOURCE has no dr_restore_events row -> runtime startup allowed.
docker run --rm --network "${NET}" -e APP_ENV=local \
  -e "NLW_RESTORE_DATABASE_URL=postgresql://nlw_app:nlw_app@${PROJ}-srcdb:5432/nlw" \
  "${BAK_IMG}" startup-check \
  && echo "  [ok] startup-check permits a never-restored DB (as nlw_app)"

echo "=== BACKUP (encrypted, off-host to MinIO) ==="
t0=$(date +%s)
docker run --rm --network "${NET}" "${_restic_env[@]}" -e APP_ENV=local \
  -e "NLW_BACKUP_DATABASE_URL=postgresql://nlw:nlw@${PROJ}-srcdb:5432/nlw" \
  -e "NLW_BACKUP_METRICS_FILE=/tmp/m.prom" "${BAK_IMG}" backup
BACKUP_S=$(( $(date +%s) - t0 ))
echo "  backup_duration_seconds=${BACKUP_S}"

echo "=== prove the encrypted object exists off-host ==="
docker run --rm --network "${NET}" "${_restic_env[@]}" --entrypoint restic "${BAK_IMG}" snapshots \
  | tee /dev/stderr | grep -q . && echo "  [ok] snapshot present in the MinIO repo"
docker run --rm --network "${NET}" --entrypoint sh minio/mc -c \
  "mc alias set d http://${PROJ}-minio:9000 ${S3_KEY} ${S3_SECRET} && mc ls -r d/${BUCKET} | head -1" >/dev/null \
  && echo "  [ok] restic objects present in bucket ${BUCKET}"

echo "=== DESTROY the disposable source (validated names only) ==="
docker rm -f "${PROJ}-srcdb" >/dev/null
docker volume rm "${PROJ}-srcdata" >/dev/null
echo "  [ok] source db + volume destroyed"

echo "=== DEST db: fresh empty target (worker/scheduler stay DOWN) ==="
_run_owner_db "${PROJ}-destdb" "${PROJ}-destdata"; _wait_db "${PROJ}-destdb"
docker run -d --name "${PROJ}-redis" --network "${NET}" redis:7 >/dev/null
DEST_URL="postgresql://nlw:nlw@${PROJ}-destdb:5432/nlw"
GATE_VOL="${PROJ}-gate"
_gate_env=(-e "NLW_RESTORE_DATABASE_URL=${DEST_URL}" \
  -e "NLW_RESTORE_GATE_FILE=/var/lib/nlw/restore-ready.json" \
  -e "NLW_RESTORE_COMPOSE_PROJECT=${PROJ}" -v "${GATE_VOL}:/var/lib/nlw")

echo "=== (B) runtime-state guard, host-scoped to this drill's containers ==="
# The drill uses `docker run` (not compose); demonstrate the SCOPED runtime check on
# the host by name prefix. In production the in-process compose probe does this.
running_rt=$(docker ps --format '{{.Names}}' \
  | grep -E "^${PROJ}-(api|worker|scheduler|web)$" || true)
[ -z "${running_rt}" ] && echo "  [ok] no runtime service running for ${PROJ} (scoped check)"

echo "=== (C) startup gate BLOCKS before a valid restore gate ==="
# api/worker/scheduler startup must fail before quiescence+validation produce a gate.
set +e
docker run --rm --network "${NET}" "${_gate_env[@]}" -e APP_ENV=local \
  "${BAK_IMG}" gate-check
gc_rc=$?
set -e
[ "${gc_rc}" -eq 4 ] && echo "  [ok] gate-check refused startup (exit 4) with no valid gate" \
  || { echo "FAIL: gate-check should have exited 4, got ${gc_rc}" >&2; exit 1; }

echo "=== RESTORE (guarded) + quiesce + validate + gate ==="
t0=$(date +%s)
docker run --rm --network "${NET}" "${_restic_env[@]}" "${_gate_env[@]}" -e APP_ENV=local \
  -e "NLW_RESTORE_TARGET_ID=${PROJ}" -e "NLW_RESTORE_CONFIRM=${PROJ}" \
  -e "NLW_RESTORE_RUNTIME_GUARD=off" \
  -e "NLW_RESTORE_SNAPSHOT=latest" -e "REDIS_URL=redis://${PROJ}-redis:6379/0" \
  "${BAK_IMG}" restore
RESTORE_S=$(( $(date +%s) - t0 ))
echo "  restore_duration_seconds=${RESTORE_S} (includes decrypt + pg_restore + quiesce + validate + gate)"

echo "=== post-restore invariant assertions (no replay) ==="
docker run --rm --network "${NET}" -v "${REPO}/scripts:/scripts:ro" "${APP_IMG}" \
  python /scripts/ops/dr_drill_seed.py verify --url "${DEST_URL}"

APP_URL="postgresql://nlw_app:nlw_app@${PROJ}-destdb:5432/nlw"
_dest_psql() { docker exec "${PROJ}-destdb" psql -U nlw -d nlw -tAc "$1" | tr -d '[:space:]'; }
_startup_check() {  # url -> expected_rc ; returns 0 on match
  set +e
  docker run --rm --network "${NET}" -e APP_ENV=local \
    -e "NLW_RESTORE_DATABASE_URL=$1" "${BAK_IMG}" startup-check
  local rc=$?; set -e
  [ "${rc}" -eq "$2" ] || { echo "FAIL: startup-check rc=${rc} expected $2" >&2; exit 1; }
}

echo "=== (F3/F4/F6) DB lock BLOCKS runtime startup even though the file gate passes ==="
# The file gate is valid now, but the DB generation is validated-but-NOT-enabled.
docker run --rm --network "${NET}" "${_gate_env[@]}" -e APP_ENV=local "${BAK_IMG}" gate-check \
  && echo "  [ok] file gate passes (defense in depth) ..."
_startup_check "${APP_URL}" 6
echo "  [ok] ... but the AUTHORITATIVE DB lock blocks startup-check (exit 6), no NLW_RESTORE_MODE set"
# A real service (scheduler) must also abort at boot.
set +e
docker run --rm --network "${NET}" -e APP_ENV=local \
  -e "DATABASE_URL=postgresql+psycopg://nlw_scheduler:nlw_scheduler@${PROJ}-destdb:5432/nlw" \
  -e "REDIS_URL=redis://${PROJ}-redis:6379/0" "${APP_IMG}" \
  sh -c 'timeout 25 python -m nlw.scheduler'
sched_rc=$?; set -e
[ "${sched_rc}" -ne 0 ] && echo "  [ok] real scheduler aborted at boot (rc=${sched_rc})" \
  || { echo "FAIL: scheduler should have refused to start" >&2; exit 1; }

echo "=== (F7) operator ENABLE the exact generation (owner credential) ==="
EVENT_ID=$(_dest_psql "SELECT id FROM dr_restore_events ORDER BY restored_at DESC LIMIT 1")
docker run --rm --network "${NET}" -e APP_ENV=local \
  -e "NLW_RESTORE_DATABASE_URL=${DEST_URL}" -e "NLW_RESTORE_EVENT_ID=${EVENT_ID}" \
  -e "NLW_RESTORE_COMPOSE_PROJECT=${PROJ}" -e "NLW_RESTORE_OPERATOR=drill" \
  "${BAK_IMG}" enable-runtime \
  && echo "  [ok] generation ${EVENT_ID} enabled"

echo "=== (F8) runtime startup now permitted ==="
_startup_check "${APP_URL}" 0
echo "  [ok] startup-check permits startup after explicit enable"

echo "=== (F9/F10) start runtime: a BRAND-NEW post-restore run executes to COMPLETED ==="
docker run --rm --network "${NET}" -v "${REPO}/scripts:/scripts:ro" "${APP_IMG}" \
  python /scripts/ops/dr_drill_seed.py newrun --url "${DEST_URL}"

echo "=== (F11/F12) a LATER restore generation re-locks runtime; old enable cannot authorize it ==="
# Insert new non-terminal work + quiesce -> a new locked generation.
TID=$(_dest_psql "SELECT tenant_id FROM workflows LIMIT 1")
WFID=$(_dest_psql "SELECT id FROM workflows WHERE tenant_id='${TID}' LIMIT 1")
VERID=$(_dest_psql "SELECT id FROM workflow_versions WHERE workflow_id='${WFID}' LIMIT 1")
_dest_psql "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status) VALUES (gen_random_uuid(), '${TID}', '${WFID}', '${VERID}', 'RUNNING')" >/dev/null
docker run --rm --network "${NET}" -e APP_ENV=local \
  -e "NLW_RESTORE_DATABASE_URL=${DEST_URL}" "${BAK_IMG}" quiesce >/dev/null
_startup_check "${APP_URL}" 6
echo "  [ok] later generation re-locks startup (exit 6)"
set +e
docker run --rm --network "${NET}" -e APP_ENV=local \
  -e "NLW_RESTORE_DATABASE_URL=${DEST_URL}" -e "NLW_RESTORE_EVENT_ID=${EVENT_ID}" \
  -e "NLW_RESTORE_COMPOSE_PROJECT=${PROJ}" "${BAK_IMG}" enable-runtime
old_enable_rc=$?; set -e
[ "${old_enable_rc}" -eq 5 ] && echo "  [ok] stale enablement rejected (exit 5)" \
  || { echo "FAIL: old enable should have exited 5, got ${old_enable_rc}" >&2; exit 1; }

echo "=== (C/E) file gate CANNOT be reused for a second empty destination ==="
_run_owner_db "${PROJ}-destdb2" "${PROJ}-destdata2"; _wait_db "${PROJ}-destdb2"
set +e
docker run --rm --network "${NET}" -v "${GATE_VOL}:/var/lib/nlw" -e APP_ENV=local \
  -e "NLW_RESTORE_DATABASE_URL=postgresql://nlw:nlw@${PROJ}-destdb2:5432/nlw" \
  -e "NLW_RESTORE_GATE_FILE=/var/lib/nlw/restore-ready.json" \
  -e "NLW_RESTORE_COMPOSE_PROJECT=${PROJ}" \
  "${BAK_IMG}" gate-check
reuse_rc=$?
set -e
[ "${reuse_rc}" -eq 4 ] && echo "  [ok] gate rejected on a different destination (exit 4)" \
  || { echo "FAIL: reused gate should have exited 4, got ${reuse_rc}" >&2; exit 1; }

echo ""
echo "=== DR DRILL RESULT (MinIO / local Docker — NOT a real provider) ==="
echo "  backup_duration_seconds   = ${BACKUP_S}"
echo "  restore_duration_seconds  = ${RESTORE_S}  (observed local RTO component)"
echo "  observed_snapshot_age     = ~0s (backup taken immediately before restore; RPO in prod = backup interval)"
echo "  authoritative DB lock     = blocks api/worker/scheduler until explicit enable (no env flag)"
echo "  file gate                 = defense in depth; cannot unlock the DB lock; not reusable"
echo "  new post-restore run      = executed to COMPLETED; no restored work replayed"
echo "  later generation          = re-locks runtime; stale enablement rejected"
echo "ALL DR DRILL CHECKS PASSED"
