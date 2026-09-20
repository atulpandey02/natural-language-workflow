#!/usr/bin/env bash
# M11 schema-incompatibility / readiness drill (NOT a live process-kill migration
# interruption — that is a real-VPS checklist item). Invariant: an incompatible
# schema must NEVER be reported ready. No automatic DB downgrade on image rollback.
set -euo pipefail
COMPOSE="${COMPOSE:-docker compose -f docker-compose.prod.yml -f docker-compose.e2e.yml -f docker-compose.staging.yml}"
API="${API:-http://127.0.0.1:8000}"  # API readiness endpoint (loopback)
# Bounded probe (never hangs); 000 sentinel on transport timeout/failure.
ready_code() {
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 --max-time 5 "$API/health/ready" 2>/dev/null) || code="000"
  echo "${code:-000}"
}

echo "== Schema-incompatibility / readiness drill =="

# 1) Fresh DB -> head (idempotent re-run).
$COMPOSE run --rm api alembic upgrade head
echo "fresh upgrade head: OK"

# 2) Incompatible schema must NOT be reported ready: stamp a bogus revision.
$COMPOSE exec -T postgres sh -lc "PGPASSWORD=\$POSTGRES_PASSWORD psql -U nlw -d nlw -c \"UPDATE alembic_version SET version_num='not_the_head'\""
code=$(ready_code)
echo "readiness with mismatched schema: $code (expect 503)"
[ "$code" = "503" ] || { echo "FAIL: incompatible schema reported ready"; exit 1; }

# 3) Repair forward and confirm readiness returns.
$COMPOSE exec -T postgres sh -lc "PGPASSWORD=\$POSTGRES_PASSWORD psql -U nlw -d nlw -c \"UPDATE alembic_version SET version_num=(SELECT version_num FROM alembic_version LIMIT 0)\"" 2>/dev/null || true
$COMPOSE run --rm api alembic stamp head
for i in $(seq 1 30); do [ "$(ready_code)" = "200" ] && break; sleep 2; done
[ "$(ready_code)" = "200" ] || { echo "FAIL: readiness did not recover"; exit 1; }
echo "SCHEMA/READINESS DRILL COMPLETE (incompatible schema never reported ready)"
