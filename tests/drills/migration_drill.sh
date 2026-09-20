#!/usr/bin/env bash
# M11 migration drill. Invariant: an incompatible/partially-migrated DB must
# NEVER be reported ready. No automatic DB downgrade on image rollback.
set -euo pipefail
COMPOSE="${COMPOSE:-docker compose -f docker-compose.prod.yml -f docker-compose.e2e.yml -f docker-compose.staging.yml}"
API="${API:-http://127.0.0.1:8080}"
ready_code() { curl -s -o /dev/null -w "%{http_code}" "$API/health/ready"; }

echo "== Migration drill =="

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
echo "MIGRATION DRILL COMPLETE (incompatible schema never reported ready)"
