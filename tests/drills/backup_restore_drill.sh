#!/usr/bin/env bash
# M11 backup/restore drill (executed, not just documented). Uses the M9 scripts.
# Measures RPO/RTO. Restores NLW application Postgres state ONLY — Supabase Auth
# identities are a SEPARATE DR responsibility (see docs/staging/*).
set -euo pipefail
COMPOSE="${COMPOSE:-docker compose -f docker-compose.prod.yml -f docker-compose.e2e.yml -f docker-compose.staging.yml}"

echo "== Backup/restore drill =="
start=$(date +%s)

# 1) Logical backup (custom format) inside the postgres container.
$COMPOSE exec -T postgres sh -lc 'PGPASSWORD=$POSTGRES_PASSWORD pg_dump -U nlw -d nlw -F c -f /tmp/nlw.dump'
echo "backup created (RPO measured from last backup; here ~0)."

# 2) Destroy + recreate the database (roles come from bootstrap/IaC, not the dump).
$COMPOSE exec -T postgres sh -lc 'PGPASSWORD=$POSTGRES_PASSWORD dropdb -U nlw --force nlw && createdb -U nlw nlw'

# 3) Restore.
$COMPOSE exec -T postgres sh -lc 'PGPASSWORD=$POSTGRES_PASSWORD pg_restore -U nlw -d nlw --no-owner /tmp/nlw.dump'

# 4) Verify schema head + core rows.
head=$($COMPOSE exec -T postgres sh -lc "PGPASSWORD=\$POSTGRES_PASSWORD psql -U nlw -d nlw -tAc 'SELECT version_num FROM alembic_version'")
echo "restored alembic head: $head"
for t in users workspaces workflows workflow_runs schedules; do
  n=$($COMPOSE exec -T postgres sh -lc "PGPASSWORD=\$POSTGRES_PASSWORD psql -U nlw -d nlw -tAc 'SELECT count(*) FROM $t'")
  echo "  $t rows: $n"
done

rto=$(( $(date +%s) - start ))
echo "RTO (backup->restore->verify): ${rto}s"
echo "BACKUP/RESTORE DRILL COMPLETE"
