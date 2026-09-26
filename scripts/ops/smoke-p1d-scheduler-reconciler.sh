#!/usr/bin/env bash
# P1D containerized scheduler/reconciler smoke.
#
# Boots the P1D-built stack (Postgres + Redis + the real scheduler service),
# applies migrations (incl. 0013), and drives the packaged scheduler/reconciler
# code against the containerized Postgres to prove: occurrence idempotency (one
# run per occurrence, no duplicate on repeat), reconciler eligibility-before-limit,
# per-tenant fairness, progress-aware recovery, terminal-UNKNOWN exclusion, and
# approval-to-step binding.
#
# Usage:  scripts/ops/smoke-p1d-scheduler-reconciler.sh
# Requires: docker compose, uv. Uses a throwaway pgdata volume.
set -euo pipefail

cd "$(dirname "$0")/../.."
# SAFETY: this script runs `docker compose down -v` (volume deletion) against the
# project derived from the checkout directory. On an ops host (/opt/nlw/app ->
# project "app") that would DELETE the live database volume. Refuse there.
case "$(pwd -P)" in /opt/*|/srv/*) echo "refusing: smoke scripts never run on an ops host ($(pwd -P))" >&2; exit 2;; esac
[ ! -f .env.prod ] || { echo "refusing: .env.prod present — this looks like a deployed checkout" >&2; exit 2; }

OWNER_MIGRATION_URL="postgresql+psycopg://nlw:nlw@postgres:5432/nlw"
export OWNER_LIBPQ="postgresql://nlw:nlw@localhost:5433/nlw"
export SCHED_SA="postgresql+psycopg://nlw_scheduler:nlw_scheduler@localhost:5433/nlw"

cleanup() {
  echo "--- tearing down ---"
  docker compose -f docker-compose.yml down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "--- building api + scheduler (P1D source) ---"
docker compose -f docker-compose.yml build api scheduler

echo "--- starting postgres + redis (fresh volume) ---"
docker compose -f docker-compose.yml down -v --remove-orphans >/dev/null 2>&1 || true
docker compose -f docker-compose.yml up -d postgres redis

echo "--- waiting for postgres health ---"
for _ in $(seq 1 30); do
  if docker compose -f docker-compose.yml exec -T postgres pg_isready -U nlw -d nlw >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo "--- applying migrations (owner) ---"
docker compose -f docker-compose.yml run --rm \
  -e DATABASE_MIGRATION_URL="${OWNER_MIGRATION_URL}" \
  api alembic upgrade head

echo "--- starting the real scheduler service (proves it boots on P1D code) ---"
docker compose -f docker-compose.yml up -d scheduler
sleep 5
if [ "$(docker inspect -f '{{.State.Running}}' "$(docker compose -f docker-compose.yml ps -q scheduler)")" != "true" ]; then
  echo "scheduler container is not running"; docker compose -f docker-compose.yml logs scheduler | tail -30; exit 1
fi
echo "  [ok] scheduler service is running"

echo "--- driving the scheduler/reconciler smoke ---"
uv run python scripts/ops/smoke_p1d_scheduler_reconciler.py

echo "ALL SMOKE CHECKS PASSED"
