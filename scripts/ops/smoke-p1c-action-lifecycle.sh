#!/usr/bin/env bash
# P1C containerized action-lifecycle smoke.
#
# Boots the P1C-built stack (Postgres + Redis + the real Dramatiq worker), applies
# migrations (incl. 0012), verifies the live UNKNOWN CHECK constraint, and drives
# the ambiguous/expired-final action path end-to-end through the real worker +
# broker, asserting a TERMINAL UNKNOWN with no resend.
#
# The happy path (approve -> SUCCESS -> COMPLETED) is validated in the integration
# suite (a MockTransport injects the destination); it cannot run against an
# internal compose sink because the SSRF guard (ADR-014) correctly refuses to
# deliver to a private IP.
#
# Usage:  scripts/ops/smoke-p1c-action-lifecycle.sh
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
export REDIS_URL="redis://localhost:6379/0"

cleanup() {
  echo "--- tearing down ---"
  docker compose -f docker-compose.yml down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "--- building api + worker (P1C source) ---"
docker compose -f docker-compose.yml build api worker

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

echo "--- starting the real worker ---"
docker compose -f docker-compose.yml up -d worker
sleep 5

echo "--- driving the lifecycle smoke ---"
uv run python scripts/ops/smoke_p1c_action_lifecycle.py

echo "ALL SMOKE CHECKS PASSED"
