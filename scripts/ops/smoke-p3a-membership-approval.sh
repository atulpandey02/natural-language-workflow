#!/usr/bin/env bash
# P3A containerized membership + approval separation-of-duties smoke.
#
# Boots the P3A-built stack (Postgres + Redis + the REAL api + Dramatiq worker),
# applies migrations (incl. 0015), and drives the P3A security invariants end to
# end against the running system:
#
#   1  live P3A schema (manage_membership + 3 immutability triggers; audit
#      append-only for runtime roles)
#   2  invitation via the API stores ONLY the sha256 token hash (never the raw)
#   3  self-approval denied via the API (403) AND by direct SQL (RLS 42501)
#   4  an eligible admin approves; the REAL worker advances the run exactly once
#   5  append-only audit records exactly one event per committed transition
#      (idempotent re-decide adds none)
#   6  provenance rewrite denied for every runtime role (worker run-initiator,
#      app requester)
#   7  a terminal approval decision is immutable (no APPROVED->REJECTED flip)
#   8  final-owner race preserves >= 1 owner (function-only mutation path)
#   9  the audit trail cannot be rewritten/erased by nlw_app
#  10  the P2 disaster-recovery validation is still green on the P3A schema
#
# P3B (signed database context, migration 0016) — with test-only key files:
#  11  unsigned direct GUC forgery sees/modifies nothing (in step 5)
#  12  the real scheduler creates a due run under scheduler_reconcile context and
#      the real worker completes it under worker_execution context
#  13  the API key cannot be used under the worker/scheduler DB roles
#  14  worker/scheduler keys cannot authorize human administration
#  15  rotate the API key with an overlap, move the API onto it, revoke the old key
#  16  old-key contexts fail after revocation; the API works on the new key
#  17  real quiescence records a locked generation; the P2 runtime recovery lock
#      still blocks it (startup-check exit 6, API readiness/business 503)
#
# Usage:  scripts/ops/smoke-p3a-membership-approval.sh
# Requires: docker compose, uv. Uses a throwaway pgdata volume.
set -euo pipefail

cd "$(dirname "$0")/../.."

OWNER_MIGRATION_URL="postgresql+psycopg://nlw:nlw@postgres:5432/nlw"
export OWNER_LIBPQ="postgresql://nlw:nlw@localhost:5433/nlw"
export APP_LIBPQ="postgresql://nlw_app:nlw_app@localhost:5433/nlw"
export WORKER_LIBPQ="postgresql://nlw_worker:nlw_worker@localhost:5433/nlw"
export SCHED_LIBPQ="postgresql://nlw_scheduler:nlw_scheduler@localhost:5433/nlw"
export REDIS_URL="redis://localhost:6379/0"
export API_URL="http://localhost:8000"

# Dev HS256 auth for the API (never used in production, which verifies via JWKS).
export SMOKE_JWT_SECRET="dev-secret-for-tests-32bytes-min-length"
export SMOKE_ISSUER="https://proj.supabase.co/auth/v1"
# Exported (not inline) so the Python driver's own `docker compose up -d api`
# during the key-rotation step (15) renders the api service identically.
export SUPABASE_URL=https://proj.supabase.co
export SUPABASE_JWT_SECRET="${SMOKE_JWT_SECRET}"

cleanup() {
  echo "--- tearing down ---"
  docker compose -f docker-compose.yml down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf docker/ctx-keys  # throwaway smoke keys only
}
trap cleanup EXIT

echo "--- building api + worker + scheduler (branch source) ---"
docker compose -f docker-compose.yml build api worker scheduler

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

echo "--- provisioning TEST signed-context keys (P3B) before any runtime starts ---"
# Fresh throwaway keys for this run; installed with the owner credential. The
# host-side driver signs its direct-SQL probes with the same files.
rm -rf docker/ctx-keys
scripts/ops/ctx-keys-dev.sh -f docker-compose.yml
export NLW_CTX_KEYS_DIR="docker/ctx-keys"

echo "--- starting the real api + worker + scheduler (dev HS256 auth) ---"
# SUPABASE_URL + SUPABASE_JWT_SECRET (exported above) make the api verify HS256
# dev tokens. Each runtime signs with ITS mounted key file only.
docker compose -f docker-compose.yml up -d api worker scheduler
sleep 6

echo "--- waiting for the api to answer ---"
for _ in $(seq 1 30); do
  if curl -fsS "${API_URL}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo "--- driving the P3A smoke ---"
uv run python scripts/ops/smoke_p3a_membership_approval.py

echo "ALL SMOKE CHECKS PASSED"
