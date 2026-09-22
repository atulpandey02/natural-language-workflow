#!/usr/bin/env bash
# Provision TEST/DEV signed-context keys for the local Compose stack (M11.5 P3B).
#
# Generates one random 32-byte key per runtime class (api / worker / scheduler)
# into docker/ctx-keys/<class>.key (git-ignored), then installs them into the
# running Compose Postgres via the one-shot installer (`python -m nlw.ctxkeys
# install`), using the OWNER credential that only the dev/migration path holds.
# Idempotent per key id.
#
# ORDER MATTERS on Linux hosts: the Compose services bind-mount
# ./docker/ctx-keys/<class>.key, and Docker auto-creates a MISSING bind-mount
# source as a root-owned DIRECTORY. So generate the files BEFORE the first
# `docker compose run api ...` (e.g. the migration), then install AFTER the
# migration created the registry:
#
#   scripts/ops/ctx-keys-dev.sh --generate-only [compose args...]   # before migrate
#   docker compose run --rm api alembic upgrade head
#   scripts/ops/ctx-keys-dev.sh [compose args...]                   # install
#
# Dev/test key files are world-readable (0644): the container user (uid 10001)
# must read them through the bind mount and the local runtime does not enforce
# strict key-file permissions (staging/production do — and never use this script).
#
# NEVER use this for production: production keys are generated and placed by the
# operator (see docs/runbooks/signed-context-keys.md) and are never committed.
set -euo pipefail
cd "$(dirname "$0")/../.."

GENERATE_ONLY=0
if [ "${1:-}" = "--generate-only" ]; then GENERATE_ONLY=1; shift; fi
COMPOSE_ARGS=("$@")
[ ${#COMPOSE_ARGS[@]} -eq 0 ] && COMPOSE_ARGS=(-f docker-compose.yml)
KEYS_DIR="docker/ctx-keys"

if [ -e "$KEYS_DIR" ] && [ ! -w "$KEYS_DIR" ]; then
  echo "ERROR: $KEYS_DIR exists but is not writable (root-owned, auto-created by a" >&2
  echo "       bind mount before the keys existed). Remove it (sudo rm -rf $KEYS_DIR)" >&2
  echo "       and run '$0 --generate-only' BEFORE any 'docker compose run api ...'." >&2
  exit 2
fi
mkdir -p "$KEYS_DIR"

for cls in api worker scheduler; do
  f="$KEYS_DIR/$cls.key"
  if [ -d "$f" ]; then
    echo "ERROR: $f is a directory (auto-created by a bind mount before the key existed)." >&2
    echo "       Remove it and generate keys BEFORE starting/running any Compose service." >&2
    exit 2
  fi
  if [ ! -s "$f" ]; then
    (umask 022; openssl rand -hex 32 > "$f")
    chmod 644 "$f"  # dev/test only: readable by the container user (uid 10001)
    echo "generated $f"
  fi
done
[ "$GENERATE_ONLY" -eq 1 ] && { echo "ctx keys generated (not installed)"; exit 0; }

# Key ids default to the Compose defaults (dev-api / dev-worker / dev-scheduler).
API_ID="${NLW_CTX_API_KEY_ID:-dev-api}"
WORKER_ID="${NLW_CTX_WORKER_KEY_ID:-dev-worker}"
SCHED_ID="${NLW_CTX_SCHEDULER_KEY_ID:-dev-scheduler}"

# Install via the api image (it has the package + owner URL in dev app-env). The
# key files are bind-mounted read-only into a throwaway container; nothing is
# passed on argv or in env values. --insecure-permissions tolerates the 0644 dev
# files (the CONTENT is still only readable via the file).
install() {
  docker compose "${COMPOSE_ARGS[@]}" run --rm --no-deps \
    -v "$(pwd)/$KEYS_DIR/$1.key:/run/nlw/keys/$1.key:ro" \
    -e NLW_CTX_OPERATOR="ctx-keys-dev" \
    api python -m nlw.ctxkeys install --class "$1" --key-id "$2" \
      --secret-file "/run/nlw/keys/$1.key" --insecure-permissions
}
install api "$API_ID"
install worker "$WORKER_ID"
install scheduler "$SCHED_ID"
echo "ctx keys installed: $API_ID / $WORKER_ID / $SCHED_ID"
