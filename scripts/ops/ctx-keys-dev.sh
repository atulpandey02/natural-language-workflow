#!/usr/bin/env bash
# Provision TEST/DEV signed-context keys for the local Compose stack (M11.5 P3B).
#
# Generates one random 32-byte key per runtime class (api / worker / scheduler)
# into docker/ctx-keys/<class>.key (git-ignored, mode 0600, owned so the container
# user uid 10001 can read it), then installs them into the running Compose
# Postgres via the one-shot installer (`python -m nlw.ctxkeys install`), using the
# OWNER credential that only the dev/migration path holds. Idempotent per key id.
#
# NEVER use this for production: production keys are generated and placed by the
# operator (see docs/runbooks/signed-context-keys.md) and are never committed.
#
# Usage:  scripts/ops/ctx-keys-dev.sh [compose args...]
#   e.g.  scripts/ops/ctx-keys-dev.sh -f docker-compose.yml -f docker-compose.e2e.yml
set -euo pipefail
cd "$(dirname "$0")/../.."

COMPOSE_ARGS=("$@")
[ ${#COMPOSE_ARGS[@]} -eq 0 ] && COMPOSE_ARGS=(-f docker-compose.yml)
KEYS_DIR="docker/ctx-keys"
mkdir -p "$KEYS_DIR"
chmod 700 "$KEYS_DIR"

for cls in api worker scheduler; do
  f="$KEYS_DIR/$cls.key"
  if [ ! -s "$f" ]; then
    umask 077
    openssl rand -hex 32 > "$f"
    chmod 600 "$f"
    echo "generated $f"
  fi
done

# Key ids default to the Compose defaults (dev-api / dev-worker / dev-scheduler).
API_ID="${NLW_CTX_API_KEY_ID:-dev-api}"
WORKER_ID="${NLW_CTX_WORKER_KEY_ID:-dev-worker}"
SCHED_ID="${NLW_CTX_SCHEDULER_KEY_ID:-dev-scheduler}"

# Install via the api image (it has the package + owner URL in dev app-env). The
# key files are bind-mounted read-only into a throwaway container; nothing is
# passed on argv or in env values. --insecure-permissions tolerates host uid
# differences on the bind mount (the CONTENT is still only readable via the file).
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
