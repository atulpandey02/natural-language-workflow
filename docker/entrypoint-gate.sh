#!/usr/bin/env sh
# Restore-mode runtime-start gate wrapper (M11.5 P2 addendum C).
#
# Wrap api/worker/scheduler startup with this ONLY when bringing a recovered stack
# up in restore mode. When NLW_RESTORE_MODE=1 it verifies the restore-ready gate
# (bound to this restore generation + database cluster) and refuses to start
# (non-zero) on a missing/stale/cross-DB/tampered gate. When NLW_RESTORE_MODE is
# unset (every normal deployment) it does nothing and execs the real command, so
# normal deploys never require a DR gate.
#
# Use via an override that sets, for api/worker/scheduler:
#   entrypoint: ["/app/docker/entrypoint-gate.sh"]
#   environment: { NLW_RESTORE_MODE: "1", NLW_RESTORE_GATE_FILE: /var/lib/nlw/restore-ready.json,
#                  NLW_RESTORE_DATABASE_URL: <owner url>, NLW_RESTORE_COMPOSE_PROJECT: <project> }
#   volumes: [ "restore_gate:/var/lib/nlw" ]
# followed by the service's normal command.
set -eu

if [ "${NLW_RESTORE_MODE:-}" = "1" ]; then
  echo "[entrypoint-gate] restore mode: verifying restore-ready gate" >&2
  python -m nlw.backup gate-check
  echo "[entrypoint-gate] gate ok; starting service" >&2
fi

exec "$@"
