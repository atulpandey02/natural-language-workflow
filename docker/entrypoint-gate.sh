#!/usr/bin/env sh
# Restore-mode file-gate wrapper — DEFENSE IN DEPTH (M11.5 P2 addendum C).
#
# NOTE: the AUTHORITATIVE runtime-start gate is the database recovery lock
# (dr_restore_events), which api/worker/scheduler enforce unconditionally at boot
# via nlw.backup.recovery_lock — NOT this optional wrapper. This wrapper only adds
# the file-gate binding check when NLW_RESTORE_MODE=1; omitting it does NOT bypass
# the DB lock. When NLW_RESTORE_MODE is unset (every normal deployment) it does
# nothing and execs the real command.
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
