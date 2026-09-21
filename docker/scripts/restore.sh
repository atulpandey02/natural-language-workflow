#!/usr/bin/env bash
# DEPRECATED (M11.5 P2, ADR-022). Superseded by the guarded restore
# `python -m nlw.backup restore`, run via the `restore` Compose profile.
#
# This script decrypted a gpg dump and ran `pg_restore` with NO destructive
# confirmation, NO runtime-active/empty-target guards, NO post-restore quiescence
# (so starting the runtime replayed in-flight side effects and missed schedules),
# and NO deep validation. Do not use it.
#
# Use instead (human-gated, quiesces + validates before any runtime start):
#   docker compose --env-file /opt/nlw/.env.restore \
#     -f docker-compose.prod.yml --profile restore run --rm restore
# See docs/runbooks/dr-fresh-host-restore.md,
# docs/runbooks/post-restore-quiescence.md, and
# docs/adr/ADR-022-encrypted-offhost-backup-dr.md.
set -euo pipefail

echo "docker/scripts/restore.sh is DEPRECATED (ADR-022)." >&2
echo "Use: docker compose --profile restore run --rm restore" >&2
echo "See docs/runbooks/dr-fresh-host-restore.md" >&2
exit 1
