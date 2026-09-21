#!/usr/bin/env bash
# DEPRECATED (M11.5 P2, ADR-022). Superseded by the encrypted, off-host, VERIFIED
# restic-based backup: `python -m nlw.backup backup`, run via the `backup` Compose
# profile and the systemd timer.
#
# This gpg + pg_dump script defined "success" as `pg_dump` exit 0 — it did NOT
# verify the artifact reached off-host storage, had no freshness/dead-man signal,
# and no repository verification. Do not use it.
#
# Use instead:
#   docker compose --env-file /opt/nlw/.env.backup \
#     -f docker-compose.prod.yml --profile backup run --rm backup
# See docs/runbooks/backup-operations.md, docs/ops/backup-systemd.md,
# docs/ops/backup-providers.md, and docs/adr/ADR-022-encrypted-offhost-backup-dr.md.
set -euo pipefail

echo "docker/scripts/backup.sh is DEPRECATED (ADR-022)." >&2
echo "Use: docker compose --profile backup run --rm backup" >&2
echo "See docs/runbooks/backup-operations.md" >&2
exit 1
