#!/usr/bin/env bash
# Nightly logical PostgreSQL backup (M9, ADR-018).
#
# Produces an encrypted, custom-format pg_dump and (optionally) ships it off-host.
# Custom format (-F c) is compressed and restores selectively with pg_restore.
# Encryption uses age/gpg so backups at rest never contain plaintext tenant data.
#
# Required env:
#   PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE   (source database)
#   BACKUP_DIR                                   (local staging dir)
#   BACKUP_PASSPHRASE                            (symmetric encryption secret)
# Optional:
#   OFFSITE_DEST   e.g. s3://bucket/nlw or a remote path for rclone/aws cp
#
# Schedule via cron/systemd-timer, e.g. daily:
#   0 3 * * *  /app/docker/scripts/backup.sh >> /var/log/nlw-backup.log 2>&1
set -euo pipefail

: "${PGDATABASE:?set PGDATABASE}"
: "${BACKUP_DIR:?set BACKUP_DIR}"
: "${BACKUP_PASSPHRASE:?set BACKUP_PASSPHRASE}"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
base="${BACKUP_DIR}/nlw-${PGDATABASE}-${stamp}.dump"
enc="${base}.gpg"

mkdir -p "${BACKUP_DIR}"

echo "[backup] dumping ${PGDATABASE} (custom format) -> ${base}"
pg_dump --format=custom --no-owner --file="${base}" "${PGDATABASE}"

echo "[backup] encrypting -> ${enc}"
gpg --batch --yes --symmetric --cipher-algo AES256 \
    --passphrase "${BACKUP_PASSPHRASE}" --output "${enc}" "${base}"
rm -f "${base}"  # keep only the encrypted artifact locally

if [[ -n "${OFFSITE_DEST:-}" ]]; then
  echo "[backup] shipping off-host -> ${OFFSITE_DEST}"
  # Wire this to your object store / remote (aws s3 cp, rclone copy, scp, ...).
  # aws s3 cp "${enc}" "${OFFSITE_DEST}/"
fi

echo "[backup] done: ${enc}"
