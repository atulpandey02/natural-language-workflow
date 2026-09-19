#!/usr/bin/env bash
# Restore an encrypted logical backup into a FRESH database (M9, ADR-018).
#
# Restores into a NEW target database (never overwrites a live one implicitly),
# then the caller verifies (row counts + `alembic current`) before switching
# traffic. Roles/bootstrap are NOT restored from the dump — they come from
# version-controlled bootstrap/IaC (docker/postgres/initdb), so backups never
# carry role passwords.
#
# Required env:
#   PGHOST PGPORT PGUSER PGPASSWORD   (target server; PGUSER must be able to createdb)
#   BACKUP_FILE                       (the *.dump.gpg artifact)
#   BACKUP_PASSPHRASE                 (symmetric decryption secret)
#   TARGET_DATABASE                   (fresh DB name to create + restore into)
set -euo pipefail

: "${BACKUP_FILE:?set BACKUP_FILE}"
: "${BACKUP_PASSPHRASE:?set BACKUP_PASSPHRASE}"
: "${TARGET_DATABASE:?set TARGET_DATABASE}"

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT

echo "[restore] decrypting ${BACKUP_FILE}"
gpg --batch --yes --decrypt --passphrase "${BACKUP_PASSPHRASE}" \
    --output "${tmp}" "${BACKUP_FILE}"

echo "[restore] creating fresh database ${TARGET_DATABASE}"
createdb "${TARGET_DATABASE}"

echo "[restore] restoring into ${TARGET_DATABASE}"
pg_restore --no-owner --dbname="${TARGET_DATABASE}" "${tmp}"

echo "[restore] done. Verify with: psql -d ${TARGET_DATABASE} -c 'SELECT version_num FROM alembic_version;'"
