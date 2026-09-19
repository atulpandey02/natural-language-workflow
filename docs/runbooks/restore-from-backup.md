# Restore from backup

See [../ops/backup-restore.md](../ops/backup-restore.md) for policy + RPO/RTO.

**Do:**
1. Choose the latest good encrypted backup artifact.
2. Restore into a FRESH database (never overwrite the live DB implicitly):
   `BACKUP_FILE=... BACKUP_PASSPHRASE=... TARGET_DATABASE=nlw_restore
   ./docker/scripts/restore.sh`
3. Verify: `SELECT version_num FROM alembic_version` matches the expected head;
   spot-check critical tables' row counts.
4. Cut over (point `DATABASE_URL` at the restored DB, or rename) during a
   maintenance window. Roles come from bootstrap/IaC, not the dump.
5. Record the incident, the backup used, and the measured RTO.
