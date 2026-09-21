# Restore from backup

> **Superseded (M11.5 P2, ADR-022).** The gpg + `pg_restore` flow below is
> replaced by the guarded restic restore that quiesces and validates before any
> runtime start. Use **[dr-fresh-host-restore](dr-fresh-host-restore.md)** and
> **[disaster-declaration-checklist](disaster-declaration-checklist.md)**. This
> page is kept as a pointer only.

The current disaster-recovery restore:

```bash
docker compose --env-file /opt/nlw/.env.restore \
  -f docker-compose.prod.yml --profile restore run --rm restore
```

It refuses to run unless `NLW_RESTORE_CONFIRM == NLW_RESTORE_TARGET_ID`, the
target DB is empty, and no runtime role is connected; it verifies manifest hashes,
restores with **ownership preserved**, flushes Redis, runs mandatory
**post-restore quiescence** ([post-restore-quiescence](post-restore-quiescence.md)),
then **deep-validates** the restored security posture. See
[ADR-022](../adr/ADR-022-encrypted-offhost-backup-dr.md) and
[backup-operations](backup-operations.md).

## Scope: application state only

This restores **NLW application PostgreSQL state**. It does **NOT** restore the
external **Supabase Auth** identity provider (accounts, passwords, sessions/JWT
signing keys). Full-platform recovery requires both this restore AND the identity
provider's own backup/restore. Do not claim full-platform DR from the NLW restore
alone.
