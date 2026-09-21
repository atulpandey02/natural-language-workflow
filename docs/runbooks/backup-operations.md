# Runbook: backup operations

Day-to-day operation of the encrypted off-host backup
([ADR-022](../adr/ADR-022-encrypted-offhost-backup-dr.md)). Scheduling lives in
[backup-systemd](../ops/backup-systemd.md); providers in
[backup-providers](../ops/backup-providers.md); failures in
[backup-failure-troubleshooting](backup-failure-troubleshooting.md).

## What a backup does (and what "success" means)

`python -m nlw.backup backup` runs a fixed sequence:
`config → db_info → pg_dump (custom, ownership preserved) + roles-only globals →
manifest (secret-free) → ensure repo → backup off-host → restic check (verify) →
confirm snapshot present → forget --prune (retention) → write metrics`.

A run is a **success only if the snapshot reached the off-host repository AND
verification passed** — never merely because `pg_dump` exited 0. The freshness
metric `nlw_backup_last_success_timestamp_seconds` advances **only** on a verified
off-host snapshot.

## Run one now (ad hoc)

```bash
docker compose --env-file /opt/nlw/.env.backup \
  -f docker-compose.prod.yml --profile backup run --rm backup
# or, on the VPS with the timer installed:
sudo systemctl start nlw-backup.service
```

## List / inspect snapshots

```bash
docker compose --env-file /opt/nlw/.env.backup \
  -f docker-compose.prod.yml --profile backup run --rm \
  --entrypoint restic backup snapshots
```
Tags include `nlw-db` and `rev-<alembic_revision>` so you can see the schema
version each snapshot carries.

## Metrics (node_exporter textfile)

Written atomically to `NLW_BACKUP_METRICS_FILE`
(default `/var/lib/node_exporter/textfile/nlw_backup.prom`):

| Metric | Meaning |
|---|---|
| `nlw_backup_success` | last run fully succeeded (1) or failed (0) |
| `nlw_backup_duration_seconds` | last run duration |
| `nlw_backup_repository_verify_success` | restic check passed |
| `nlw_backup_retention_success` | forget --prune succeeded |
| `nlw_backup_last_success_timestamp_seconds` | Unix time of last **verified** backup (dead-man source) |

Alerts: [`docker/prometheus/alerts/backup.rules.yml`](../../docker/prometheus/alerts/backup.rules.yml).

## Retention

`restic forget --prune` runs each backup using
`NLW_BACKUP_RETENTION_DAILY/WEEKLY/MONTHLY` (pilot defaults 14/8/6). restic
snapshots are deduplicated, so retained history is cheap. If provider
object-lock/immutability is enabled for ransomware resistance, automated pruning
cannot reclaim locked objects — run pruning as a separate human-gated step and
size the bucket accordingly (see [backup-providers](../ops/backup-providers.md)).

## Verify recoverability (do not skip)

A backup you have never restored is a hypothesis. Prove the mechanism with the
disposable drill and prove the provider with a real dry run:
```bash
scripts/ops/dr-drill.sh    # disposable, MinIO fixture, measures backup/restore
```
See [dr-real-vps-checklist](dr-real-vps-checklist.md) and
[dr-fresh-host-restore](dr-fresh-host-restore.md).

## Rotating credentials

- **Object-store keys:** update `.env.backup`; no repo re-encryption needed.
- **`RESTIC_PASSWORD`:** use `restic key add` / `restic key remove` (never just
  swap the env var — the repo is encrypted with the existing key). Keep the old
  key until the new one is proven.
