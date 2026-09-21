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

## Single execution

The job takes an explicit `flock` around its whole lifecycle (shared
`backup_run` volume → `/run/nlw/backup.lock`), so a second invocation — a manual
run racing the timer, a duplicate timer — exits **3** ("already running") having
run no dump/upload/prune/metrics. This does not rely on restic's repo lock (which
only guards the repo during its own operation). Exit codes: `0` ok, `1` step
failed, `2` usage/unexpected, `3` already running, `4` gate-check failed.

## Retention

Retention has two modes (`NLW_BACKUP_RETENTION_MODE`, see
[backup-providers](../ops/backup-providers.md)):

- **simple** (default): `restic forget --prune` runs each backup using
  `NLW_BACKUP_RETENTION_DAILY/WEEKLY/MONTHLY` (defaults 14/8/6). restic snapshots
  are deduplicated, so retained history is cheap.
- **immutable**: the backup job **never** prunes; run retention as a separate,
  human-gated admin step off the VPS with delete-capable credentials:
  ```bash
  NLW_BACKUP_ALLOW_PRUNE=1 python -m nlw.backup prune
  ```
  Selecting immutable mode with `NLW_BACKUP_FORCE_LOCAL_PRUNE=true` is a
  contradiction and fails closed.

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
