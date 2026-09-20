# Backup & restore (M9, ADR-018)

## Policy (staging)

- **What:** nightly logical `pg_dump` of the platform database, **custom format**
  (`-F c`), **encrypted** (AES256 via gpg), stored **off-host**.
- **RPO ≤ 24h** (nightly logical). **RTO ≤ 1h** (restore into a fresh DB + verify).
- **Redis:** transport only — **no backup required**. After Redis loss the
  scheduler's reconciler rebuilds recovery eligibility from Postgres and
  re-enqueues; Postgres is authoritative.
- **Roles/bootstrap** are restored from version-controlled bootstrap/IaC
  (`docker/postgres/initdb`), never from backed-up role passwords.
- **PITR / 5-minute RPO is NOT configured** and must not be claimed. Enabling WAL
  archiving + PITR (and restore-testing it) is pre-production work.

## Scripts

- `docker/scripts/backup.sh` — dump → encrypt → (optional) ship off-host.
- `docker/scripts/restore.sh` — decrypt → create fresh DB → `pg_restore`.

Schedule `backup.sh` daily (cron/systemd-timer). Required env is documented in
each script header.

## Restore drill (run at least once before staging go-live)

1. Take/obtain a recent encrypted backup artifact.
2. `BACKUP_FILE=... TARGET_DATABASE=nlw_restore ./docker/scripts/restore.sh`
3. Verify: `psql -d nlw_restore -c "SELECT version_num FROM alembic_version;"`
   matches the expected head, and spot-check row counts.
4. Record the drill date + measured RTO.

An automated fidelity check of the dump→restore round-trip runs in the
integration suite (`tests/integration/test_backup_restore.py`).

## Audit / disk-growth monitoring (M11, risk E)

Audit tables (`plan_proposals`, `step_runs`, `external_actions`, `workflow_runs`)
grow unbounded in the limited launch (no retention/GC yet — accepted risk E).
Operational monitoring is therefore REQUIRED:

- Alert when the Postgres data volume exceeds **75%** usage.
- Track table growth (e.g. `pg_total_relation_size`) for the audit tables weekly.
- Action on threshold: provision more disk and/or introduce a retention/GC policy
  (deferred feature) before growth threatens availability.
