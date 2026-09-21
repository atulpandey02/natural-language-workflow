# PITR boundary — what this backup does NOT do

The pilot uses **daily logical backups** (`pg_dump` custom format via restic). This
document states the boundary honestly so no one over-claims the recovery point.

## What is NOT configured

- **No point-in-time recovery (PITR).** There is no continuous WAL archiving and no
  ability to restore to an arbitrary instant. Recovery lands on the **last daily
  snapshot**, not on "5 minutes ago".
- **No sub-daily RPO.** The recovery point is bounded by the backup interval
  (objective ≤ 24h). Data written after the last snapshot is lost.
- **No physical/base backups or streaming replication.** The pilot is a single
  VPS; there is no standby.

Do **not** claim a 5-minute (or any sub-daily) RPO, PITR, or "zero data loss" from
this mechanism.

## Why (pilot scope)

Logical dumps are version-portable and restore cleanly into a fresh host, which is
the right trade for a single-VPS pilot. Continuous WAL archiving + PITR is a
meaningfully larger operational surface (archive storage, restore-to-timestamp
drills, monitoring of archiver lag) and is **pre-production** work.

## The future path (when sub-daily RPO is required)

Introduce **WAL archiving + PITR** with a purpose-built tool — **WAL-G** or
**pgBackRest** — layered on the same off-host object store:

1. Continuous WAL archiving to the object store alongside a periodic base backup.
2. Restore = base backup + WAL replay to a chosen `recovery_target_time`.
3. Its own drill: restore-to-timestamp verified on a disposable host, with
   archiver-lag monitoring feeding the same dead-man alerting model.
4. Post-restore **quiescence still applies** — PITR changes the recovery *point*,
   not the need to stop replaying in-flight side effects on the restored state.

This would be recorded as a follow-up ADR that supersedes the RPO objective here.
Until then, the honest recovery point is **≤ 24h**, and quiescence (not PITR) is
what makes a restore safe to bring online.
