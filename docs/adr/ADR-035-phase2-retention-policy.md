# ADR-035: Phase 2 retention policy for the synthetic pilot (owner decision O-5)

Status: **accepted; implemented without AWS contact (branch
`chore/phase2-retention-o3-cleanup`); NOT RUN against AWS; uploads stay
refused in staging and production (O-6).** Owner approval: 2026-10-15.
Date: 2026-10-15.
Builds on [ADR-029](ADR-029-dataset-lifecycle-foundation.md) (lifecycle),
[ADR-030](ADR-030-csv-ingestion-and-profiling.md) (purge, tombstone),
[ADR-033](ADR-033-s3-dataset-object-storage.md) (S3 store, D2 rejected objects) and
[ADR-034](ADR-034-external-deletion-receipt-log.md) (deletion receipts).

> **Principle.** Every piece of dataset data has a stated lifetime, a named
> actor that ends it, and evidence that it ended. Nothing is deleted silently:
> object bytes go only through the verified, receipted purge; database rows are
> scrubbed only by the operator's verified tombstone.

## The source of truth

`nlw.core.retention` holds every value below. The provisioning templates, the
backup configuration, the retention sweep, the alert thresholds and this table
are pinned to it by `tests/unit/test_retention_policy.py`. A value is changed
by a new owner decision, never by configuration: the backup retention settings
refuse any other value.

**Guarantee vs target.** A *guarantee* bounds what the system does on its own
(data is kept at least this long, and an automated rule removes it no sooner).
A *target* is an operational deadline for an operator-run job; missing it fires
an alert and never deletes anything by itself.

**Deadline arithmetic.** Timezone-aware timestamps only. A retention period has
*ended* at exactly its length (`>=`, `retention.eligible`); a deadline is
*overdue* only after it (`>`, `retention.overdue`).

## The matrix

| Data | Period | Kind | Actor | Mechanism |
|---|---|---|---|---|
| ACTIVE published source | until deletion is requested | guarantee | none | never touched by the sweep or by S3 lifecycle (no current-version expiry) |
| REJECTED object | purge within 7 days | target | operator (`retention-sweep`) | `REJECTED_RETENTION` -> DELETING, verified purge with receipt |
| Unpublished/inactive version (QUARANTINED, PROFILING with an expired lease, PROFILED, SUPERSEDED) | 30 days (from `superseded_at`, else `created_at`) | guarantee | operator (`retention-sweep`) | `INACTIVE_RETENTION` -> DELETING (migration 0030), verified purge with receipt |
| Logically deleted bytes (DELETING) | purge within 7 days of the request | target | operator (`retention-sweep` or `purge`) | verified purge with receipt; the tombstone stays a separate operator step |
| Incomplete multipart upload | 1 day | guarantee | S3 lifecycle | `AbortIncompleteMultipartUpload` |
| Noncurrent S3 object version | 30 days after it became noncurrent | guarantee | S3 lifecycle | `NoncurrentVersionExpiration` |
| Deletion receipt | 365 days | guarantee | S3 Object Lock (GOVERNANCE) | default retention 365, lifecycle expiry at 366 |
| CloudTrail data events (dataset and receipt buckets) | 365 days | guarantee | S3 Object Lock (GOVERNANCE) | `<AUDIT_RETENTION_DAYS>` = 365, expiry at 366 |
| Database backups | 30 daily, 12 monthly recovery points | guarantee | backup job (`restic forget`) | `NLW_BACKUP_RETENTION_DAILY/WEEKLY/MONTHLY` = 30/0/12, refused otherwise |
| Object-backup recovery copies | 30 days | guarantee (design constraint) | O-4 (not implemented) | to be implemented by O-4 |

## The distinct deletions

- **Database logical deletion**: a request moves a dataset or version to
  DELETING (unusable at once). Rows are never deleted; the operator's tombstone
  later scrubs names, keys, profiles and semantics, after a verified receipt.
- **Physical object purge**: the operator's purge deletes every S3 version,
  delete marker and in-progress upload of a version, verifies absence, writes a
  receipt, records `VERSION_OBJECT_PURGED`. The only path that removes bytes of
  a current object.
- **S3 noncurrent-version expiration**: lifecycle removes object versions that
  are no longer current, 30 days after that. Objects are write-once and the
  operator purge removes every version, so this is a backstop, never the
  evidence for a deletion.
- **Multipart cleanup**: lifecycle aborts uploads left incomplete for 1 day; the
  purge also aborts a version's uploads explicitly.
- **Deletion-receipt retention**: Object Lock keeps each receipt 365 days; a
  lifecycle rule expires it on day 366. The operator cannot delete or shorten
  it; the audit administrator could only with a separately granted GOVERNANCE
  bypass.
- **Audit-log retention**: the same, for CloudTrail data events, in the audit
  bucket.
- **Database-backup retention**: restic keeps 30 daily and 12 monthly snapshots
  (no weekly tier). A restored snapshot may predate a deletion: the restore runs
  `reapply-receipts` before any runtime starts (ADR-034).
- **Object-backup retention**: no object backup exists yet (O-4). When it does,
  its recovery copies are kept 30 days, and a restore from them must likewise
  re-apply receipts.

## Enforcement

**`retention-sweep`** (`python -m nlw.ops.datasets retention-sweep --operator
<name> [--dry-run] [--limit N] [--metrics-file PATH]`, `nlw.ops.dataset_retention`):

- bounded (`--limit`, 1..10000), oldest first; phases: logically deleted, then
  rejected, then inactive;
- idempotent: each item is its own transaction; a failure stops the run with
  earlier items committed; a re-run resumes from the oldest remaining item;
- mutually exclusive: a session advisory lock; a concurrent run reports
  `busy=1` and changes nothing;
- refused while the recovery lock is active (as are `purge`, `purge-rejected`
  and now `tombstone`; `reapply-receipts` is the inverse and runs only then);
- never touches an ACTIVE version or a dataset's active version (excluded in
  SQL and re-checked under the row lock), never deletes a row, never tombstones,
  never purges without a deletion log that can retain the receipt (preflight,
  including the operator role's IAM path, ADR-034).

Scheduling the sweep (a daily timer under the operator identity) is part of
O-6; until then it is an operator command.

**Lifecycle rules** cannot remove the current object (no `Expiration`, no
`Transition` on `versions/`), and cannot remove a receipt or an audit event
while it is retained (expiry is one day after the Object Lock period, and
Object Lock refuses earlier deletion anyway).

## Metrics and alerts (dormant until O-6)

Textfile gauges (node-exporter textfile collector), aggregates only, no labels:

| Source | Gauges |
|---|---|
| `retention-sweep --metrics-file` / `retention-status --metrics-file` | `nlw_dataset_rejected_retained`, `nlw_dataset_rejected_oldest_age_seconds`, `nlw_dataset_inactive_retention_due`, `nlw_dataset_inactive_oldest_age_seconds`, `nlw_dataset_deleting_unpurged`, `nlw_dataset_deleting_oldest_unpurged_age_seconds`, `nlw_dataset_receipts_expiring_untombstoned` |
| `retention-sweep --metrics-file` | `nlw_dataset_retention_sweep_last_run_timestamp_seconds`, `..._last_success_timestamp_seconds` (kept across failures), `nlw_dataset_retention_sweep_failed`, `nlw_dataset_retention_sweep_recovery_locked` |
| `reconcile-receipts --metrics-file` | `nlw_dataset_receipts_unverified`, `nlw_dataset_receipts_unexpected_objects`, `nlw_dataset_receipts_without_event`, `nlw_dataset_receipts_reconcile_last_success_timestamp_seconds` |

Alerts in `docker/prometheus/alerts/datasets.rules.yml` (not loaded by the
deployed Prometheus until O-6; promtool-tested):
`NlwDatasetRejectedRetainedTooLong` (> 7 d), `NlwDatasetInactiveRetainedTooLong`
(> 30 d for 24 h), `NlwDatasetDeletedNotPurged` (> 7 d),
`NlwDatasetReceiptsUnverified`, `NlwDatasetReceiptsExpiringBeforeTombstone`
(receipt retention ends within 30 days, version not tombstoned),
`NlwDatasetRetentionSweepFailed`, `NlwDatasetRetentionSweepStale` (no success for
36 h).

## Object Lock and customer data

The synthetic pilot uses **GOVERNANCE** on the receipt and audit buckets.
**Real customer data remains blocked** until both use **COMPLIANCE** (with the
365-day periods above) and a separate GO decision is recorded.

## Consequences

- Migration `0030_inactive_version_retention` (reason `INACTIVE_RETENTION`; no
  grant, trigger or policy change).
- Template changes (all NOT RUN): the dataset lifecycle gains
  `expire-noncurrent-versions` (30 days; the D6 pins are updated explicitly),
  the receipt lifecycle and Object Lock become 365/366, the audit retention
  value is 365, and the operator's receipt policy gains `ConfirmOwnRolePath`
  (`iam:GetRole` on its own path-`/` ARN, ADR-034).
- Deployed configuration: the production Compose backup retention defaults
  become 30/0/12.
- The isolated D6 proof account keeps its own audit-retention decision (E1).

## Not covered

- Workspace offboarding and its receipts (still not implemented).
- CloudTrail coverage of the receipt bucket (a pinned trail-template change for
  the next provisioning review); its retention, once covered, is 365 days.
- O-4 object backups (the 30-day value is a design constraint).
- Scheduling of the sweep, and enabling the alerts (O-6).
