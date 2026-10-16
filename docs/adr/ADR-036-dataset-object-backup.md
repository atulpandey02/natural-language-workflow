# ADR-036: Dataset object backup and restore (owner decision O-4)

Status: **accepted; implemented without AWS contact (branch
`feat/o4-dataset-object-backup`); NOT RUN against AWS, no AWS resources;
uploads stay refused in staging and production (O-6).** Owner approval:
2026-10-15. Date: 2026-10-15.
Builds on [ADR-033](ADR-033-s3-dataset-object-storage.md) (S3 store),
[ADR-034](ADR-034-external-deletion-receipt-log.md) (receipts, `reapply-receipts`)
and [ADR-035](ADR-035-phase2-retention-policy.md) (retention). Templates:
[dataset-object-backup-provisioning](../runbooks/dataset-object-backup-provisioning.md) (NOT RUN).

> **Principle.** A database restore must be able to bring back the bytes its
> rows reference, and must never bring back bytes a deletion receipt says are
> gone.

## Context

PostgreSQL backups hold metadata, never bytes (ADR-030). After a database
restore, `verify-objects` would report every object the dataset bucket no
longer holds as missing, and nothing could restore it. ADR-035 fixed the
retention of object recovery copies at 30 days as a design constraint.

## Decision (owner, 2026-10-15)

1. **Mechanism: AWS Backup continuous backups** of the dataset bucket
   (point-in-time restore over 30 days) into a dedicated vault. Chosen over S3
   replication (copies would need the replication deny lifted and keep purged
   copies with no restore control), a restic copy job (bulk downloads, static
   keys) and versioning alone (no protection from bucket or account loss of
   access).
2. **Location: same account, us-east-1**, a vault per environment with its own
   KMS key, separate from the dataset bucket, the receipt bucket and the Restic
   repository. A second region or a separate account were deferred (they would
   change ADR-033's us-east-1-only rule or need cross-account operation).
3. **Restore: into a separate restore bucket**, then `restore-objects` copies
   back only what the restored database still references.

## Design

- **Backup**: `backup-plan` (continuous, `DeleteAfterDays: 30`),
  `backup-selection` (the dataset bucket only), `backup-vault-lock` (exactly 30
  days; GOVERNANCE for the synthetic pilot), `backup-vault-access-policy` (no
  recovery-point change except by the administrator). The service role reads
  the dataset bucket and writes only the restore bucket; it is explicitly
  denied every write, delete or configuration change on the dataset bucket.
- **Keys**: the dataset key's reviewed statements are unchanged; two statements
  are **appended** where O-4 is provisioned (`dataset-kms-key-o4-statements`):
  the backup role may decrypt, and the restore role may generate data keys and
  decrypt, both only via S3 and only for this bucket's encryption context. The
  D6 proof account keeps the base policy (KMS refuses a policy naming a role
  that does not exist there).
- **Restore bucket**: write by the backup service only, read by the restore
  role only, everything expires after 7 days (`RESTORE_COPY_EXPIRY_DAYS`).
- **`restore-objects`** (`python -m nlw.ops.datasets restore-objects [--dry-run]
  [--limit N] [--after VERSION_ID]`, run as `nlw-<env>-dataset-restore` only;
  it never loads the operator credentials):
  - refused unless the recovery lock holds a restored database;
  - refused until every receipt in the deletion log is re-applied
    (`reapply-receipts`): a backup taken before a purge can never resurrect it.
    The restore role lists and reads receipts itself (an identity grant on
    `receipts/*`; never a write, and the receipt bucket policy is unchanged);
  - for each version with a key that is not DELETING, DELETED or REJECTED,
    oldest first, bounded: present and matching -> `present`; present but
    different -> reported, never overwritten; missing -> the restored copy is
    hashed and must equal the recorded SHA-256 and size, then written
    write-once (`If-None-Match`, SSE-KMS with the dataset key) exactly as an
    upload; absent from the backup or different -> reported;
  - one bounded page per run (`--limit`, oldest first), continued with
    `--after <next>` until `more=0`; idempotent; exit 1 on anything to
    investigate.
- **`verify-objects`** no longer fails on noncurrent versions (expected for up
  to 30 days under the O-5 lifecycle); they are still reported.
- **DR evidence** records `objects_step: restored_and_verified` or
  `not_applicable_no_dataset_store`, never assumed.

## Consequences

- RPO for uploaded files: the continuous-backup point chosen for the restore
  (seconds to minutes of the incident, an AWS service property **not proven
  here**); RTO: the AWS restore job plus `restore-objects` (not measured).
- A purged object stays in recovery points until they expire (30 days): the
  documented "beyond use" posture; restores cannot bring it back.
- New, pinned templates, including the complete vault-key and restore-key
  statements; the D6 package is unchanged.
- The restore role could write a purged key back outside `restore-objects`
  (IAM cannot know which keys a receipt proves deleted): it is a time-boxed,
  named human role used only during a declared recovery, and every write is a
  CloudTrail data event reviewed after the restore (runbook §9).

## Unverified and remaining

- U1-U5 in the runbook (AWS Backup notification permissions, managed-policy
  actions, key preservation on restore, multipart checksums).
- An object restore drill against AWS (part of the authorized proof).
- COMPLIANCE vault lock and a separate GO decision before customer data.
