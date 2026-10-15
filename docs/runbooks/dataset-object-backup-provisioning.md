# Dataset object backup and restore provisioning (NOT RUN — templates for review)

Status: **a plan, not a record.** Nothing here has been created, and no AWS
account has been contacted. These templates implement
[ADR-036](../adr/ADR-036-dataset-object-backup.md) (owner decision O-4,
2026-10-15): AWS Backup continuous backups (point-in-time restore over 30 days)
of the dataset bucket into a dedicated vault in the same account and region,
and restores into a separate restore bucket from which the operator copies
objects back with `restore-objects`. Creating any real resource needs a
separate provisioning review and **explicit owner authorization**.

Every JSON block is marked `<!-- template: name -->`.
`tests/unit/test_object_backup_templates.py` parses each one, pins it, and
asserts the invariants below. The templates in
[dataset-s3-provisioning.md](dataset-s3-provisioning.md) (dataset bucket,
dataset key, every role and every D6 proof document) are **unchanged**: O-4 is
added beside them, never by editing them, and the D6 proof account never
provisions it.

## Placeholders

None of these may be replaced by a real value in this repository.

| Placeholder | Meaning |
|---|---|
| `<ENV>`, `<OTHER_ENV>`, `<ACCOUNT>`, `<BUCKET>`, `<KEY_ARN>`, `<ADMIN_ROLE>` | as in [dataset-s3-provisioning.md](dataset-s3-provisioning.md) |
| `<VAULT>` | the backup vault `nlw-<ENV>-datasets`, one per environment |
| `<VAULT_KEY_ARN>` | a customer-managed KMS key for the vault's recovery points, separate from `<KEY_ARN>` |
| `<RESTORE_BUCKET>` | `nlw-<ENV>-datasets-restore-<ACCOUNT>-us-east-1[-<suffix>]`; settings refuse sharing it with the dataset, receipt or Restic bucket |
| `<RESTORE_KEY_ARN>` | a customer-managed KMS key for the restore bucket, separate from both keys above |
| `<HUMAN_PRINCIPAL_ARNS>` | as for the operator (`trust-human`); the restorer is a human role |

## 1. Retention (owner decision O-5, ADR-035)

- Recovery points: **30 days** (`nlw.core.retention.OBJECT_BACKUP_RETENTION_DAYS`).
- Restore bucket: everything it holds expires after **7 days**
  (`RESTORE_COPY_EXPIRY_DAYS`); it is a staging area for one restore, never a
  copy kept for itself.
- The vault lock keeps every recovery point exactly 30 days. In GOVERNANCE
  mode (no `ChangeableForDays`) for the synthetic pilot; real customer data
  stays blocked until the vault lock is COMPLIANCE and a separate GO decision
  is recorded.

<!-- template: backup-plan -->
```json
{"BackupPlanName": "nlw-<ENV>-datasets",
 "Rules": [{
   "RuleName": "continuous-30-days",
   "TargetBackupVaultName": "<VAULT>",
   "ScheduleExpression": "cron(0 5 ? * * *)",
   "EnableContinuousBackup": true,
   "Lifecycle": {"DeleteAfterDays": 30}
 }]}
```

<!-- template: backup-selection -->
```json
{"SelectionName": "nlw-<ENV>-dataset-bucket",
 "IamRoleArn": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-backup-service",
 "Resources": ["arn:aws:s3:::<BUCKET>"]}
```

<!-- template: backup-vault-lock -->
```json
{"BackupVaultName": "<VAULT>", "MinRetentionDays": 30, "MaxRetentionDays": 30}
```

**Vault access policy:** recovery points are never deleted, re-scoped or
re-tained differently by anyone but the administrator (the lock refuses an
early deletion even then).

<!-- template: backup-vault-access-policy -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "DenyRecoveryPointChangesExceptAdmin", "Effect": "Deny", "Principal": "*",
   "Action": ["backup:DeleteRecoveryPoint", "backup:UpdateRecoveryPointLifecycle",
              "backup:PutBackupVaultAccessPolicy", "backup:DeleteBackupVaultAccessPolicy",
              "backup:DeleteBackupVault", "backup:PutBackupVaultLockConfiguration",
              "backup:DeleteBackupVaultLockConfiguration"],
   "Resource": "*",
   "Condition": {"ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/<ADMIN_ROLE>"}}},
  {"Sid": "DenyOtherEnvironmentRoles", "Effect": "Deny", "Principal": "*",
   "Action": "backup:*", "Resource": "*",
   "Condition": {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/nlw-<OTHER_ENV>-*"}}}
]}
```

## 2. The backup service role

`nlw-<ENV>-dataset-backup-service`, assumed only by AWS Backup for this
account. It reads the dataset bucket (to back it up) and writes only the
restore bucket (to restore into it). It can never write, delete or reconfigure
the dataset bucket. Continuous backups need the dataset bucket's EventBridge
notifications: the bucket **administrator** enables them once at provisioning
(`<ADMIN_ROLE>`, the only principal the bucket policy lets change
configuration); the service role is not granted `s3:PutBucketNotification`
(see "Unverified AWS behaviour").

<!-- template: trust-backup-service -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "AwsBackupThisAccountOnly", "Effect": "Allow",
   "Principal": {"Service": "backup.amazonaws.com"},
   "Action": "sts:AssumeRole",
   "Condition": {"StringEquals": {"aws:SourceAccount": "<ACCOUNT>"}}}
]}
```

<!-- template: role-backup-service -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "ReadTheDatasetBucket", "Effect": "Allow",
   "Action": ["s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketVersioning",
              "s3:GetBucketLocation", "s3:GetBucketTagging", "s3:GetBucketNotification"],
   "Resource": "arn:aws:s3:::<BUCKET>"},
  {"Sid": "ReadDatasetObjects", "Effect": "Allow",
   "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging",
              "s3:GetObjectVersionTagging", "s3:GetObjectAcl", "s3:GetObjectVersionAcl"],
   "Resource": "arn:aws:s3:::<BUCKET>/versions/*"},
  {"Sid": "DecryptDatasetObjects", "Effect": "Allow", "Action": "kms:Decrypt",
   "Resource": "<KEY_ARN>",
   "Condition": {"StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com"}}},
  {"Sid": "ContinuousBackupEvents", "Effect": "Allow",
   "Action": ["events:DescribeRule", "events:EnableRule", "events:PutRule", "events:DeleteRule",
              "events:PutTargets", "events:RemoveTargets", "events:ListTargetsByRule",
              "events:DisableRule"],
   "Resource": "arn:aws:events:us-east-1:<ACCOUNT>:rule/AwsBackupManagedRule*"},
  {"Sid": "BackupMetrics", "Effect": "Allow", "Action": "cloudwatch:GetMetricData", "Resource": "*"},
  {"Sid": "RestoreIntoTheRestoreBucketOnly", "Effect": "Allow",
   "Action": ["s3:PutObject", "s3:PutObjectTagging", "s3:GetBucketVersioning",
              "s3:ListBucket", "s3:GetBucketLocation"],
   "Resource": ["arn:aws:s3:::<RESTORE_BUCKET>", "arn:aws:s3:::<RESTORE_BUCKET>/versions/*"]},
  {"Sid": "EncryptRestoredObjects", "Effect": "Allow",
   "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": "<RESTORE_KEY_ARN>",
   "Condition": {"StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com"}}},
  {"Sid": "NeverChangeTheDatasetBucket", "Effect": "Deny",
   "Action": ["s3:PutObject*", "s3:DeleteObject*", "s3:PutBucket*", "s3:DeleteBucket*",
              "s3:PutLifecycleConfiguration", "s3:PutReplicationConfiguration",
              "s3:PutInventoryConfiguration", "s3:BypassGovernanceRetention"],
   "Resource": ["arn:aws:s3:::<BUCKET>", "arn:aws:s3:::<BUCKET>/*"]},
  {"Sid": "NeverOtherEnvironment", "Effect": "Deny", "Action": ["s3:*", "kms:*"],
   "Resource": ["arn:aws:s3:::nlw-<OTHER_ENV>-*", "arn:aws:s3:::nlw-<OTHER_ENV>-*/*"]}
]}
```

## 3. Key-policy statements (appended where O-4 is provisioned)

The dataset key's reviewed statements are unchanged. Where O-4 is provisioned,
these two statements are **appended** to that key policy (KMS refuses a policy
that names a role which does not exist, so the D6 proof account, which has no
backup or restore role, keeps the base policy). Both carry the same
`kms:ViaService` and bucket encryption-context condition as every other grant.

<!-- template: dataset-kms-key-o4-statements -->
```json
[
  {"Sid": "BackupDecryptsViaS3ForThisBucketOnly", "Effect": "Allow",
   "Principal": {"AWS": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-backup-service"},
   "Action": "kms:Decrypt",
   "Resource": "*",
   "Condition": {"StringEquals": {
     "kms:ViaService": "s3.us-east-1.amazonaws.com",
     "kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::<BUCKET>"}}},
  {"Sid": "RestorerWritesViaS3ForThisBucketOnly", "Effect": "Allow",
   "Principal": {"AWS": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-restore"},
   "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
   "Resource": "*",
   "Condition": {"StringEquals": {
     "kms:ViaService": "s3.us-east-1.amazonaws.com",
     "kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::<BUCKET>"}}}
]
```

## 4. The restore bucket

- us-east-1, Block Public Access on, `BucketOwnerEnforced`, Versioning on,
  default encryption SSE-KMS with `<RESTORE_KEY_ARN>`, no Object Lock, no
  replication, no notifications.
- Only the backup service role writes (a restore); only the restore role reads.

<!-- template: restore-bucket-lifecycle -->
```json
{"Rules": [{
  "ID": "expire-restored-copies",
  "Status": "Enabled",
  "Filter": {"Prefix": ""},
  "Expiration": {"Days": 7},
  "NoncurrentVersionExpiration": {"NoncurrentDays": 1},
  "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}
}]}
```

<!-- template: restore-bucket-policy -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "DenyNonTLS", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
   "Resource": ["arn:aws:s3:::<RESTORE_BUCKET>", "arn:aws:s3:::<RESTORE_BUCKET>/*"],
   "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
  {"Sid": "DenyOutsideAccount", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
   "Resource": ["arn:aws:s3:::<RESTORE_BUCKET>", "arn:aws:s3:::<RESTORE_BUCKET>/*"],
   "Condition": {"StringNotEquals": {"aws:PrincipalAccount": "<ACCOUNT>"}}},
  {"Sid": "DenyOtherEnvironmentRoles", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
   "Resource": ["arn:aws:s3:::<RESTORE_BUCKET>", "arn:aws:s3:::<RESTORE_BUCKET>/*"],
   "Condition": {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/nlw-<OTHER_ENV>-*"}}},
  {"Sid": "DenyWritesExceptBackupService", "Effect": "Deny", "Principal": "*",
   "Action": "s3:PutObject", "Resource": "arn:aws:s3:::<RESTORE_BUCKET>/*",
   "Condition": {"ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-backup-service"}}},
  {"Sid": "DenyReadsExceptRestorer", "Effect": "Deny", "Principal": "*",
   "Action": ["s3:GetObject", "s3:GetObjectVersion"], "Resource": "arn:aws:s3:::<RESTORE_BUCKET>/*",
   "Condition": {"ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-restore"}}},
  {"Sid": "DenyBucketConfigExceptAdmin", "Effect": "Deny", "Principal": "*",
   "Action": ["s3:PutBucket*", "s3:DeleteBucket*", "s3:PutLifecycleConfiguration",
              "s3:PutEncryptionConfiguration", "s3:PutBucketVersioning",
              "s3:PutReplicationConfiguration", "s3:PutInventoryConfiguration"],
   "Resource": "arn:aws:s3:::<RESTORE_BUCKET>",
   "Condition": {"ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/<ADMIN_ROLE>"}}}
]}
```

## 5. The restore role

`nlw-<ENV>-dataset-restore`, a human role (`trust-human` with its own
`<HUMAN_PRINCIPAL_ARNS>`), used only during a restore by `python -m
nlw.ops.datasets restore-objects`. It reads the restore bucket and writes the
dataset bucket only the way the API does: `PutObject` on `versions/*`, which
the dataset bucket policy accepts only as a conditional (`If-None-Match`),
SSE-KMS creation with the dataset key, so it can never overwrite an object.
It can never delete. It lists and reads the deletion receipts (never writes
them; the receipt bucket policy admits receipt writes from the operator role
only), so `restore-objects` itself confirms every receipt was re-applied. The
receipt bucket policy is unchanged: it denies only the runtime roles.

<!-- template: role-dataset-restore -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "ReadRestoredCopies", "Effect": "Allow",
   "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes"],
   "Resource": "arn:aws:s3:::<RESTORE_BUCKET>/versions/*"},
  {"Sid": "ListRestoredCopies", "Effect": "Allow", "Action": "s3:ListBucket",
   "Resource": "arn:aws:s3:::<RESTORE_BUCKET>",
   "Condition": {"StringLike": {"s3:prefix": ["versions/*"]}}},
  {"Sid": "DecryptRestoredCopies", "Effect": "Allow", "Action": "kms:Decrypt",
   "Resource": "<RESTORE_KEY_ARN>",
   "Condition": {"StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com"}}},
  {"Sid": "ReadDeletionReceipts", "Effect": "Allow", "Action": "s3:GetObject",
   "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>/receipts/*"},
  {"Sid": "ListDeletionReceipts", "Effect": "Allow", "Action": "s3:ListBucket",
   "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>",
   "Condition": {"StringLike": {"s3:prefix": ["receipts/*"]}}},
  {"Sid": "WriteOnceIntoTheDatasetBucket", "Effect": "Allow",
   "Action": ["s3:PutObject", "s3:GetObject", "s3:GetObjectAttributes"],
   "Resource": "arn:aws:s3:::<BUCKET>/versions/*"},
  {"Sid": "ListTheDatasetBucket", "Effect": "Allow", "Action": "s3:ListBucket",
   "Resource": "arn:aws:s3:::<BUCKET>",
   "Condition": {"StringLike": {"s3:prefix": ["versions/*"]}}},
  {"Sid": "EncryptWithTheDatasetKey", "Effect": "Allow",
   "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": "<KEY_ARN>",
   "Condition": {"StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com"}}},
  {"Sid": "NeverDeleteOrReconfigure", "Effect": "Deny",
   "Action": ["s3:DeleteObject*", "s3:PutBucket*", "s3:DeleteBucket*", "s3:PutObjectRetention",
              "s3:PutLifecycleConfiguration", "s3:PutReplicationConfiguration",
              "s3:BypassGovernanceRetention", "backup:*"],
   "Resource": "*"},
  {"Sid": "NeverOtherEnvironment", "Effect": "Deny", "Action": ["s3:*", "kms:*"],
   "Resource": ["arn:aws:s3:::nlw-<OTHER_ENV>-*", "arn:aws:s3:::nlw-<OTHER_ENV>-*/*"]}
]}
```

## 6. Configuration

Operator commands only. No runtime container is given these settings.

| Setting | Value |
|---|---|
| `DATASET_RESTORE_BUCKET` | `<RESTORE_BUCKET>` |
| `AWS_SHARED_CREDENTIALS_FILE` | the restore role's pinned, short-lived credential file (ADR-033 D3), for `restore-objects` |

## 7. Restore procedure (NOT RUN)

Part of [dr-fresh-host-restore](dr-fresh-host-restore.md) step 6c, while the
recovery lock holds the restored database and after `reapply-receipts`:

1. Start an AWS Backup restore of the dataset bucket's latest recovery point
   before the incident into `<RESTORE_BUCKET>` (the administrator, from the vault).
2. `python -m nlw.ops.datasets restore-objects --dry-run`, then without `--dry-run`
   (while `more=1`, run it again with `--after <next>`).
3. `python -m nlw.ops.datasets verify-objects` must report no missing object and
   no digest mismatch.
4. Record `objects_step: restored_and_verified` in the DR evidence.

## 8. Unverified AWS behaviour (to prove before relying on it)

- **U1** whether AWS Backup continuous backup of S3 requires the service role
  itself to call `s3:PutBucketNotification` even when the administrator has
  already enabled EventBridge notifications (the dataset bucket policy denies
  it to every principal but `<ADMIN_ROLE>`);
- **U2** the exact actions of the current AWS managed policies
  `AWSBackupServiceRolePolicyForS3Backup` / `...Restore`, compared with
  `role-backup-service`;
- **U3** that a restore into an existing bucket keeps the original
  `versions/...` keys and each object's checksum;
- **U4** the restore of objects created by a multipart upload (composite
  checksum) and the SHA-256 `restore-objects` recomputes.

## 9. Residual risks

- A purged object remains in recovery points until they expire (30 days).
  This is the documented "beyond use" posture: physical erasure inside the
  backup retention window is not promised; a restore cannot resurrect it,
  because `restore-objects` refuses to run until every deletion receipt is
  re-applied and never restores a DELETING or DELETED version.
- GOVERNANCE vault lock for the synthetic pilot: the administrator could
  shorten it; COMPLIANCE before customer data.
- Same account and region: a loss of the account or of us-east-1 loses the
  backups with the data (owner decision; ADR-033 keeps us-east-1 only).
