# Deletion-receipt log provisioning (NOT RUN — templates for review)

Status: **a plan, not a record.** Nothing here has been created, and no AWS
account has been contacted. These templates implement
[ADR-034](../adr/ADR-034-external-deletion-receipt-log.md) (owner decision O-3,
2026-10-14). Creating or changing any real AWS resource requires a separate
provisioning review and **explicit owner authorization**, as for the dataset
bucket ([dataset-s3-provisioning.md](dataset-s3-provisioning.md)).

Every JSON block is marked `<!-- template: name -->`.
`tests/unit/test_deletion_receipt_templates.py` parses each one, pins its
statements and asserts the invariants below. The in-memory S3 the code is
tested against (`tests/unit/receipt_s3_fake.py`) enforces the same grants.

The existing templates in `dataset-s3-provisioning.md` (including
`role-operator`, the audit roles and every D6 proof document) are **unchanged**.
The operator role receives the receipt grants as a **second, separate inline
policy**, so the D6 pins and boundaries stay as reviewed.

## Placeholders

None of these may be replaced by a real value in this repository.

| Placeholder | Meaning |
|---|---|
| `<ENV>` | `staging` or `production`, one log per environment, never shared |
| `<OTHER_ENV>` | the other environment, which is explicitly denied |
| `<ACCOUNT>` | the AWS account id of the environment's dataset bucket |
| `<RECEIPT_BUCKET>` | `nlw-<ENV>-deletion-receipts-<ACCOUNT>-us-east-1[-<suffix>]`, at most 61 characters (the sink id `s3.<bucket>` is at most 64). It is separate from the dataset bucket, the audit bucket and the Restic bucket; settings refuse a shared name. |
| `<RECEIPT_RETENTION_DAYS>` | default Object Lock retention. **Undecided: set by O-5.** Until then the proof uses GOVERNANCE with a short placeholder; before any customer data it becomes COMPLIANCE with the O-5 value (D6 decisions E1/E2). |
| `<RECEIPT_EXPIRY_DAYS>` | `<RECEIPT_RETENTION_DAYS>` + 1, the lifecycle expiry |
| `<AUDIT_ADMIN_ROLE>` | the environment's audit administrator (`nlw-<ENV>-dataset-audit-admin`), the only principal that may change the bucket's configuration or the retention of a receipt |
| `<AUDIT_READER_ROLE>` | the environment's read-only audit reviewer |

## 1. The receipt bucket

**Settings:**

- us-east-1, Block Public Access: all four settings on, `BucketOwnerEnforced`;
- Versioning: on (required by Object Lock);
- **Object Lock enabled at creation**, default retention **GOVERNANCE** for
  `<RECEIPT_RETENTION_DAYS>` days. The code refuses to purge unless this default
  exists (`preflight`) and refuses a receipt stored without retention;
- default encryption **SSE-S3** (`AES256`). Receipts hold ids, digests, counts,
  an operator label and a time: no names, keys, paths or values. SSE-S3 keeps
  the evidence readable without a KMS key whose policy could later be changed
  or scheduled for deletion. The bucket policy denies any other algorithm;
- no replication, no event notifications, no website, no ACLs.

**Expiry** (only after retention):

<!-- template: receipt-bucket-lifecycle -->
```json
{"Rules": [{
  "ID": "expire-after-retention",
  "Status": "Enabled",
  "Filter": {"Prefix": "receipts/"},
  "Expiration": {"Days": "<RECEIPT_EXPIRY_DAYS>"},
  "NoncurrentVersionExpiration": {"NoncurrentDays": 1}
}]}
```

**Bucket policy:** TLS only; this account only; never another environment's
roles; never the dataset runtime roles; **only this environment's
`nlw-<ENV>-dataset-operator` role may create a receipt** (no other principal in
the account, whatever its identity policy grants); every write is a
conditional, SSE-S3 creation under `receipts/`; no copy; no deletion, retention
or legal-hold change and no configuration change except by the audit
administrator.

<!-- template: receipt-bucket-policy -->
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "DenyNonTLS", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
     "Resource": ["arn:aws:s3:::<RECEIPT_BUCKET>", "arn:aws:s3:::<RECEIPT_BUCKET>/*"],
     "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
    {"Sid": "DenyOutsideAccount", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
     "Resource": ["arn:aws:s3:::<RECEIPT_BUCKET>", "arn:aws:s3:::<RECEIPT_BUCKET>/*"],
     "Condition": {"StringNotEquals": {"aws:PrincipalAccount": "<ACCOUNT>"}}},
    {"Sid": "DenyOtherEnvironmentRoles", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
     "Resource": ["arn:aws:s3:::<RECEIPT_BUCKET>", "arn:aws:s3:::<RECEIPT_BUCKET>/*"],
     "Condition": {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/nlw-<OTHER_ENV>-*"}}},
    {"Sid": "DenyDatasetRuntimeRoles", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
     "Resource": ["arn:aws:s3:::<RECEIPT_BUCKET>", "arn:aws:s3:::<RECEIPT_BUCKET>/*"],
     "Condition": {"ArnLike": {"aws:PrincipalArn": [
        "arn:aws:iam::<ACCOUNT>:role/nlw-*-dataset-api",
        "arn:aws:iam::<ACCOUNT>:role/nlw-*-dataset-ingest",
        "arn:aws:iam::<ACCOUNT>:role/nlw-*-dataset-bootstrap"]}}},
    {"Sid": "DenyWritesOutsideReceipts", "Effect": "Deny", "Principal": "*",
     "Action": "s3:PutObject", "NotResource": "arn:aws:s3:::<RECEIPT_BUCKET>/receipts/*"},
    {"Sid": "DenyReceiptWritesExceptOperator", "Effect": "Deny", "Principal": "*",
     "Action": "s3:PutObject", "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>/receipts/*",
     "Condition": {"ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator"}}},
    {"Sid": "DenyUnconditionalCreate", "Effect": "Deny", "Principal": "*",
     "Action": "s3:PutObject", "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>/*",
     "Condition": {"Null": {"s3:if-none-match": "true"}}},
    {"Sid": "DenyMissingSseAlgorithmHeader", "Effect": "Deny", "Principal": "*",
     "Action": "s3:PutObject", "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>/*",
     "Condition": {"Null": {"s3:x-amz-server-side-encryption": "true"}}},
    {"Sid": "DenyWrongSseAlgorithm", "Effect": "Deny", "Principal": "*",
     "Action": "s3:PutObject", "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>/*",
     "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption": "AES256"}}},
    {"Sid": "DenyServerSideCopy", "Effect": "Deny", "Principal": "*",
     "Action": "s3:PutObject", "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>/*",
     "Condition": {"Null": {"s3:x-amz-copy-source": "false"}}},
    {"Sid": "DenyRecordChangeExceptAuditAdmin", "Effect": "Deny", "Principal": "*",
     "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention",
                "s3:PutObjectRetention", "s3:PutObjectLegalHold"],
     "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>/*",
     "Condition": {"ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/<AUDIT_ADMIN_ROLE>"}}},
    {"Sid": "DenyBucketConfigExceptAuditAdmin", "Effect": "Deny", "Principal": "*",
     "Action": ["s3:PutBucket*", "s3:DeleteBucket*", "s3:PutLifecycleConfiguration",
                "s3:PutEncryptionConfiguration", "s3:PutBucketVersioning",
                "s3:PutBucketObjectLockConfiguration", "s3:PutReplicationConfiguration",
                "s3:PutInventoryConfiguration", "s3:PutAnalyticsConfiguration",
                "s3:PutMetricsConfiguration", "s3:PutIntelligentTieringConfiguration",
                "s3:PutAccelerateConfiguration"],
     "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>",
     "Condition": {"ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/<AUDIT_ADMIN_ROLE>"}}}
  ]
}
```

## 2. The operator's receipt grants (second inline policy)

Attached to `nlw-<ENV>-dataset-operator` as an inline policy named
`deletion-receipts`, beside the unchanged `role-operator` policy. The operator
already runs `purge`, `purge-rejected` and `tombstone`; with this policy it
also writes one receipt per purged version, reads receipts back to verify
them, lists them for `reconcile-receipts` and `reapply-receipts`, and confirms
the bucket's default retention before a purge deletes anything.

<!-- template: role-operator-receipts -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "WriteReceiptsOnce", "Effect": "Allow", "Action": "s3:PutObject",
   "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>/receipts/*"},
  {"Sid": "ReadReceipts", "Effect": "Allow",
   "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"],
   "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>/receipts/*"},
  {"Sid": "ListReceipts", "Effect": "Allow", "Action": "s3:ListBucket",
   "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>",
   "Condition": {"StringLike": {"s3:prefix": ["receipts/*"]}}},
  {"Sid": "ConfirmRetention", "Effect": "Allow", "Action": "s3:GetBucketObjectLockConfiguration",
   "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>"},
  {"Sid": "NeverAlterReceipts", "Effect": "Deny",
   "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention",
              "s3:PutObjectRetention", "s3:PutObjectLegalHold", "s3:PutBucket*",
              "s3:DeleteBucket*", "s3:PutLifecycleConfiguration",
              "s3:PutEncryptionConfiguration", "s3:PutBucketVersioning",
              "s3:PutBucketObjectLockConfiguration"],
   "Resource": ["arn:aws:s3:::<RECEIPT_BUCKET>", "arn:aws:s3:::<RECEIPT_BUCKET>/*"]}
]}
```

- `s3:PutObject` can only **create**: the bucket policy denies a write without
  `If-None-Match` (an overwrite) and Object Lock keeps every version anyway.
- `s3:GetObjectRetention` lets the code see the retention mode and date it
  requires on every receipt. No delete, retention or configuration action is
  granted, and each is explicitly denied.

## 3. The audit roles (second inline policies)

The audit administrator manages the bucket; the reader reviews receipts.
Neither receives a bypass of retention: removing a receipt early under
GOVERNANCE needs a separate, reviewed change that grants
`s3:BypassGovernanceRetention`, and under COMPLIANCE is impossible.

<!-- template: role-audit-admin-receipts -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "AdministerReceiptBucket", "Effect": "Allow",
   "Action": ["s3:CreateBucket", "s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketPolicy",
              "s3:PutBucketPolicy", "s3:GetBucketVersioning", "s3:PutBucketVersioning",
              "s3:GetEncryptionConfiguration", "s3:PutEncryptionConfiguration",
              "s3:GetLifecycleConfiguration", "s3:PutLifecycleConfiguration",
              "s3:GetBucketObjectLockConfiguration", "s3:PutBucketObjectLockConfiguration",
              "s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock",
              "s3:GetBucketOwnershipControls", "s3:PutBucketOwnershipControls",
              "s3:GetBucketTagging", "s3:PutBucketTagging"],
   "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>"},
  {"Sid": "InspectReceipts", "Effect": "Allow",
   "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"],
   "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>/receipts/*"}
]}
```

<!-- template: role-audit-reader-receipts -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "ReadReceipts", "Effect": "Allow",
   "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"],
   "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>/receipts/*"},
  {"Sid": "ListReceipts", "Effect": "Allow", "Action": "s3:ListBucket",
   "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>",
   "Condition": {"StringLike": {"s3:prefix": ["receipts/*"]}}}
]}
```

## 4. Configuration

Operator commands only (`python -m nlw.ops.datasets`). No runtime container
needs, or is given, these settings.

| Setting | Value |
|---|---|
| `DATASET_DELETION_LOG` | `s3` |
| `DATASET_DELETION_LOG_BUCKET` | `<RECEIPT_BUCKET>` |
| `DATASET_STORAGE_BACKEND` and `DATASET_S3_*` | as for the dataset store; required (the log uses the same verified operator identity and must be in the same account and environment) |

Settings refuse: `s3` without the S3 dataset store; a bucket name outside the
pattern or longer than 61 characters; another environment's or account's
bucket; the dataset bucket or the Restic bucket. The local fake log stays
refused in staging and production.

## 5. What is enforced where

| Property | Enforced by |
|---|---|
| A receipt is never overwritten | `If-None-Match: *` in code; `DenyUnconditionalCreate`; Object Lock keeps every version |
| A receipt is never deleted or its retention shortened by the operator or runtime | no grant; `NeverAlterReceipts`; `DenyRecordChangeExceptAuditAdmin`; Object Lock (COMPLIANCE: nobody) |
| No purge without a protected place for its receipt | `preflight` (Object Lock default retention) before deletion; `append` re-reads the stored version and requires retention |
| A receipt matches its purge | `verify` fetches by the ids the database expects; checksum; `check_receipt` (identity, digests, time) |
| Runtime roles cannot read or write receipts | `DenyDatasetRuntimeRoles`; they hold no grant |
| Only the operator role can create a receipt | `DenyReceiptWritesExceptOperator` (`ArnNotEquals` the exact `nlw-<ENV>-dataset-operator` role ARN), whatever any other principal's identity policy allows |
| One bad receipt cannot stop reconciliation or a restore | receipts are size-bounded (64 KiB) and depth-bounded (4) before parsing; anything else is `MALFORMED`/unreadable and reported, and the run continues |
| A listing is complete or refused | prefix echo, encoding, keys outside `receipts/`, truncation without a token, a repeated token and a 1000-page bound each refuse the listing before anything changes |
| A database restore cannot erase the evidence | the log is outside PostgreSQL and its backups; `reapply-receipts` re-applies it before runtimes start |

## 6. Residual risks (recorded, not hidden)

- **GOVERNANCE until O-5.** The audit administrator could, with a separately
  granted `s3:BypassGovernanceRetention`, remove a receipt early. COMPLIANCE
  (irreversible) is required before customer data.
- **The operator can write a receipt.** Only the operator role may (the
  bucket policy denies every other principal). A trusted operator could file a
  well-formed receipt for a live version; `reapply-receipts` would then move
  that version to DELETING during a restore. The operator can already request
  any deletion, so this grants no new power over data, but it is a path that
  does not go through the API. Receipts are attributable (the `operator`
  label, and `PutObject` data events once the trail covers this bucket; see
  below).
- **Objects that are not receipts** (a misfiled key under `receipts/`) are
  never read; `reconcile-receipts` and `reapply-receipts` report their count
  as `unexpected_objects` and exit 1 so an operator investigates. They cannot
  be removed during retention.
- **CloudTrail does not yet cover this bucket.** The reviewed trail
  (`dataset-s3-provisioning.md` §4) records data events for the dataset
  bucket only. Adding this bucket is a pinned-template change for the next
  provisioning review.
- **Receipt without event** (ADR-033 note 3) remains possible: the receipt is
  written before the purge transaction commits. `reconcile-receipts` lists
  such receipts; they are evidence of a deletion attempt, not a completed purge.

## 7. Verification (NOT RUN; part of a future authorized proof)

1. `python -m nlw.ops.datasets purge ...` on one synthetic DELETING version:
   the receipt object exists once, with `ObjectLockMode=GOVERNANCE` and a
   retain-until date `<RECEIPT_RETENTION_DAYS>` ahead.
2. As the operator: `DeleteObject`, `PutObjectRetention` and an unconditional
   `PutObject` on that key are each `AccessDenied`.
3. As the dataset API role: `GetObject` on that key is `AccessDenied`.
4. `tombstone` succeeds; `reconcile-receipts` reports nothing unverified.
5. Restore drill: restore a snapshot taken before step 1 into a locked
   database, run `reapply-receipts`, and confirm the version is DELETING with
   `RESTORE_REAPPLY` evidence before any runtime starts.
