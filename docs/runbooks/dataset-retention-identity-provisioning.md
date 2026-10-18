# Unattended retention identity provisioning (NOT RUN — templates for review)

Status: **a plan, not a record.** Nothing here has been created and no AWS
account has been contacted. Owner decision (2026-10-18,
[ADR-038](../adr/ADR-038-o6-dormant-staging-configuration.md)): the daily
retention timer runs as its own narrow role, `nlw-<ENV>-dataset-retention`,
never the human operator role. Creating it needs a provisioning review and
**explicit owner authorization**.

Every JSON block is marked `<!-- template: name -->`;
`tests/unit/test_retention_identity_templates.py` pins each one.

## What the role may and may not do

- **May:** list `versions/` and in-progress uploads in the dataset bucket,
  delete object versions and abort uploads there (the purge), write receipts
  once and read and list them (the receipt log, `preflight` and
  `reconcile-receipts`), confirm the receipt bucket's Object Lock, and read its
  own role's path.
- **May not:** read or write any dataset object's content (no `GetObject`, no
  `PutObject`, no KMS at all: deleting needs no key and receipts are SSE-S3),
  touch the restore bucket, the trail, the audit bucket or another
  environment, change any configuration, delete or shorten a receipt, or run a
  tombstone, a restore step, a dispatch or offboarding (the application
  refuses those under `DATASET_OPERATOR_IDENTITY=retention`).
- **Trust:** only the host's bootstrap role (the instance profile), with the
  fixed session name `nlw-<ENV>-retention`, refreshed every 15 min by
  `nlw-aws-credentials` into `/run/nlw/aws/retention/credentials` (1 h).

## 1. Trust and grants

<!-- template: trust-retention -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "BootstrapWithRetentionSessionName", "Effect": "Allow",
   "Principal": {"AWS": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap"},
   "Action": "sts:AssumeRole",
   "Condition": {"StringEquals": {"sts:RoleSessionName": "nlw-<ENV>-retention"}}}
]}
```

<!-- template: role-dataset-retention -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "ListVersionsBounded", "Effect": "Allow",
   "Action": ["s3:ListBucket", "s3:ListBucketVersions"],
   "Resource": "arn:aws:s3:::<BUCKET>",
   "Condition": {"StringLike": {"s3:prefix": ["versions/*"]}}},
  {"Sid": "ListInProgressUploads", "Effect": "Allow",
   "Action": "s3:ListBucketMultipartUploads",
   "Resource": "arn:aws:s3:::<BUCKET>"},
  {"Sid": "PurgeOnly", "Effect": "Allow",
   "Action": ["s3:DeleteObjectVersion", "s3:AbortMultipartUpload"],
   "Resource": "arn:aws:s3:::<BUCKET>/versions/*"},
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
  {"Sid": "ConfirmOwnRolePath", "Effect": "Allow", "Action": "iam:GetRole",
   "Resource": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-retention"},
  {"Sid": "NeverReadOrWriteDatasetContent", "Effect": "Deny",
   "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes", "s3:PutObject"],
   "Resource": "arn:aws:s3:::<BUCKET>/*"},
  {"Sid": "NeverUseAKey", "Effect": "Deny", "Action": "kms:*", "Resource": "*"},
  {"Sid": "NeverAlterReceiptsOrConfiguration", "Effect": "Deny",
   "Action": ["s3:DeleteObject", "s3:BypassGovernanceRetention", "s3:PutObjectRetention",
              "s3:PutObjectLegalHold", "s3:PutBucket*", "s3:DeleteBucket*",
              "s3:PutLifecycleConfiguration", "s3:PutEncryptionConfiguration",
              "s3:PutBucketVersioning", "s3:PutBucketObjectLockConfiguration",
              "s3:PutReplicationConfiguration", "backup:*", "iam:PassRole"],
   "Resource": "*"},
  {"Sid": "NeverReceiptVersionDelete", "Effect": "Deny", "Action": "s3:DeleteObjectVersion",
   "Resource": "arn:aws:s3:::<RECEIPT_BUCKET>/*"},
  {"Sid": "NeverOtherEnvironment", "Effect": "Deny", "Action": ["s3:*", "kms:*"],
   "Resource": ["arn:aws:s3:::nlw-<OTHER_ENV>-*", "arn:aws:s3:::nlw-<OTHER_ENV>-*/*"]},
  {"Sid": "NeverRestoreBucket", "Effect": "Deny", "Action": "s3:*",
   "Resource": ["arn:aws:s3:::<RESTORE_BUCKET>", "arn:aws:s3:::<RESTORE_BUCKET>/*"]},
  {"Sid": "NeverTouchAudit", "Effect": "Deny",
   "Action": ["cloudtrail:*", "s3:*", "kms:*"],
   "Resource": ["<TRAIL_ARN>", "arn:aws:s3:::<AUDIT_BUCKET>", "arn:aws:s3:::<AUDIT_BUCKET>/*", "<AUDIT_KEY_ARN>"]}
]}
```

## 2. The two reviewed documents that must name the role

`PutBucketPolicy` and `PutRolePolicy` replace a document whole, so these are
**complete** documents, applied where the retention role exists, in place of
the D6 originals. Each is the reviewed D6 document **byte for byte except one
list**, which also names `nlw-<ENV>-dataset-retention` (pinned). The D6 proof
account, which has no retention role, keeps the originals.

- the dataset bucket policy: `DenyDeleteExceptOperator` also excepts the
  retention role (the only principal besides the operator that may delete);
- the bootstrap role: it may assume (and is denied every role but) the api,
  ingest and retention roles.

The receipt bucket policy (O-3) names the retention role directly in
`DenyReceiptWritesExceptOperator` ([deletion-receipt-log-provisioning](deletion-receipt-log-provisioning.md)).

<!-- template: dataset-bucket-policy-with-retention -->
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "DenyNonTLS", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
     "Resource": ["arn:aws:s3:::<BUCKET>", "arn:aws:s3:::<BUCKET>/*"],
     "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
    {"Sid": "DenyOutsideAccount", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
     "Resource": ["arn:aws:s3:::<BUCKET>", "arn:aws:s3:::<BUCKET>/*"],
     "Condition": {"StringNotEquals": {"aws:PrincipalAccount": "<ACCOUNT>"}}},
    {"Sid": "DenyOtherEnvironmentRoles", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
     "Resource": ["arn:aws:s3:::<BUCKET>", "arn:aws:s3:::<BUCKET>/*"],
     "Condition": {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/nlw-<OTHER_ENV>-*"}}},
    {"Sid": "DenyUnconditionalCreate", "Effect": "Deny", "Principal": "*",
     "Action": "s3:PutObject", "Resource": "arn:aws:s3:::<BUCKET>/versions/*",
     "Condition": {"Null": {"s3:if-none-match": "true"},
                   "Bool": {"s3:ObjectCreationOperation": "true"}}},
    {"Sid": "DenyMissingSseAlgorithmHeader", "Effect": "Deny", "Principal": "*",
     "Action": "s3:PutObject", "Resource": "arn:aws:s3:::<BUCKET>/*",
     "Condition": {"Null": {"s3:x-amz-server-side-encryption": "true"}}},
    {"Sid": "DenyMissingSseKmsKeyHeader", "Effect": "Deny", "Principal": "*",
     "Action": "s3:PutObject", "Resource": "arn:aws:s3:::<BUCKET>/*",
     "Condition": {"Null": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "true"}}},
    {"Sid": "DenyWrongSseAlgorithm", "Effect": "Deny", "Principal": "*",
     "Action": "s3:PutObject", "Resource": "arn:aws:s3:::<BUCKET>/*",
     "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}}},
    {"Sid": "DenyWrongSseKmsKey", "Effect": "Deny", "Principal": "*",
     "Action": "s3:PutObject", "Resource": "arn:aws:s3:::<BUCKET>/*",
     "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "<KEY_ARN>"}}},
    {"Sid": "DenyServerSideCopy", "Effect": "Deny", "Principal": "*",
     "Action": "s3:PutObject", "Resource": "arn:aws:s3:::<BUCKET>/*",
     "Condition": {"Null": {"s3:x-amz-copy-source": "false"}}},
    {"Sid": "DenyDeleteExceptOperator", "Effect": "Deny", "Principal": "*",
     "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
     "Resource": "arn:aws:s3:::<BUCKET>/*",
     "Condition": {"ArnNotEquals": {"aws:PrincipalArn": [
        "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator",
        "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-retention"]}}},
    {"Sid": "DenyBucketConfigExceptAdmin", "Effect": "Deny", "Principal": "*",
     "Action": ["s3:PutBucket*", "s3:DeleteBucket*", "s3:PutLifecycleConfiguration",
                "s3:PutEncryptionConfiguration", "s3:PutBucketVersioning",
                "s3:PutReplicationConfiguration", "s3:PutInventoryConfiguration",
                "s3:PutAnalyticsConfiguration", "s3:PutMetricsConfiguration",
                "s3:PutIntelligentTieringConfiguration", "s3:PutAccelerateConfiguration"],
     "Resource": "arn:aws:s3:::<BUCKET>",
     "Condition": {"ArnNotEquals": {"aws:PrincipalArn": [
        "arn:aws:iam::<ACCOUNT>:role/<ADMIN_ROLE>"]}}}
  ]
}
```

<!-- template: role-bootstrap-with-retention -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "AssumeRuntimeRolesOnly", "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": [
    "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api",
    "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest",
    "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-retention"]},
  {"Sid": "NeverAssumeAnyOtherRole", "Effect": "Deny", "Action": "sts:AssumeRole", "NotResource": [
    "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api",
    "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest",
    "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-retention"]},
  {"Sid": "NeverDataPlane", "Effect": "Deny", "Action": ["s3:*", "kms:*"], "Resource": "*"},
  {"Sid": "NeverPassOrAttachDatasetRoles", "Effect": "Deny",
   "Action": ["iam:PassRole", "ec2:AssociateIamInstanceProfile", "ec2:ReplaceIamInstanceProfileAssociation"],
   "Resource": "*"},
  {"Sid": "NeverTouchAudit", "Effect": "Deny",
   "Action": ["cloudtrail:*", "s3:*", "kms:*"],
   "Resource": ["<TRAIL_ARN>", "arn:aws:s3:::<AUDIT_BUCKET>", "arn:aws:s3:::<AUDIT_BUCKET>/*", "<AUDIT_KEY_ARN>"]},
  {"Sid": "NeverAlterAnyTrail", "Effect": "Deny",
   "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
              "cloudtrail:PutEventSelectors", "cloudtrail:PutInsightSelectors"],
   "Resource": "*"}
]}
```

## 3. Verification (NOT RUN; part of the authorized proof)

1. As the retention role: `GetObject` and `PutObject` on a dataset object, any
   KMS call, and any call on the restore bucket are `AccessDenied`.
2. `retention-sweep` on a synthetic due version purges it with a receipt;
   `reconcile-receipts` verifies it.
3. `python -m nlw.ops.datasets tombstone ...` and `restore-objects` under
   `DATASET_OPERATOR_IDENTITY=retention` are refused by the application.
4. The role's CloudTrail data events name only `DeleteObjectVersion`,
   `AbortMultipartUpload`, listings and receipt calls.
