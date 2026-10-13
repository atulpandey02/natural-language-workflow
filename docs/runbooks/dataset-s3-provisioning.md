# Dataset S3 provisioning (NOT RUN — templates for review)

Status: **a plan, not a record.** Nothing here has been created. These
templates implement [ADR-033](../adr/ADR-033-s3-dataset-object-storage.md)
(D1–D6 approved on 2026-10-09). Creating or changing any real AWS resource
requires a separate provisioning review and **explicit owner authorization**
(D6). The isolated proof in §7 runs only after that, following the ordered,
NOT RUN procedure in [dataset-s3-d6-proof.md](dataset-s3-d6-proof.md).

Every JSON block is marked `<!-- template: name -->`.
`tests/unit/test_dataset_s3_provisioning_templates.py` parses each one and
asserts the security invariants below.

## Placeholders

None of these may be replaced by a real value in this repository.

| Placeholder | Meaning |
|---|---|
| `<ENV>` | `staging` or `production`. Every resource is created once per environment and never shared. |
| `<OTHER_ENV>` | the other environment, which is explicitly denied |
| `<ACCOUNT>` | AWS account id |
| `<BUCKET>` | dataset bucket, `nlw-<ENV>-datasets-<ACCOUNT>-us-east-1[-<suffix>]` |
| `<KEY_ARN>` | the environment's customer-managed KMS key for dataset objects |
| `<AUDIT_BUCKET>` | CloudTrail log bucket, `nlw-<ENV>-dataset-audit-<ACCOUNT>-us-east-1[-<suffix>]`. It is separate from `<BUCKET>` and from the Restic bucket. |
| `<AUDIT_KEY_ARN>` | a separate customer-managed KMS key for the audit logs |
| `<TRAIL_ARN>` | `arn:aws:cloudtrail:us-east-1:<ACCOUNT>:trail/nlw-<ENV>-dataset-data-events` |
| `<ADMIN_ROLE>` | the role that manages the dataset bucket and key. For D6 it is the provisioner's Identity Center permission-set role (§3.7), given as its name with path |
| `<AUDIT_ADMIN_ROLE>` | the role that administers the trail, audit bucket and audit key. It is not an application or operator role. |
| `<AUDIT_READER_ROLE>` | a human, read-only role for audit review |
| `<HUMAN_PRINCIPAL_ARNS>` | the IAM Identity Center permission-set role ARNs allowed to assume one human role (§3.5). Each human role has its own list; the operator and audit-administrator lists must not overlap. |
| `<PROOF_BOUNDARY_ARN>` | the customer-managed policy `nlw-<ENV>-d6-proof-boundary` (§3.6) in the dedicated proof account, attached as the permissions boundary of every principal the D6 proof uses and every role it creates. Its companion, `nlw-<ENV>-d6-proof-denies`, has a fixed name in the same account |
| `<AUDIT_EXPIRY_DAYS>` | `<AUDIT_RETENTION_DAYS>` + 1, the lifecycle expiry of audit log objects |
| `<AUDIT_RETENTION_DAYS>` | audit-log retention. It is set with O-3 and O-5, and must outlast any deletion-evidence need. |

## 1. Dataset KMS key (one per environment)

- Symmetric, customer-managed, alias `alias/nlw-<ENV>-datasets`, with
  automatic rotation on.
- Tagged `nlw-env=<ENV>`; the role denies in §3 rely on the tag.
- **Key policy** (the complete policy; there is no `kms:*` statement for the
  account root):
  - `<ADMIN_ROLE>` and the account root may **manage** the key, never use it.
    The root statement keeps the key recoverable if `<ADMIN_ROLE>` is lost;
    it grants no cryptographic action, so delegated IAM administrators cannot
    decrypt through it.
  - Only the API role may generate data keys. The ingest and operator roles
    may only decrypt.
  - Every use is through S3 in us-east-1, for this bucket.

<!-- template: dataset-kms-key-statements -->
```json
[
  {"Sid": "AdministerNeverUse", "Effect": "Allow",
   "Principal": {"AWS": ["arn:aws:iam::<ACCOUNT>:root", "arn:aws:iam::<ACCOUNT>:role/<ADMIN_ROLE>"]},
   "Action": ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:PutKeyPolicy", "kms:GetKeyRotationStatus",
              "kms:EnableKeyRotation", "kms:ListGrants", "kms:ListResourceTags", "kms:TagResource",
              "kms:UntagResource", "kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias", "kms:EnableKey",
              "kms:DisableKey", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"],
   "Resource": "*"},
  {"Sid": "ApiEncryptViaS3ForThisBucketOnly", "Effect": "Allow",
   "Principal": {"AWS": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api"},
   "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
   "Resource": "*",
   "Condition": {"StringEquals": {
     "kms:ViaService": "s3.us-east-1.amazonaws.com",
     "kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::<BUCKET>"}}},
  {"Sid": "ReadersDecryptViaS3ForThisBucketOnly", "Effect": "Allow",
   "Principal": {"AWS": [
     "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest",
     "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator"]},
   "Action": "kms:Decrypt",
   "Resource": "*",
   "Condition": {"StringEquals": {
     "kms:ViaService": "s3.us-east-1.amazonaws.com",
     "kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::<BUCKET>"}}}
]
```

- **Why the split matters.** A key-policy statement that names a role is
  sufficient on its own within the account; the role policy is not consulted
  for that grant. The earlier single statement therefore let the ingest and
  operator roles generate data keys even though their role policies did not.
- The encryption context is the bucket ARN because S3 Bucket Keys are enabled.
- The bootstrap role is absent from the key policy.

## 2. Dataset bucket

**Settings:**

- us-east-1;
- Block Public Access: all four settings on;
- Object Ownership: `BucketOwnerEnforced`;
- Versioning: enabled;
- Object Lock: off;
- default encryption: SSE-KMS with `<KEY_ARN>` and Bucket Key enabled.

The default encryption is defence in depth only. **The bucket policy below
refuses any creation request that does not itself name SSE-KMS and this key**,
so no request ever relies on the default.

**Lifecycle rule:**

<!-- template: dataset-bucket-lifecycle -->
```json
{"Rules": [{
  "ID": "abort-incomplete-multipart",
  "Status": "Enabled",
  "Filter": {"Prefix": "versions/"},
  "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}
}]}
```

Noncurrent-version expiry is deliberately absent until O-5. Lifecycle is never
the evidence for an individual deletion.

**Bucket policy** (explicit denies only; the role policies grant):

<!-- template: dataset-bucket-policy -->
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
        "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator"]}}},
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

### Encryption enforcement semantics

Four separate denies, all on `s3:PutObject` for every object in the bucket:

| Statement | Denies a creation request when |
|---|---|
| `DenyMissingSseAlgorithmHeader` | the `x-amz-server-side-encryption` header is **absent** |
| `DenyMissingSseKmsKeyHeader` | the `x-amz-server-side-encryption-aws-kms-key-id` header is **absent** |
| `DenyWrongSseAlgorithm` | the algorithm header is present and is not exactly `aws:kms` (refuses `AES256`, `aws:kms:dsse`, SSE-C) |
| `DenyWrongSseKmsKey` | the key header is present and is not exactly `<KEY_ARN>`. An alias, a bare key id or another key is refused; the application always sends the full ARN. |

- **Missing and wrong values are separate statements.** A missing header is
  denied by a `Null` check. A present but wrong header is denied by
  `StringNotEquals`, which matches only when the key is present.
- **No `…IfExists` operator is used.** The earlier template used
  `StringNotEqualsIfExists` in a Deny, which also denies when the key is
  absent. The behaviour was equally strict, but its prose wrongly said a
  headerless request would fall back to default encryption.
- **There are no exceptions.** A request that relies on the bucket default is
  denied.

The configuration denies name replication, inventory, analytics, metrics,
Intelligent-Tiering and acceleration explicitly: `s3:PutBucket*` does not
cover them, and replication or inventory would copy objects or their keys
elsewhere.

`DenyServerSideCopy` refuses `CopyObject` and `UploadPartCopy`. The
application never copies, and without this deny the API role could duplicate
one stored object under another key using its own read and write grants.

### Multipart uploads and conditional writes

- **Headers.** The application sends both encryption headers on
  `CreateMultipartUpload`, and on any `PutObject` or `CopyObject`.
  `UploadPart` and `CompleteMultipartUpload` do not carry SSE-KMS headers.
- **Unproven point.** These four statements follow AWS's documented
  "require SSE-KMS" pattern, a `Null` deny on `s3:PutObject`. The AWS pages
  reviewed on 2026-10-09 do **not** state explicitly how S3 evaluates these
  condition keys for `UploadPart` and `CompleteMultipartUpload`. That is
  therefore a **mandatory proof item** (§7, E-MPU).
- **If the proof shows part or completion requests are denied**, provisioning
  **stops**. No encryption exception is added. The design is revisited
  instead. The likely alternative, single-request `PutObject` uploads with
  both headers up to the 25 MB cap, is **an application change**: the store
  switches to multipart above 8 MiB (`PART_SIZE` in `nlw.storage.s3`). It
  needs its own code change, tests and review before the proof is re-run; it
  is not a documentation fallback.
- **`DenyUnconditionalCreate`** must refuse a plain `PutObject` and a
  `CompleteMultipartUpload` without `If-None-Match`. It must still allow
  `CreateMultipartUpload` and `UploadPart`, using the documented
  `s3:ObjectCreationOperation` semantics, and is proven in §7.

## 3. Roles (one set per environment)

Every role in this section also carries the **audit-protection deny** in §4.3.

### `nlw-<ENV>-dataset-bootstrap` (EC2 instance profile)

- **Permissions:** only `sts:AssumeRole` on exactly two ARNs.

<!-- template: role-bootstrap -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "AssumeRuntimeRolesOnly", "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": [
    "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api",
    "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest"]},
  {"Sid": "NeverAssumeAnyOtherRole", "Effect": "Deny", "Action": "sts:AssumeRole", "NotResource": [
    "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api",
    "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest"]},
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

- **Excluded:** no S3, no KMS, and never the operator role. These are
  explicit denies, so a broader policy attached by mistake cannot grant them.
- **Trust:** `trust-bootstrap` (§3.5), the EC2 service only.
- **Instance:** IMDSv2 required, with hop limit **1**.

### `nlw-<ENV>-dataset-api`

- **Trust:** only `nlw-<ENV>-dataset-bootstrap`, with `sts:RoleSessionName`
  conditioned to `nlw-<ENV>-api`.
- **Policy:**

<!-- template: role-api -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "CreateOnce", "Effect": "Allow",
   "Action": ["s3:PutObject", "s3:AbortMultipartUpload"],
   "Resource": "arn:aws:s3:::<BUCKET>/versions/*"},
  {"Sid": "RetryAndOrphanMetadata", "Effect": "Allow",
   "Action": ["s3:GetObject", "s3:GetObjectAttributes"],
   "Resource": "arn:aws:s3:::<BUCKET>/versions/*"},
  {"Sid": "Encrypt", "Effect": "Allow",
   "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": "<KEY_ARN>"},
  {"Sid": "NeverOtherEnvironment", "Effect": "Deny", "Action": ["s3:*", "kms:*"],
   "Resource": ["arn:aws:s3:::nlw-<OTHER_ENV>-*", "arn:aws:s3:::nlw-<OTHER_ENV>-*/*"]},
  {"Sid": "NeverOtherEnvironmentKeys", "Effect": "Deny", "Action": "kms:*",
   "Resource": "arn:aws:kms:us-east-1:<ACCOUNT>:key/*",
   "Condition": {"StringNotEquals": {"aws:ResourceTag/nlw-env": "<ENV>"}}},
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

- `s3:GetObject` is required by `HeadObject` and `GetObjectAttributes`. Code
  calls only those operations (ADR-033 note 1, accepted residual risk). Every
  such call is a CloudTrail data event (§4).
- There is no delete, no list, and nothing outside `versions/`.
- `NeverOtherEnvironment` denies every bucket of the other environment
  unconditionally. `NeverOtherEnvironmentKeys` relies on the KMS key tags
  (§1): a key without the tag is denied, which fails closed.
- **Trust:** `trust-api` (§3.5).

### `nlw-<ENV>-dataset-ingest`

- **Trust:** only `nlw-<ENV>-dataset-bootstrap`, with session name
  `nlw-<ENV>-ingest`.
- **Policy:**

<!-- template: role-ingest -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "ReadVersions", "Effect": "Allow", "Action": ["s3:GetObject"],
   "Resource": "arn:aws:s3:::<BUCKET>/versions/*"},
  {"Sid": "Decrypt", "Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "<KEY_ARN>"},
  {"Sid": "NeverOtherEnvironment", "Effect": "Deny", "Action": ["s3:*", "kms:*"],
   "Resource": ["arn:aws:s3:::nlw-<OTHER_ENV>-*", "arn:aws:s3:::nlw-<OTHER_ENV>-*/*"]},
  {"Sid": "NeverOtherEnvironmentKeys", "Effect": "Deny", "Action": "kms:*",
   "Resource": "arn:aws:kms:us-east-1:<ACCOUNT>:key/*",
   "Condition": {"StringNotEquals": {"aws:ResourceTag/nlw-env": "<ENV>"}}},
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

- IAM scope is the environment prefix. Exact-object access is enforced in the
  application (ADR-033 note 2). Every read is a CloudTrail data event (§4).
- **Trust:** `trust-ingest` (§3.5).

### `nlw-<ENV>-dataset-operator`

- **Trust:** `trust-human` (§3.5) with the operator's
  `<HUMAN_PRINCIPAL_ARNS>`. It is **not** the bootstrap role or any
  application role.
- **Policy:**

<!-- template: role-operator -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "ListVersionsBounded", "Effect": "Allow",
   "Action": ["s3:ListBucket", "s3:ListBucketVersions"],
   "Resource": "arn:aws:s3:::<BUCKET>",
   "Condition": {"StringLike": {"s3:prefix": ["versions/*"]}}},
  {"Sid": "ListInProgressUploads", "Effect": "Allow",
   "Action": "s3:ListBucketMultipartUploads",
   "Resource": "arn:aws:s3:::<BUCKET>"},
  {"Sid": "PurgeAndVerify", "Effect": "Allow",
   "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes",
              "s3:DeleteObjectVersion", "s3:AbortMultipartUpload"],
   "Resource": "arn:aws:s3:::<BUCKET>/versions/*"},
  {"Sid": "Decrypt", "Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "<KEY_ARN>"},
  {"Sid": "NeverOtherEnvironment", "Effect": "Deny", "Action": ["s3:*", "kms:*"],
   "Resource": ["arn:aws:s3:::nlw-<OTHER_ENV>-*", "arn:aws:s3:::nlw-<OTHER_ENV>-*/*"]},
  {"Sid": "NeverOtherEnvironmentKeys", "Effect": "Deny", "Action": "kms:*",
   "Resource": "arn:aws:kms:us-east-1:<ACCOUNT>:key/*",
   "Condition": {"StringNotEquals": {"aws:ResourceTag/nlw-env": "<ENV>"}}},
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

- `DeleteObjectVersion` is the only delete. A plain `DeleteObject` without a
  version id, which would only add a delete marker, is not granted.
- The operator purges dataset objects, never audit records. Audit review uses
  `<AUDIT_READER_ROLE>`.
- **Multipart listing is not prefix-bounded by IAM.** The AWS Service
  Authorization Reference (S3 actions table, checked 2026-10-12) lists **no**
  `s3:prefix` condition key for `s3:ListBucketMultipartUploads`, whose only
  resource is the bucket. Under the earlier template, which put it in the
  `s3:prefix`-conditioned statement, the condition could never match, so every
  `ListMultipartUploads` call would have been implicitly denied and purge
  verification would have failed. It is now its own statement on the exact
  bucket ARN, with no condition. What this adds, and what it does not:
  - the operator can list the **keys and upload ids of in-progress uploads
    anywhere in this bucket** (metadata only, no object bytes);
  - it can **abort** only under `versions/*`: `AbortMultipartUpload` is an
    object-resource action, so `PurgeAndVerify` still scopes it;
  - `s3:ListMultipartUploadParts` is **not** granted (no operator command
    lists parts), and no read, write or delete grant changes;
  - the prefix is enforced by the application: `S3BlobStore` aborts only
    uploads whose key lies inside the requested version or dataset prefix,
    ignores look-alike siblings, and refuses the whole listing, before any
    abort, on a key outside the requested prefix, a malformed or encoded key,
    `EncodingType`, a prefix echo that differs, bad pagination markers, a
    partial page, or more than 100 pages.

| Action | Resource type (AWS) | `s3:prefix` supported | Operator grant |
|---|---|---|---|
| `s3:ListBucketVersions` | bucket | yes | `versions/*` only (`ListVersionsBounded`) |
| `s3:ListBucketMultipartUploads` | bucket | **no** | whole bucket, filtered in code (`ListInProgressUploads`) |
| `s3:ListMultipartUploadParts` | object | no | not granted |
| `s3:AbortMultipartUpload` | object | no (resource-scoped) | `versions/*` (`PurgeAndVerify`) |
| `s3:DeleteObjectVersion` | object | no (resource-scoped) | `versions/*` (`PurgeAndVerify`), and the bucket policy denies every other principal |
- It is used only through reviewed operator commands:

| Command | Purpose |
|---|---|
| `purge` | Version-aware deletion of a `DELETING` version |
| `purge-rejected` | Bounded removal of rejected objects |
| `rejected-pending` | Lists rejected objects eligible for purge |
| `verify-objects` | Reconciles database keys with stored objects |

### `nlw-<ENV>-dataset-audit-admin` and `nlw-<ENV>-dataset-audit-reader`

These are the `<AUDIT_ADMIN_ROLE>` and `<AUDIT_READER_ROLE>` of this
environment. Neither is an application or operator role, and neither may touch
dataset objects or the dataset key. Both use `trust-human` (§3.5).

<!-- template: role-audit-admin -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "AdministerThisTrail", "Effect": "Allow",
   "Action": ["cloudtrail:CreateTrail", "cloudtrail:GetTrail", "cloudtrail:GetTrailStatus",
              "cloudtrail:DescribeTrails", "cloudtrail:GetEventSelectors", "cloudtrail:PutEventSelectors",
              "cloudtrail:StartLogging", "cloudtrail:StopLogging", "cloudtrail:UpdateTrail",
              "cloudtrail:DeleteTrail", "cloudtrail:AddTags", "cloudtrail:ListTags"],
   "Resource": "<TRAIL_ARN>"},
  {"Sid": "AdministerAuditBucket", "Effect": "Allow",
   "Action": ["s3:CreateBucket", "s3:ListBucket", "s3:ListBucketVersions",
              "s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:GetBucketAcl",
              "s3:GetBucketVersioning", "s3:PutBucketVersioning",
              "s3:GetEncryptionConfiguration", "s3:PutEncryptionConfiguration",
              "s3:GetLifecycleConfiguration", "s3:PutLifecycleConfiguration",
              "s3:GetBucketObjectLockConfiguration", "s3:PutBucketObjectLockConfiguration",
              "s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock",
              "s3:GetBucketOwnershipControls", "s3:PutBucketOwnershipControls",
              "s3:GetBucketTagging", "s3:PutBucketTagging", "s3:DeleteBucket"],
   "Resource": "arn:aws:s3:::<AUDIT_BUCKET>"},
  {"Sid": "CreateAuditKey", "Effect": "Allow", "Action": "kms:CreateKey",
   "Resource": "*",
   "Condition": {"StringEquals": {"aws:RequestTag/nlw-env": "<ENV>"}}},
  {"Sid": "TagOnlyUntaggedKeys", "Effect": "Allow", "Action": "kms:TagResource",
   "Resource": "*",
   "Condition": {"StringEquals": {"aws:RequestTag/nlw-env": "<ENV>"},
                 "Null": {"aws:ResourceTag/nlw-env": "true"}}},
  {"Sid": "AuditKeyAlias", "Effect": "Allow", "Action": "kms:CreateAlias",
   "Resource": "arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-dataset-audit"},
  {"Sid": "AdministerAuditKey", "Effect": "Allow",
   "Action": ["kms:CreateAlias", "kms:DescribeKey", "kms:GetKeyPolicy", "kms:PutKeyPolicy",
              "kms:EnableKeyRotation", "kms:GetKeyRotationStatus", "kms:ListGrants", "kms:ListResourceTags"],
   "Resource": "<AUDIT_KEY_ARN>"},
  {"Sid": "NeverTouchDatasets", "Effect": "Deny", "Action": ["s3:*", "kms:*"],
   "Resource": ["arn:aws:s3:::<BUCKET>", "arn:aws:s3:::<BUCKET>/*", "<KEY_ARN>"]},
  {"Sid": "NeverPassOrAttachDatasetRoles", "Effect": "Deny",
   "Action": ["iam:PassRole", "ec2:AssociateIamInstanceProfile", "ec2:ReplaceIamInstanceProfileAssociation"],
   "Resource": "*"}
]}
```

- The audit administrator never deletes or rewrites log objects: no
  `DeleteObject*`, `PutObject`, `PutObjectRetention` or
  `BypassGovernanceRetention` is granted. The audit bucket policy (§4.3)
  allows those actions only to this role so that retention can be corrected,
  which would need a separately reviewed policy change first.
- `TagOnlyUntaggedKeys` lets the audit administrator tag a key only while it
  has no `nlw-env` tag, which in practice means the key it is creating. It
  cannot re-tag another environment's key, which would defeat the runtime
  roles' `NeverOtherEnvironmentKeys` deny. How KMS evaluates
  `aws:ResourceTag` while `CreateKey` applies tags is not documented
  explicitly; P03-04 shows whether creation with tags succeeds.
- `NeverPassOrAttachDatasetRoles` (on every dataset and audit role): none of
  these identities may pass a role to a service or attach an instance
  profile. Who else in the account may do so is decision E12.
- `AdministerAuditKey` names the key ARN, which exists only after
  `CreateAuditKey`. The proof attaches this statement after the key is
  created. `AuditKeyAlias` is separate so that the alias can be created in
  the same step as the key: an alias is authorised by IAM on the alias ARN,
  which the key policy cannot grant.
- `kms:ListGrants` is granted so that P03-11 can show that the audit key has
  no grant; both key policies allow it to their administrators.

<!-- template: role-audit-reader -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "ReadAuditLogs", "Effect": "Allow", "Action": ["s3:GetObject"],
   "Resource": "arn:aws:s3:::<AUDIT_BUCKET>/dataset-data-events/*"},
  {"Sid": "LocateAuditBucket", "Effect": "Allow", "Action": "s3:GetBucketLocation",
   "Resource": "arn:aws:s3:::<AUDIT_BUCKET>"},
  {"Sid": "ListAuditLogs", "Effect": "Allow", "Action": ["s3:ListBucket"],
   "Resource": "arn:aws:s3:::<AUDIT_BUCKET>",
   "Condition": {"StringLike": {"s3:prefix": ["dataset-data-events/*"]}}},
  {"Sid": "DecryptAuditLogs", "Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "<AUDIT_KEY_ARN>"},
  {"Sid": "ValidateTrail", "Effect": "Allow",
   "Action": ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:ListPublicKeys"],
   "Resource": "*"},
  {"Sid": "NeverTouchDatasets", "Effect": "Deny", "Action": ["s3:*", "kms:*"],
   "Resource": ["arn:aws:s3:::<BUCKET>", "arn:aws:s3:::<BUCKET>/*", "<KEY_ARN>"]},
  {"Sid": "NeverPassOrAttachDatasetRoles", "Effect": "Deny",
   "Action": ["iam:PassRole", "ec2:AssociateIamInstanceProfile", "ec2:ReplaceIamInstanceProfileAssociation"],
   "Resource": "*"}
]}
```

- `LocateAuditBucket`: `aws cloudtrail validate-logs` (P13-01) calls
  `GetBucketLocation` on the log bucket before it reads digests. It is the
  reader's only bucket-level action besides the prefix-bounded listing.

### 3.5 Trust policies

IAM checks that a principal named in a trust policy exists. Every deny below
therefore names roles through a condition, never as a principal, so the deny
is valid before or after those roles exist.

<!-- template: trust-bootstrap -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "Ec2InstanceProfileOnly", "Effect": "Allow",
   "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
]}
```

<!-- template: trust-api -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "BootstrapWithApiSessionName", "Effect": "Allow",
   "Principal": {"AWS": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap"},
   "Action": "sts:AssumeRole",
   "Condition": {"StringEquals": {"sts:RoleSessionName": "nlw-<ENV>-api"}}}
]}
```

<!-- template: trust-ingest -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "BootstrapWithIngestSessionName", "Effect": "Allow",
   "Principal": {"AWS": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap"},
   "Action": "sts:AssumeRole",
   "Condition": {"StringEquals": {"sts:RoleSessionName": "nlw-<ENV>-ingest"}}}
]}
```

<!-- template: trust-human -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "NamedSsoPermissionSetRolesOnly", "Effect": "Allow",
   "Principal": {"AWS": "<HUMAN_PRINCIPAL_ARNS>"},
   "Action": "sts:AssumeRole",
   "Condition": {"StringLike": {"sts:RoleSessionName": "nlw-d6-*"}}},
  {"Sid": "DenyAnythingButIdentityCenter", "Effect": "Deny", "Principal": {"AWS": "*"},
   "Action": "sts:AssumeRole",
   "Condition": {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/aws-reserved/sso.amazonaws.com/*"}}},
  {"Sid": "DenyMachineRoles", "Effect": "Deny", "Principal": {"AWS": "*"},
   "Action": "sts:AssumeRole",
   "Condition": {"ArnLike": {"aws:PrincipalArn": [
     "arn:aws:iam::<ACCOUNT>:role/nlw-*-dataset-bootstrap",
     "arn:aws:iam::<ACCOUNT>:role/nlw-*-dataset-api",
     "arn:aws:iam::<ACCOUNT>:role/nlw-*-dataset-ingest"]}}}
]}
```

- **Short-lived humans only.** The human roles (operator, audit
  administrator, audit reader) trust only named IAM Identity Center
  permission-set roles. `DenyAnythingButIdentityCenter` refuses every other
  principal, including an IAM user with a long-term access key.
- **MFA.** Identity Center sessions reach these roles by role chaining, where
  `aws:MultiFactorAuthPresent` is generally absent, so this template does not
  test it, and **no policy in this package enforces MFA.** Whether a person
  must use MFA depends on Identity Center's sign-in settings, which IAM
  policy cannot see. The independent verifier attests that setting in the D6
  gate record (decision E15); neither the procedure nor the tests check it.
  It is residual risk R11.
- `DenyMachineRoles` is a second, name-based refusal of the bootstrap and
  runtime roles.
- `sts:RoleSessionName` must start with `nlw-d6-`, so every cached session
  carries the proof run's id (`nlw-d6-<PROOF_ID>-<role>`) and cleanup can
  remove exactly that run's sessions.

### 3.6 Proof identities, boundaries and the deny policy (dedicated proof account, mandatory for D6)

**Where D6 runs.** D6 runs only in a **dedicated AWS proof account**
(decision E14). It holds no production or staging resource, and its id is
none of the staging or production account ids. **The account limits the
blast radius:** none of the proof's principals is trusted in any other
account, so a mistake or misuse in the proof cannot reach another account's
resources. It does not replace least privilege inside the account, which the
policies below provide.

**Three separated functions (E9).** Each is a different Identity Center
permission set, used on its own machine (the procedure's persona sections):

| Function | Permission set | May | Never |
|---|---|---|---|
| **provisioner** | `<ADMIN_ROLE>` (§3.7 `permission-set-provisioner`) | create the six roles with their trust, exact inline policies and exact boundaries; create the dataset bucket, dataset key, proof instance and budget; read the account inventory; run simulations | read, write or delete any dataset object; touch the trail, the audit bucket, the audit key or its alias; assume any of the six roles; change any trust policy after creation; change or remove any boundary |
| **dataset operator** | operator (§3.7) | assume only `nlw-<ENV>-dataset-operator`, whose boundary allows only listing, reading and version-aware deletion under `versions/` | any IAM change, including to its own role; the trail, audit bucket, audit key or audit roles |
| **audit administrator / reader** | audit administrator and audit reader (§3.7) | assume only the audit-admin or audit-reader role; confirm the audit resources are absent; the reader may also read (never change) the six roles and the proof policies, to check the provisioner's work independently | any IAM change, including to its own roles; any dataset role, the dataset bucket or the dataset key |

**What is enforced, and what is not.**

- **Enforced by policy** (as written; AWS has not evaluated it): the
  operator and audit permission sets carry an explicit deny of every IAM
  write. The provisioner's permission set denies assuming any of the six
  roles, every dataset-object action, every CloudTrail change and every
  action on the audit bucket, audit key and audit alias. Every role the
  proof creates carries an exact boundary of its own (below), so a rewritten
  inline policy can never exceed what that role was reviewed to do. The
  provisioner cannot change a trust policy after creation
  (`UpdateAssumeRolePolicy` is not granted), cannot remove or replace a
  boundary, and can create a role only with that role's own boundary.
- **Not enforced, only attested:** that three **different people** hold the
  three functions. IAM sees permission-set roles, not people; who is assigned
  which permission set is an Identity Center setting that the gate record
  attests (E15). If one person holds two functions, the separation above
  still constrains each identity but no longer separates people.
- **Residual authority:** the account root user, the organization's
  management account and anyone who administers Identity Center or this
  account's IAM outside the proof can override all of it (review R13). The
  provisioner's IAM authority over the six roles is itself a residual risk
  (R14): it cannot use the roles, but it shapes them; the audit side checks
  its work independently (P03-15), and the account trail (E7) records every
  change.

**Policy layers.**

| Layer | Attached to | Holds |
|---|---|---|
| `proof-principal-boundary` (`nlw-<ENV>-d6-proof-boundary`) | the permissions boundary of the four permission sets | an **upper bound**: the actions the four permission sets use, on the proof's resources |
| `proof-principal-denies` (`nlw-<ENV>-d6-proof-denies`) | the only managed policy of each permission set | the explicit denies every proof identity carries |
| `boundary-<role>` (`nlw-<ENV>-d6-boundary-<role>`), six policies | the permissions boundary of exactly that role | that role's reviewed Allows, and nothing else |
| permission-set inline policies (§3.7) | each permission set | its exact Allows, and the denies that separate the functions |

**Upper bounds, and where they are broader by resource.** A boundary only
limits; it never grants. The permission-set boundary's actions are exactly
the union of the four permission sets' actions. It is broader than that
union **by resource** only where the resource is not known until the run,
and each case is listed: S3 bucket names (matched by the proof-name pattern
`…-us-east-1-d6*`), KMS key ids (`key/*` in `us-east-1` of this account;
key policies and the `nlw-purpose` tag decide who administers which key), EC2
resources (`arn:aws:ec2:us-east-1:<ACCOUNT>:*`), and IAM reads and
simulations (`role/*`, `user/*`, because E12 names arbitrary principals of
the account). Each role boundary copies its role's Allows with exactly those
substitutions and no others. The tests check both.

**The explicit denies** (`proof-principal-denies`), so that a policy widened
by mistake still cannot:

- create, update or delete a SAML or OIDC identity provider;
- assume any role but the five proof roles that are assumed;
- pass any role but the bootstrap role, or pass it to a service other than
  EC2;
- use Lambda, CodeBuild, CloudFormation, ECS, Step Functions, SSM (other
  than reading the one public AMI parameter), Session Manager channels,
  instance-profile association, or EC2 serial-console and Instance Connect
  tunnels;
- change an organization or account setting;
- create, version or attach a managed policy, create a user or access key,
  or put or remove a permissions boundary;
- create a role without its own reviewed boundary;
- change any Identity Center permission-set role or any proof policy;
- act on resources named or tagged for the other environment;
- act outside `us-east-1`, except for the global services IAM, STS, Budgets
  and Organizations.

<!-- template: proof-principal-boundary -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "D6NoResourceScope", "Effect": "Allow", "Action": ["cloudtrail:DescribeTrails", "ec2:DescribeAvailabilityZones", "ec2:DescribeInstanceStatus", "ec2:DescribeInstances", "ec2:DescribeTags", "ec2:DescribeVpcs", "iam:ListAccountAliases", "iam:ListRoles", "iam:SimulateCustomPolicy", "kms:CreateKey", "kms:ListAliases", "organizations:DescribeOrganization", "s3:ListAllMyBuckets", "tag:GetResources"], "Resource": "*"},
  {"Sid": "D6ReadPrincipals", "Effect": "Allow", "Action": ["iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:ListRoleTags", "iam:SimulatePrincipalPolicy"], "Resource": ["arn:aws:iam::<ACCOUNT>:role/*", "arn:aws:iam::<ACCOUNT>:user/*"]},
  {"Sid": "D6ReadTheProofPolicies", "Effect": "Allow", "Action": ["iam:GetPolicy", "iam:GetPolicyVersion"], "Resource": ["<PROOF_BOUNDARY_ARN>", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-proof-denies", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-bootstrap", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-api", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-ingest", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-operator", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-audit-admin", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-audit-reader"]},
  {"Sid": "D6TheSixRoles", "Effect": "Allow", "Action": ["iam:CreateRole", "iam:DeleteRole", "iam:DeleteRolePolicy", "iam:PutRolePolicy", "iam:TagRole", "sts:AssumeRole"], "Resource": ["arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-admin", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-reader"]},
  {"Sid": "D6TheBootstrapProfileAndRole", "Effect": "Allow", "Action": ["iam:AddRoleToInstanceProfile", "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile", "iam:GetInstanceProfile", "iam:ListInstanceProfileTags", "iam:PassRole", "iam:RemoveRoleFromInstanceProfile", "iam:TagInstanceProfile"], "Resource": ["arn:aws:iam::<ACCOUNT>:instance-profile/nlw-<ENV>-dataset-bootstrap", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap"]},
  {"Sid": "D6TheProofBuckets", "Effect": "Allow", "Action": ["s3:CreateBucket", "s3:DeleteBucket", "s3:GetBucketOwnershipControls", "s3:GetBucketPolicy", "s3:GetBucketPublicAccessBlock", "s3:GetBucketTagging", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration", "s3:GetLifecycleConfiguration", "s3:ListBucket", "s3:ListBucketVersions", "s3:PutBucketOwnershipControls", "s3:PutBucketPolicy", "s3:PutBucketPublicAccessBlock", "s3:PutBucketTagging", "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration", "s3:PutLifecycleConfiguration"], "Resource": ["arn:aws:s3:::nlw-<ENV>-datasets-<ACCOUNT>-us-east-1-d6*", "arn:aws:s3:::nlw-<ENV>-dataset-audit-<ACCOUNT>-us-east-1-d6*"]},
  {"Sid": "D6TheProofKeys", "Effect": "Allow", "Action": ["kms:CreateAlias", "kms:DescribeKey", "kms:DisableKey", "kms:EnableKeyRotation", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListGrants", "kms:ListResourceTags", "kms:ScheduleKeyDeletion", "kms:TagResource"], "Resource": ["arn:aws:kms:us-east-1:<ACCOUNT>:key/*", "arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-datasets"]},
  {"Sid": "D6TheDataEventTrail", "Effect": "Allow", "Action": "cloudtrail:GetTrail", "Resource": "<TRAIL_ARN>"},
  {"Sid": "D6TheProofInstance", "Effect": "Allow", "Action": ["ec2:AuthorizeSecurityGroupIngress", "ec2:CreateSecurityGroup", "ec2:CreateTags", "ec2:DeleteSecurityGroup", "ec2:RunInstances", "ec2:TerminateInstances"], "Resource": ["arn:aws:ec2:us-east-1:<ACCOUNT>:*", "arn:aws:ec2:us-east-1::image/*"]},
  {"Sid": "D6SshKeyToTheProofInstance", "Effect": "Allow", "Action": "ec2-instance-connect:SendSSHPublicKey", "Resource": "arn:aws:ec2:us-east-1:<ACCOUNT>:instance/*", "Condition": {"StringEquals": {"aws:ResourceTag/nlw-env": "<ENV>", "ec2:osuser": "ec2-user"}}},
  {"Sid": "D6TheAmiParameter", "Effect": "Allow", "Action": "ssm:GetParameters", "Resource": "arn:aws:ssm:us-east-1::parameter/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64"},
  {"Sid": "D6TheProofBudget", "Effect": "Allow", "Action": ["budgets:ModifyBudget", "budgets:ViewBudget"], "Resource": "arn:aws:budgets::<ACCOUNT>:budget/nlw-<ENV>-dataset-proof-*"}
]}
```

<!-- template: proof-principal-denies -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "NeverOtherEnvironmentNames", "Effect": "Deny", "Action": "*", "Resource": ["arn:aws:s3:::nlw-<OTHER_ENV>-*", "arn:aws:s3:::nlw-<OTHER_ENV>-*/*", "arn:aws:iam::<ACCOUNT>:role/nlw-<OTHER_ENV>-*", "arn:aws:iam::<ACCOUNT>:instance-profile/nlw-<OTHER_ENV>-*", "arn:aws:cloudtrail:*:<ACCOUNT>:trail/nlw-<OTHER_ENV>-*", "arn:aws:kms:*:<ACCOUNT>:alias/nlw-<OTHER_ENV>-*"]},
  {"Sid": "NeverOtherEnvironmentKeys", "Effect": "Deny", "Action": "kms:*", "Resource": "*", "Condition": {"StringEquals": {"aws:ResourceTag/nlw-env": "<OTHER_ENV>"}}},
  {"Sid": "NeverEscalate", "Effect": "Deny", "Action": ["iam:AttachGroupPolicy", "iam:AttachRolePolicy", "iam:AttachUserPolicy", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:CreateUser", "iam:DeletePolicy", "iam:DeletePolicyVersion", "iam:DeleteRolePermissionsBoundary", "iam:DeleteUserPermissionsBoundary", "iam:PutGroupPolicy", "iam:PutRolePermissionsBoundary", "iam:PutUserPermissionsBoundary", "iam:PutUserPolicy", "iam:SetDefaultPolicyVersion", "iam:UpdateLoginProfile", "identitystore:*", "sso-directory:*", "sso:*"], "Resource": "*"},
  {"Sid": "NeverIdentityProviders", "Effect": "Deny", "Action": ["iam:*OpenIDConnectProvider*", "iam:*SAMLProvider"], "Resource": "*"},
  {"Sid": "NeverOrganizationOrAccountChanges", "Effect": "Deny", "Action": ["account:*", "organizations:Accept*", "organizations:Attach*", "organizations:Cancel*", "organizations:Close*", "organizations:Create*", "organizations:Decline*", "organizations:Delete*", "organizations:Deregister*", "organizations:Detach*", "organizations:Disable*", "organizations:Enable*", "organizations:Invite*", "organizations:Leave*", "organizations:Move*", "organizations:Put*", "organizations:Register*", "organizations:Remove*", "organizations:Tag*", "organizations:Untag*", "organizations:Update*"], "Resource": "*"},
  {"Sid": "NeverDirectKmsGrants", "Effect": "Deny", "Action": ["kms:CreateGrant", "kms:RetireGrant", "kms:RevokeGrant"], "Resource": "*", "Condition": {"Null": {"kms:ViaService": "true"}}},
  {"Sid": "AssumeOnlyTheProofRoles", "Effect": "Deny", "Action": ["sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity", "sts:GetFederationToken"], "NotResource": ["arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-admin", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-reader"]},
  {"Sid": "PassOnlyTheBootstrapRole", "Effect": "Deny", "Action": "iam:PassRole", "NotResource": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap"},
  {"Sid": "PassTheBootstrapRoleOnlyToEc2", "Effect": "Deny", "Action": "iam:PassRole", "Resource": "*", "Condition": {"Null": {"iam:PassedToService": "false"}, "StringNotEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}},
  {"Sid": "NeverIndirectExecution", "Effect": "Deny", "Action": ["cloudformation:*", "codebuild:*", "ec2-instance-connect:OpenTunnel", "ec2-instance-connect:SendSerialConsoleSSHPublicKey", "ec2:AssociateIamInstanceProfile", "ec2:ReplaceIamInstanceProfileAssociation", "ec2messages:*", "ecs:*", "lambda:*", "ssm-guiconnect:*", "ssmmessages:*", "states:*"], "Resource": "*"},
  {"Sid": "NeverSsmBeyondTheAmiParameter", "Effect": "Deny", "Action": "ssm:*", "NotResource": "arn:aws:ssm:us-east-1::parameter/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64"},
  {"Sid": "NeverChangeTheProofPrincipalsOrPolicies", "Effect": "Deny", "Action": ["iam:AttachRolePolicy", "iam:CreatePolicyVersion", "iam:DeletePolicy", "iam:DeletePolicyVersion", "iam:DeleteRole", "iam:DeleteRolePermissionsBoundary", "iam:DeleteRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePermissionsBoundary", "iam:PutRolePolicy", "iam:SetDefaultPolicyVersion", "iam:TagPolicy", "iam:TagRole", "iam:UntagPolicy", "iam:UntagRole", "iam:UpdateAssumeRolePolicy", "iam:UpdateRole"], "Resource": ["arn:aws:iam::<ACCOUNT>:role/aws-reserved/*", "<PROOF_BOUNDARY_ARN>", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-*"]},
  {"Sid": "CreatedRolesCarryTheirBoundary", "Effect": "Deny", "Action": "iam:CreateRole", "Resource": "*", "Condition": {"StringNotEquals": {"iam:PermissionsBoundary": ["arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-bootstrap", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-api", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-ingest", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-operator", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-audit-admin", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-audit-reader"]}}},
  {"Sid": "OnlyTheApprovedRegion", "Effect": "Deny", "NotAction": ["budgets:*", "iam:*", "organizations:*", "sts:*"], "Resource": "*", "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}}}
]}
```

- `NeverDirectKmsGrants` still allows grants that a service creates on the
  caller's behalf (for example EC2 for an encrypted volume). It refuses grants
  made directly, which would bypass the key policy. P03-11 and P03-15 check
  that both proof keys have no grant.
- `PassTheBootstrapRoleOnlyToEc2` denies passing the bootstrap role whenever
  `iam:PassedToService` is present and is not EC2. It does not deny when the
  key is absent, because `AddRoleToInstanceProfile` also checks
  `iam:PassRole` and whether that request carries the key is not documented
  (review I6). No `…IfExists` operator is used.
- `NeverIdentityProviders` uses action wildcards: `iam:*SAMLProvider` covers
  creating, updating, deleting and tagging a SAML provider, and
  `iam:*OpenIDConnectProvider*` the same for OIDC, including client ids and
  thumbprints.

**Role boundaries.** One per created role, each exactly that role's Allows
(§3) with run-time names replaced by the proof patterns above. The
provisioner may create a role only with its own boundary
(`CreateRoleWithItsBoundary` statements in §3.7, and
`CreatedRolesCarryTheirBoundary` in the deny policy), and nobody in the proof
may change or remove a boundary.

<!-- template: boundary-bootstrap -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "AssumeRuntimeRolesOnly", "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": ["arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest"]}
]}
```

<!-- template: boundary-api -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "CreateOnce", "Effect": "Allow", "Action": ["s3:PutObject", "s3:AbortMultipartUpload"], "Resource": "arn:aws:s3:::nlw-<ENV>-datasets-<ACCOUNT>-us-east-1-d6*/versions/*"},
  {"Sid": "RetryAndOrphanMetadata", "Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectAttributes"], "Resource": "arn:aws:s3:::nlw-<ENV>-datasets-<ACCOUNT>-us-east-1-d6*/versions/*"},
  {"Sid": "Encrypt", "Effect": "Allow", "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": "arn:aws:kms:us-east-1:<ACCOUNT>:key/*"}
]}
```

<!-- template: boundary-ingest -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "ReadVersions", "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::nlw-<ENV>-datasets-<ACCOUNT>-us-east-1-d6*/versions/*"},
  {"Sid": "Decrypt", "Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "arn:aws:kms:us-east-1:<ACCOUNT>:key/*"}
]}
```

<!-- template: boundary-operator -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "ListVersionsBounded", "Effect": "Allow", "Action": ["s3:ListBucket", "s3:ListBucketVersions"], "Resource": "arn:aws:s3:::nlw-<ENV>-datasets-<ACCOUNT>-us-east-1-d6*", "Condition": {"StringLike": {"s3:prefix": ["versions/*"]}}},
  {"Sid": "ListInProgressUploads", "Effect": "Allow", "Action": "s3:ListBucketMultipartUploads", "Resource": "arn:aws:s3:::nlw-<ENV>-datasets-<ACCOUNT>-us-east-1-d6*"},
  {"Sid": "PurgeAndVerify", "Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes", "s3:DeleteObjectVersion", "s3:AbortMultipartUpload"], "Resource": "arn:aws:s3:::nlw-<ENV>-datasets-<ACCOUNT>-us-east-1-d6*/versions/*"},
  {"Sid": "Decrypt", "Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "arn:aws:kms:us-east-1:<ACCOUNT>:key/*"}
]}
```

<!-- template: boundary-audit-admin -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "AdministerThisTrail", "Effect": "Allow", "Action": ["cloudtrail:CreateTrail", "cloudtrail:GetTrail", "cloudtrail:GetTrailStatus", "cloudtrail:DescribeTrails", "cloudtrail:GetEventSelectors", "cloudtrail:PutEventSelectors", "cloudtrail:StartLogging", "cloudtrail:StopLogging", "cloudtrail:UpdateTrail", "cloudtrail:DeleteTrail", "cloudtrail:AddTags", "cloudtrail:ListTags"], "Resource": "<TRAIL_ARN>"},
  {"Sid": "AdministerAuditBucket", "Effect": "Allow", "Action": ["s3:CreateBucket", "s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:GetBucketAcl", "s3:GetBucketVersioning", "s3:PutBucketVersioning", "s3:GetEncryptionConfiguration", "s3:PutEncryptionConfiguration", "s3:GetLifecycleConfiguration", "s3:PutLifecycleConfiguration", "s3:GetBucketObjectLockConfiguration", "s3:PutBucketObjectLockConfiguration", "s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock", "s3:GetBucketOwnershipControls", "s3:PutBucketOwnershipControls", "s3:GetBucketTagging", "s3:PutBucketTagging", "s3:DeleteBucket"], "Resource": "arn:aws:s3:::nlw-<ENV>-dataset-audit-<ACCOUNT>-us-east-1-d6*"},
  {"Sid": "CreateAuditKey", "Effect": "Allow", "Action": "kms:CreateKey", "Resource": "*", "Condition": {"StringEquals": {"aws:RequestTag/nlw-env": "<ENV>"}}},
  {"Sid": "TagOnlyUntaggedKeys", "Effect": "Allow", "Action": "kms:TagResource", "Resource": "*", "Condition": {"StringEquals": {"aws:RequestTag/nlw-env": "<ENV>"}, "Null": {"aws:ResourceTag/nlw-env": "true"}}},
  {"Sid": "AuditKeyAlias", "Effect": "Allow", "Action": "kms:CreateAlias", "Resource": "arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-dataset-audit"},
  {"Sid": "AdministerAuditKey", "Effect": "Allow", "Action": ["kms:CreateAlias", "kms:DescribeKey", "kms:GetKeyPolicy", "kms:PutKeyPolicy", "kms:EnableKeyRotation", "kms:GetKeyRotationStatus", "kms:ListGrants", "kms:ListResourceTags"], "Resource": "arn:aws:kms:us-east-1:<ACCOUNT>:key/*"}
]}
```

<!-- template: boundary-audit-reader -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "ReadAuditLogs", "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::nlw-<ENV>-dataset-audit-<ACCOUNT>-us-east-1-d6*/dataset-data-events/*"},
  {"Sid": "LocateAuditBucket", "Effect": "Allow", "Action": "s3:GetBucketLocation", "Resource": "arn:aws:s3:::nlw-<ENV>-dataset-audit-<ACCOUNT>-us-east-1-d6*"},
  {"Sid": "ListAuditLogs", "Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": "arn:aws:s3:::nlw-<ENV>-dataset-audit-<ACCOUNT>-us-east-1-d6*", "Condition": {"StringLike": {"s3:prefix": ["dataset-data-events/*"]}}},
  {"Sid": "DecryptAuditLogs", "Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "arn:aws:kms:us-east-1:<ACCOUNT>:key/*"},
  {"Sid": "ValidateTrail", "Effect": "Allow", "Action": ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:ListPublicKeys"], "Resource": "*"}
]}
```

### 3.7 Identity Center permission sets for D6 (dedicated proof account)

Four permission sets. Each has **exactly** its inline policy below, exactly
one managed policy, `nlw-<ENV>-d6-proof-denies` (§3.6), and the proof
boundary as its permissions boundary. Identity Center provisions each as a
role named `AWSReservedSSO_<permission set>_<hash>` with the inline policy
named `AwsSSOInlinePolicy`; P01-02 and P03-15 read all of this back and
compare it with the templates. Sessions last one hour or less (E11).

| Permission set | Function and machine (E9) | Held by |
|---|---|---|
| provisioner (`<ADMIN_ROLE>`) | provisioner; the provisioner machine | the provisioner |
| operator | dataset operator; the operator machine | the operator, a different person |
| audit administrator | audit; the audit machine | the audit administrator, a third person |
| audit reader | audit; the audit machine | the audit administrator or a fourth person, never the provisioner or the operator |

- **The provisioner never uses a proof role.** `NeverUseTheProofRoles`
  denies it `sts:AssumeRole` on all six; `NeverDatasetObjects` denies every
  object action in the dataset bucket; it holds nothing on the trail, the
  audit bucket, the audit key or its alias. It has no
  `iam:UpdateAssumeRolePolicy`, so a trust policy cannot change after
  creation, and it may create each role only with that role's boundary.
- **The operator and audit sets change no IAM at all.** `NeverChangeIam`
  denies every IAM write (`Add*`, `Attach*`, `Create*`, `Delete*`, `Put*`,
  `Update*`, `PassRole` and the rest) on every resource, including their own
  roles.
- **The audit reader verifies, read-only.** `VerifyTheProofPrincipals` and
  `ReadTheProofPolicies` let the audit side read the six roles, the four
  permission-set roles and the proof policies, so P03-15 checks the
  provisioner's work with an identity the provisioner does not hold.
- **Keys are separated by tag.** The provisioner may create only a key tagged
  `nlw-purpose=dataset`, tag only an untagged key, and administer only keys
  tagged `dataset`. The audit-admin role tags the audit key
  `nlw-purpose=audit` when it creates it (P03-04). How KMS evaluates
  `aws:ResourceTag` while `CreateKey` applies tags is the same open question
  as `TagOnlyUntaggedKeys` (§3); P03-02 and P03-04 show it.

<!-- template: permission-set-provisioner -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "ReadTheAccountInventory", "Effect": "Allow", "Action": ["cloudtrail:DescribeTrails", "ec2:DescribeAvailabilityZones", "ec2:DescribeInstanceStatus", "ec2:DescribeInstances", "ec2:DescribeTags", "ec2:DescribeVpcs", "iam:ListAccountAliases", "iam:ListRoles", "iam:SimulateCustomPolicy", "kms:ListAliases", "organizations:DescribeOrganization", "s3:ListAllMyBuckets", "tag:GetResources"], "Resource": "*"},
  {"Sid": "InspectTheProofPrincipals", "Effect": "Allow", "Action": ["iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:ListRoleTags"], "Resource": ["arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-admin", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-reader", "arn:aws:iam::<ACCOUNT>:role/aws-reserved/sso.amazonaws.com/*"]},
  {"Sid": "SimulateThisAccountsPrincipals", "Effect": "Allow", "Action": "iam:SimulatePrincipalPolicy", "Resource": ["arn:aws:iam::<ACCOUNT>:role/*", "arn:aws:iam::<ACCOUNT>:user/*"]},
  {"Sid": "ReadTheProofPolicies", "Effect": "Allow", "Action": ["iam:GetPolicy", "iam:GetPolicyVersion"], "Resource": ["<PROOF_BOUNDARY_ARN>", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-proof-denies", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-bootstrap", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-api", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-ingest", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-operator", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-audit-admin", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-audit-reader"]},
  {"Sid": "CreateBootstrapWithItsBoundary", "Effect": "Allow", "Action": "iam:CreateRole", "Resource": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap", "Condition": {"StringEquals": {"iam:PermissionsBoundary": "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-bootstrap"}}},
  {"Sid": "CreateApiWithItsBoundary", "Effect": "Allow", "Action": "iam:CreateRole", "Resource": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api", "Condition": {"StringEquals": {"iam:PermissionsBoundary": "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-api"}}},
  {"Sid": "CreateIngestWithItsBoundary", "Effect": "Allow", "Action": "iam:CreateRole", "Resource": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest", "Condition": {"StringEquals": {"iam:PermissionsBoundary": "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-ingest"}}},
  {"Sid": "CreateOperatorWithItsBoundary", "Effect": "Allow", "Action": "iam:CreateRole", "Resource": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator", "Condition": {"StringEquals": {"iam:PermissionsBoundary": "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-operator"}}},
  {"Sid": "CreateAuditAdminWithItsBoundary", "Effect": "Allow", "Action": "iam:CreateRole", "Resource": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-admin", "Condition": {"StringEquals": {"iam:PermissionsBoundary": "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-audit-admin"}}},
  {"Sid": "CreateAuditReaderWithItsBoundary", "Effect": "Allow", "Action": "iam:CreateRole", "Resource": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-reader", "Condition": {"StringEquals": {"iam:PermissionsBoundary": "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-audit-reader"}}},
  {"Sid": "ConfigureTheSixRoles", "Effect": "Allow", "Action": ["iam:PutRolePolicy", "iam:TagRole"], "Resource": ["arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-admin", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-reader"]},
  {"Sid": "RemoveTheDatasetRoles", "Effect": "Allow", "Action": ["iam:DeleteRole", "iam:DeleteRolePolicy"], "Resource": ["arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator"]},
  {"Sid": "TheBootstrapInstanceProfile", "Effect": "Allow", "Action": ["iam:AddRoleToInstanceProfile", "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile", "iam:GetInstanceProfile", "iam:ListInstanceProfileTags", "iam:RemoveRoleFromInstanceProfile", "iam:TagInstanceProfile"], "Resource": "arn:aws:iam::<ACCOUNT>:instance-profile/nlw-<ENV>-dataset-bootstrap"},
  {"Sid": "PassOnlyTheBootstrapRole", "Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap"},
  {"Sid": "PassTheBootstrapRoleOnlyToEc2", "Effect": "Deny", "Action": "iam:PassRole", "Resource": "*", "Condition": {"Null": {"iam:PassedToService": "false"}, "StringNotEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}},
  {"Sid": "AdministerTheDatasetBucket", "Effect": "Allow", "Action": ["s3:CreateBucket", "s3:DeleteBucket", "s3:GetBucketOwnershipControls", "s3:GetBucketPolicy", "s3:GetBucketPublicAccessBlock", "s3:GetBucketTagging", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration", "s3:GetLifecycleConfiguration", "s3:ListBucket", "s3:ListBucketVersions", "s3:PutBucketOwnershipControls", "s3:PutBucketPolicy", "s3:PutBucketPublicAccessBlock", "s3:PutBucketTagging", "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration", "s3:PutLifecycleConfiguration"], "Resource": "arn:aws:s3:::nlw-<ENV>-datasets-<ACCOUNT>-us-east-1-d6*"},
  {"Sid": "CreateOnlyDatasetKeys", "Effect": "Allow", "Action": "kms:CreateKey", "Resource": "*", "Condition": {"StringEquals": {"aws:RequestTag/nlw-env": "<ENV>", "aws:RequestTag/nlw-purpose": "dataset"}}},
  {"Sid": "TagOnlyNewDatasetKeys", "Effect": "Allow", "Action": "kms:TagResource", "Resource": "arn:aws:kms:us-east-1:<ACCOUNT>:key/*", "Condition": {"StringEquals": {"aws:RequestTag/nlw-purpose": "dataset"}, "Null": {"aws:ResourceTag/nlw-purpose": "true"}}},
  {"Sid": "AdministerOnlyDatasetKeys", "Effect": "Allow", "Action": ["kms:CreateAlias", "kms:DescribeKey", "kms:DisableKey", "kms:EnableKeyRotation", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListGrants", "kms:ListResourceTags", "kms:ScheduleKeyDeletion"], "Resource": "arn:aws:kms:us-east-1:<ACCOUNT>:key/*", "Condition": {"StringEquals": {"aws:ResourceTag/nlw-purpose": "dataset"}}},
  {"Sid": "TheDatasetKeyAlias", "Effect": "Allow", "Action": "kms:CreateAlias", "Resource": "arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-datasets"},
  {"Sid": "LaunchTheProofInstance", "Effect": "Allow", "Action": ["ec2:CreateSecurityGroup", "ec2:RunInstances"], "Resource": ["arn:aws:ec2:us-east-1:<ACCOUNT>:*", "arn:aws:ec2:us-east-1::image/*"]},
  {"Sid": "TagOnlyAtLaunch", "Effect": "Allow", "Action": "ec2:CreateTags", "Resource": ["arn:aws:ec2:us-east-1:<ACCOUNT>:instance/*", "arn:aws:ec2:us-east-1:<ACCOUNT>:security-group/*"], "Condition": {"StringEquals": {"ec2:CreateAction": ["RunInstances", "CreateSecurityGroup"]}}},
  {"Sid": "ChangeOnlyTheTaggedProofInstance", "Effect": "Allow", "Action": ["ec2:AuthorizeSecurityGroupIngress", "ec2:DeleteSecurityGroup", "ec2:TerminateInstances"], "Resource": ["arn:aws:ec2:us-east-1:<ACCOUNT>:instance/*", "arn:aws:ec2:us-east-1:<ACCOUNT>:security-group/*"], "Condition": {"StringEquals": {"aws:ResourceTag/nlw-env": "<ENV>"}}},
  {"Sid": "SshKeyToTheProofInstanceOnly", "Effect": "Allow", "Action": "ec2-instance-connect:SendSSHPublicKey", "Resource": "arn:aws:ec2:us-east-1:<ACCOUNT>:instance/*", "Condition": {"StringEquals": {"aws:ResourceTag/nlw-env": "<ENV>", "ec2:osuser": "ec2-user"}}},
  {"Sid": "ReadTheAmiParameter", "Effect": "Allow", "Action": "ssm:GetParameters", "Resource": "arn:aws:ssm:us-east-1::parameter/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64"},
  {"Sid": "TheProofBudget", "Effect": "Allow", "Action": ["budgets:ModifyBudget", "budgets:ViewBudget"], "Resource": "arn:aws:budgets::<ACCOUNT>:budget/nlw-<ENV>-dataset-proof-*"},
  {"Sid": "NeverUseTheProofRoles", "Effect": "Deny", "Action": "sts:AssumeRole", "Resource": ["arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-admin", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-reader"]},
  {"Sid": "NeverDatasetObjects", "Effect": "Deny", "Action": ["s3:AbortMultipartUpload", "s3:BypassGovernanceRetention", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:GetObject", "s3:GetObjectAttributes", "s3:GetObjectVersion", "s3:PutObject", "s3:PutObjectLegalHold", "s3:PutObjectRetention", "s3:RestoreObject"], "Resource": "arn:aws:s3:::nlw-<ENV>-datasets-<ACCOUNT>-us-east-1-d6*/*"},
  {"Sid": "NeverAlterAnyTrail", "Effect": "Deny", "Action": ["cloudtrail:AddTags", "cloudtrail:CreateTrail", "cloudtrail:DeleteTrail", "cloudtrail:PutEventSelectors", "cloudtrail:PutInsightSelectors", "cloudtrail:RemoveTags", "cloudtrail:StartLogging", "cloudtrail:StopLogging", "cloudtrail:UpdateTrail"], "Resource": "*"},
  {"Sid": "NeverTheAuditBucketOrAlias", "Effect": "Deny", "Action": ["kms:*", "s3:*"], "Resource": ["arn:aws:s3:::nlw-<ENV>-dataset-audit-<ACCOUNT>-us-east-1-d6*", "arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-dataset-audit"]},
  {"Sid": "NeverAuditKeys", "Effect": "Deny", "Action": "kms:*", "Resource": "*", "Condition": {"StringEquals": {"aws:ResourceTag/nlw-purpose": "audit"}}}
]}
```

<!-- template: permission-set-operator -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "AssumeOnlyTheOperatorRole", "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator", "Condition": {"StringLike": {"sts:RoleSessionName": "nlw-d6-*-operator"}}},
  {"Sid": "NeverChangeIam", "Effect": "Deny", "Action": ["iam:Add*", "iam:Attach*", "iam:Change*", "iam:Create*", "iam:Deactivate*", "iam:Delete*", "iam:Detach*", "iam:Enable*", "iam:PassRole", "iam:Put*", "iam:Remove*", "iam:Reset*", "iam:Resync*", "iam:Set*", "iam:Tag*", "iam:Untag*", "iam:Update*", "iam:Upload*"], "Resource": "*"},
  {"Sid": "NeverAlterAnyTrail", "Effect": "Deny", "Action": ["cloudtrail:AddTags", "cloudtrail:CreateTrail", "cloudtrail:DeleteTrail", "cloudtrail:PutEventSelectors", "cloudtrail:PutInsightSelectors", "cloudtrail:RemoveTags", "cloudtrail:StartLogging", "cloudtrail:StopLogging", "cloudtrail:UpdateTrail"], "Resource": "*"},
  {"Sid": "NeverTheAuditRolesBucketOrAlias", "Effect": "Deny", "Action": ["kms:*", "s3:*", "sts:AssumeRole"], "Resource": ["arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-admin", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-reader", "arn:aws:s3:::nlw-<ENV>-dataset-audit-<ACCOUNT>-us-east-1-d6*", "arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-dataset-audit"]},
  {"Sid": "NeverAuditKeys", "Effect": "Deny", "Action": "kms:*", "Resource": "*", "Condition": {"StringEquals": {"aws:ResourceTag/nlw-purpose": "audit"}}}
]}
```

<!-- template: permission-set-audit-admin -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "AssumeOnlyTheAuditAdminRole", "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-admin", "Condition": {"StringLike": {"sts:RoleSessionName": "nlw-d6-*-audit-admin"}}},
  {"Sid": "ConfirmTheAuditResourcesAreAbsent", "Effect": "Allow", "Action": ["cloudtrail:GetTrail", "kms:DescribeKey", "s3:ListBucket"], "Resource": ["<TRAIL_ARN>", "arn:aws:kms:us-east-1:<ACCOUNT>:key/*", "arn:aws:s3:::nlw-<ENV>-dataset-audit-<ACCOUNT>-us-east-1-d6*"]},
  {"Sid": "NeverChangeIam", "Effect": "Deny", "Action": ["iam:Add*", "iam:Attach*", "iam:Change*", "iam:Create*", "iam:Deactivate*", "iam:Delete*", "iam:Detach*", "iam:Enable*", "iam:PassRole", "iam:Put*", "iam:Remove*", "iam:Reset*", "iam:Resync*", "iam:Set*", "iam:Tag*", "iam:Untag*", "iam:Update*", "iam:Upload*"], "Resource": "*"},
  {"Sid": "NeverTheDatasetRolesBucketOrAlias", "Effect": "Deny", "Action": ["kms:*", "s3:*", "sts:AssumeRole"], "Resource": ["arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator", "arn:aws:iam::<ACCOUNT>:instance-profile/nlw-<ENV>-dataset-bootstrap", "arn:aws:s3:::nlw-<ENV>-datasets-<ACCOUNT>-us-east-1-d6*", "arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-datasets"]},
  {"Sid": "NeverDatasetKeys", "Effect": "Deny", "Action": "kms:*", "Resource": "*", "Condition": {"StringEquals": {"aws:ResourceTag/nlw-purpose": "dataset"}}}
]}
```

<!-- template: permission-set-audit-reader -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "AssumeOnlyTheAuditReaderRole", "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-reader", "Condition": {"StringLike": {"sts:RoleSessionName": "nlw-d6-*-audit-reader"}}},
  {"Sid": "VerifyTheProofPrincipals", "Effect": "Allow", "Action": ["iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:ListRoleTags"], "Resource": ["arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-admin", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-reader", "arn:aws:iam::<ACCOUNT>:role/aws-reserved/sso.amazonaws.com/*"]},
  {"Sid": "ReadTheProofPolicies", "Effect": "Allow", "Action": ["iam:GetPolicy", "iam:GetPolicyVersion"], "Resource": ["<PROOF_BOUNDARY_ARN>", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-proof-denies", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-bootstrap", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-api", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-ingest", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-operator", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-audit-admin", "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-boundary-audit-reader"]},
  {"Sid": "NeverChangeIam", "Effect": "Deny", "Action": ["iam:Add*", "iam:Attach*", "iam:Change*", "iam:Create*", "iam:Deactivate*", "iam:Delete*", "iam:Detach*", "iam:Enable*", "iam:PassRole", "iam:Put*", "iam:Remove*", "iam:Reset*", "iam:Resync*", "iam:Set*", "iam:Tag*", "iam:Untag*", "iam:Update*", "iam:Upload*"], "Resource": "*"},
  {"Sid": "NeverTheDatasetRolesBucketOrAlias", "Effect": "Deny", "Action": ["kms:*", "s3:*", "sts:AssumeRole"], "Resource": ["arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest", "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator", "arn:aws:iam::<ACCOUNT>:instance-profile/nlw-<ENV>-dataset-bootstrap", "arn:aws:s3:::nlw-<ENV>-datasets-<ACCOUNT>-us-east-1-d6*", "arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-datasets"]},
  {"Sid": "NeverDatasetKeys", "Effect": "Deny", "Action": "kms:*", "Resource": "*", "Condition": {"StringEquals": {"aws:ResourceTag/nlw-purpose": "dataset"}}}
]}
```

## 4. CloudTrail object-data audit (one trail per environment)

ADR-033 relies on these records for every API metadata request, every ingest
read, every write and every purge.

### 4.1 Trail

- **Name and region:** `nlw-<ENV>-dataset-data-events`, single-region
  (us-east-1, where the bucket lives).
- **Delivery:** to `<AUDIT_BUCKET>` under the prefix `dataset-data-events`.
- **Encryption:** SSE-KMS with `<AUDIT_KEY_ARN>`.
- **Log file validation:** on (digest files).
- **Global service events:** excluded.

**Event scope.** Data events only, for **object-level read and write in this
environment's dataset bucket only**. There is no `readOnly` filter, so reads,
including `HeadObject`, `GetObject` and `GetObjectAttributes`, and writes,
including the multipart calls, `DeleteObjectVersion` and
`AbortMultipartUpload`, are all recorded.

<!-- template: trail-advanced-event-selectors -->
```json
[{
  "Name": "nlw-<ENV>-dataset-object-reads-and-writes",
  "FieldSelectors": [
    {"Field": "eventCategory", "Equals": ["Data"]},
    {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
    {"Field": "resources.ARN", "StartsWith": ["arn:aws:s3:::<BUCKET>/"]}
  ]
}]
```

**Bucket-level reads are an open question.** `ListBucket` and
`ListBucketVersions` act on the bucket ARN, which does not start with
`arn:aws:s3:::<BUCKET>/`. Whether this selector records them is not stated
clearly enough in AWS documentation to rely on, and this repository does not
guess a different selector shape. P13 records whether the operator's listing
appears; decision E13 decides what happens if it does not.

Management events, such as bucket-policy, KMS and IAM changes, are **not** in
this trail. **Assumption:** an account- or organization-level management-event
trail already exists and is protected the same way. This must be confirmed in
the provisioning review.

### 4.2 Audit KMS key (separate from the dataset key)

- Alias `alias/nlw-<ENV>-dataset-audit`, with rotation on.
- `<AUDIT_ADMIN_ROLE>` administers the key.
- No dataset application or operator role is in this key policy.
- No statement grants `ScheduleKeyDeletion`, so the key cannot be scheduled
  for deletion **without first changing its key policy**. The account root
  and IAM administrators delegated through the root statement keep the
  authority to make that change (`kms:PutKeyPolicy`); the account's
  management-event trail (decision E7) must record it. Deleting the key would
  make every retained audit record unreadable, so it must outlive the logs it
  protects.

<!-- template: audit-kms-key-statements -->
```json
[
  {"Sid": "AdministerNeverUse", "Effect": "Allow",
   "Principal": {"AWS": ["arn:aws:iam::<ACCOUNT>:root", "arn:aws:iam::<ACCOUNT>:role/<AUDIT_ADMIN_ROLE>"]},
   "Action": ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:PutKeyPolicy", "kms:GetKeyRotationStatus",
              "kms:EnableKeyRotation", "kms:ListGrants", "kms:ListResourceTags", "kms:TagResource",
              "kms:UntagResource", "kms:CreateAlias", "kms:UpdateAlias", "kms:EnableKey", "kms:DisableKey"],
   "Resource": "*"},
  {"Sid": "CloudTrailEncryptThisTrailOnly", "Effect": "Allow",
   "Principal": {"Service": "cloudtrail.amazonaws.com"},
   "Action": "kms:GenerateDataKey*", "Resource": "*",
   "Condition": {
     "StringEquals": {"aws:SourceArn": "<TRAIL_ARN>", "aws:SourceAccount": "<ACCOUNT>"},
     "StringLike": {"kms:EncryptionContext:aws:cloudtrail:arn": "<TRAIL_ARN>"}}},
  {"Sid": "CloudTrailDescribeKey", "Effect": "Allow",
   "Principal": {"Service": "cloudtrail.amazonaws.com"},
   "Action": "kms:DescribeKey", "Resource": "*",
   "Condition": {"StringEquals": {"aws:SourceArn": "<TRAIL_ARN>", "aws:SourceAccount": "<ACCOUNT>"}}},
  {"Sid": "AuditReadersDecrypt", "Effect": "Allow",
   "Principal": {"AWS": "arn:aws:iam::<ACCOUNT>:role/<AUDIT_READER_ROLE>"},
   "Action": "kms:Decrypt", "Resource": "*",
   "Condition": {"StringEquals": {"kms:EncryptionContext:aws:cloudtrail:arn": "<TRAIL_ARN>"}}}
]
```

### 4.3 Audit bucket

**Settings:**

- us-east-1;
- Block Public Access: all four settings on;
- `BucketOwnerEnforced`;
- Versioning: on;
- default encryption: SSE-KMS with `<AUDIT_KEY_ARN>`;
- **Bucket Key off.** CloudTrail's per-object `aws:cloudtrail:arn` encryption
  context is what the decrypt condition above checks.

**Object Lock:** enabled at creation, with default retention **GOVERNANCE**
for `<AUDIT_RETENTION_DAYS>` days.

- **COMPLIANCE mode** is stronger but irreversible. Choosing it is an owner
  decision for the provisioning review.
- **Expiry:** a lifecycle rule expires current and noncurrent log objects only
  after the retention period:

<!-- template: audit-bucket-lifecycle -->
```json
{"Rules": [{
  "ID": "expire-after-retention",
  "Status": "Enabled",
  "Filter": {"Prefix": "dataset-data-events/"},
  "Expiration": {"Days": "<AUDIT_EXPIRY_DAYS>"},
  "NoncurrentVersionExpiration": {"NoncurrentDays": 1}
}]}
```

  `<AUDIT_EXPIRY_DAYS>` is `<AUDIT_RETENTION_DAYS>` plus one, so no log
  object expires while Object Lock still protects it. It is quoted only so the
  template parses; rendering replaces the quoted placeholder with a number.

**Independence from dataset deletion:**

- the audit bucket is a separate bucket, with a separate key and a separate
  administrator;
- no dataset purge, lifecycle rule or operator command touches it;
- deleting dataset objects never deletes their audit records.

**Bucket policy:**

- CloudTrail delivery with confused-deputy protection;
- TLS only;
- no deletion, retention bypass or configuration change except by the audit
  administrator;
- no access at all for dataset runtime, bootstrap or operator roles.

<!-- template: audit-bucket-policy -->
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "CloudTrailAclCheck", "Effect": "Allow",
     "Principal": {"Service": "cloudtrail.amazonaws.com"},
     "Action": "s3:GetBucketAcl", "Resource": "arn:aws:s3:::<AUDIT_BUCKET>",
     "Condition": {"StringEquals": {"aws:SourceArn": "<TRAIL_ARN>", "aws:SourceAccount": "<ACCOUNT>"}}},
    {"Sid": "CloudTrailWriteThisTrailOnly", "Effect": "Allow",
     "Principal": {"Service": "cloudtrail.amazonaws.com"},
     "Action": "s3:PutObject",
     "Resource": "arn:aws:s3:::<AUDIT_BUCKET>/dataset-data-events/AWSLogs/<ACCOUNT>/*",
     "Condition": {"StringEquals": {
        "s3:x-amz-acl": "bucket-owner-full-control",
        "aws:SourceArn": "<TRAIL_ARN>", "aws:SourceAccount": "<ACCOUNT>"}}},
    {"Sid": "DenyNonTLS", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
     "Resource": ["arn:aws:s3:::<AUDIT_BUCKET>", "arn:aws:s3:::<AUDIT_BUCKET>/*"],
     "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
    {"Sid": "DenyDatasetRoles", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
     "Resource": ["arn:aws:s3:::<AUDIT_BUCKET>", "arn:aws:s3:::<AUDIT_BUCKET>/*"],
     "Condition": {"ArnLike": {"aws:PrincipalArn": [
        "arn:aws:iam::<ACCOUNT>:role/nlw-*-dataset-api",
        "arn:aws:iam::<ACCOUNT>:role/nlw-*-dataset-ingest",
        "arn:aws:iam::<ACCOUNT>:role/nlw-*-dataset-bootstrap",
        "arn:aws:iam::<ACCOUNT>:role/nlw-*-dataset-operator"]}}},
    {"Sid": "DenyRecordDeletionExceptAuditAdmin", "Effect": "Deny", "Principal": "*",
     "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention",
                "s3:PutObjectRetention", "s3:PutObjectLegalHold"],
     "Resource": "arn:aws:s3:::<AUDIT_BUCKET>/*",
     "Condition": {"ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/<AUDIT_ADMIN_ROLE>"}}},
    {"Sid": "DenyBucketConfigExceptAuditAdmin", "Effect": "Deny", "Principal": "*",
     "Action": ["s3:PutBucket*", "s3:DeleteBucket*", "s3:PutLifecycleConfiguration",
                "s3:PutEncryptionConfiguration", "s3:PutBucketVersioning",
                "s3:PutBucketObjectLockConfiguration",
                "s3:PutReplicationConfiguration", "s3:PutInventoryConfiguration",
                "s3:PutAnalyticsConfiguration", "s3:PutMetricsConfiguration",
                "s3:PutIntelligentTieringConfiguration", "s3:PutAccelerateConfiguration"],
     "Resource": "arn:aws:s3:::<AUDIT_BUCKET>",
     "Condition": {"ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/<AUDIT_ADMIN_ROLE>"}}}
  ]
}
```

**Protection of the records:**

- The dataset API, ingest, bootstrap and operator roles hold **no** CloudTrail
  permission. Each also carries explicit denies (§3) on the trail, the audit
  bucket and the audit key, and on stopping, deleting or re-scoping any trail.
- The audit bucket policy denies them independently.
- Object Lock stops log deletion within retention, even by the audit
  administrator in COMPLIANCE mode.
- Log file validation exposes any edit.

**Event identification.** Each data event carries:

- `userIdentity.type = AssumedRole`;
- `userIdentity.sessionContext.sessionIssuer.arn` = the role ARN, for example
  `…:role/nlw-<ENV>-dataset-api`;
- the session name, such as `nlw-<ENV>-api`;
- the object ARN in `resources[]`;
- `eventName`, for example `HeadObject`, `GetObjectAttributes` or `GetObject`;
- `errorCode` on a denied request.

**Retention assumptions:**

- `<AUDIT_RETENTION_DAYS>` is undecided. It is set with O-3 and O-5, and must
  cover the longest period for which deletion evidence or access review may be
  needed.
- CloudTrail data events are billed per event. This is acceptable at pilot
  volume, and should be reviewed when uploads are enabled (O-6).

## 5. Per-container credentials (single Compose host; built with O-6)

This is an explicitly documented single-host design. On ECS or EKS it is
replaced by task or pod identities.

### The refresher

- **What it is:** a root-owned systemd service and timer. It runs every 15 min,
  and on failure retries with backoff.
- **What it does:** it assumes **only** `nlw-<ENV>-dataset-api` and
  `nlw-<ENV>-dataset-ingest`, with a 1 h duration and fixed session names.
- **Where it writes:**
  - `/run/nlw/aws/api/credentials` and `/run/nlw/aws/ingest/credentials`;
  - separate directories on tmpfs, each `0700`;
  - files `0400`, owned by the container uid.
- **How it writes:** atomically. It writes a temp file in the same directory,
  `fsync`s it and `rename`s it, then removes the previous file. It never logs
  credential values; logs carry the role ARN, expiry and result only.
- **File format.** The application (`nlw.storage.s3_credentials`) reads a
  standard shared-credentials file, profile `[default]`, holding:
  - the three standard fields of a temporary credential (access key id,
    secret key and session token);
  - one non-standard field, `x_nlw_expiration`, an ISO-8601 UTC expiry such as
    `2026-10-09T15:00:00Z`.

  - A file without a session token, or without `x_nlw_expiration`, is refused
    as static.
  - A file expiring within 5 min is refused.
  - A file readable by group or others is refused.

### Mounts

- The API container mounts only `/run/nlw/aws/api`, read-only.
- The ingest container mounts only `/run/nlw/aws/ingest`, read-only.
- The dispatcher, worker, scheduler and web containers get **no** AWS mount.

### Container configuration

- The container sets `AWS_SHARED_CREDENTIALS_FILE` and
  `AWS_EC2_METADATA_DISABLED=true`.
- The application pins the SDK credential chain to that file and **never**
  falls back to environment variables or IMDS.

### Startup check (fail closed)

The container refuses to start when:

- the file is missing or unreadable;
- the credentials are expired or expire in under 5 min;
- `sts:GetCallerIdentity` returns a role other than the expected
  `nlw-<ENV>-dataset-<service>`.

At startup it logs the effective role ARN and account, never a credential.

### IMDS block, verified

- **Two layers:** IMDSv2 with hop limit 1, and a host firewall rule dropping
  `169.254.169.254` from Docker bridges.
- **Proof:** a deployment check runs a metadata request **inside every
  application container** (api, ingest, ingest-dispatch, worker, scheduler,
  web) and requires failure.

### Alerts

- refresh failure;
- credentials expiring within 15 min: `NlwDatasetS3CredentialsExpiring`, on
  `nlw_dataset_s3_credentials_expiry_timestamp_seconds - time() < 900` for
  5 m. The gauge is the absolute expiry recorded at the last file read, so the
  alert fires even when a stopped refresher means the process never re-reads
  the file;
- the startup identity check failing.

## 6. Rejected-object purge (D2, provisional 7 days)

**Cadence:** at least weekly, the operator runs:

1. `python -m nlw.ops.datasets rejected-pending [--limit N] [--metrics-file PATH]`
   (ids, ages and aggregate counts; writes the node-exporter textfile with
   `nlw_dataset_rejected_retained` and
   `nlw_dataset_rejected_oldest_age_seconds`);
2. `python -m nlw.ops.datasets purge-rejected --operator <name> --dry-run`;
3. `python -m nlw.ops.datasets purge-rejected --operator <name> [--limit N]`.

`purge-rejected` moves each version `REJECTED` to `DELETING` (an operator
event with reason `REJECTED_RETENTION`), then runs the same verified,
version-aware purge as a deletion request. The tombstone follows as usual.
Both commands:

- work in bounded, oldest-first batches;
- refuse while the recovery lock is active or unreadable;
- are idempotent on re-run.

**Monitoring:**

- `NlwDatasetRejectedRetainedTooLong` fires past 7 days. It is dormant until
  O-6, when it is wired with the other dataset alerts.
- **The 7-day value is provisional** (development and staging). It is not the
  customer retention policy, which O-5 sets.

## 7. Isolated real-AWS proof (D6; only after explicit authorization)

This runs in a **dedicated AWS proof account** (decision E14), against
staging-named resources it creates there, never in a staging or production
account. The ordered commands, stop conditions, evidence rules and cleanup
are in [dataset-s3-d6-proof.md](dataset-s3-d6-proof.md); the items below are
the pass criteria it implements. Every item must pass. A failure stops provisioning, with no
exceptions added.

1. **Role isolation:**
   - **bootstrap:** can assume only the API and ingest roles, not the
     operator role, and has no S3 or KMS access;
   - **API:** can create once, but gets 412 on overwrite, is denied writes
     without `If-None-Match`, is denied outside `versions/`, and cannot delete
     or list;
   - **ingest:** can read, but cannot write, copy, delete or list.
2. **Encryption enforcement.** Each case is attempted by the API role, as both
   a single `PutObject` and a `CreateMultipartUpload`:
   - **E-ALG-MISSING:** no `x-amz-server-side-encryption` header → **denied**;
   - **E-KEY-MISSING:** `aws:kms` without the key-id header → **denied**;
   - **E-ALG-WRONG:** `AES256`, and separately `aws:kms:dsse` → **denied**;
   - **E-KEY-WRONG:** the other environment's key ARN, an alias, and a bare key
     id → **denied**;
   - **E-OK:** `aws:kms` with `<KEY_ARN>` → allowed;
   - **E-MPU:** a correctly headed `CreateMultipartUpload`, then `UploadPart`
     and `CompleteMultipartUpload` with `If-None-Match: *`, **succeeds**. If it
     is denied, stop and redesign (§2); never add an exception;
   - **E-STORED:** every created object reports `aws:kms`, `<KEY_ARN>` and
     the Bucket Key.
3. **Simultaneous writes** to one key: exactly one completion succeeds.
4. **Multipart:**
   - completion works;
   - an application abort works;
   - an abandoned upload is removed by the lifecycle rule (observed after one
     day, or the policy is shown).
5. **Integrity:** the whole-file SHA-256 matches; the composite checksum is
   bound to the part digests.
6. **KMS:** an object is unreadable without `kms:Decrypt`; the ingest role
   cannot generate data keys.
7. **Cross-environment:** staging roles are denied on the production bucket and
   key, and the reverse, by policy simulation if the production bucket does
   not exist yet.
8. **Operator purge** removes every version and delete marker; listing shows
   none; the receipt lists version ids.
   - **O-MPU-LIST:** the operator's `ListMultipartUploads` with
     `Prefix=<version key>` is **allowed**, and returns only that prefix's
     uploads;
   - **O-MPU-ABORT:** the operator aborts an upload under `versions/`, and an
     abort of an upload outside `versions/` is **denied**;
   - **O-MPU-PARTS:** the operator's `ListParts` is **denied**;
   - **O-LIST-OUTSIDE:** the operator's `ListObjectVersions` outside
     `versions/` is **denied**.
   - **Limitation, not provable here:** IAM cannot stop the operator role
     from listing in-progress uploads anywhere in the bucket. The offline
     tests (`tests/unit/test_s3_multipart_cleanup.py`) prove only that the
     application never aborts outside the requested prefix; D6 proves that
     AWS evaluates the grants as above, not that every client of the
     operator role filters.
   - **O-LEGACY:** with the operator role, `purge`, `tombstone` and
     `verify-objects` make **no** request outside `versions/` (the S3 store
     answers the legacy `quarantine/` and `datasets/` areas as empty without
     asking), and none is denied;
   - **O-BUCKET-ONLY-VERSIONS:** an administrator listing of the whole bucket
     shows nothing outside `versions/`. Anything there would be invisible to
     the operator role, `verify-objects`, purge and tombstone (ADR-033 note 3).
     This is a point-in-time check.
   - **O-MISSING-STATUS (record, do not assume):** with the operator role,
     `HeadObject` and `GetObjectAttributes` on a key under `versions/` that
     does not exist. Record the exact status AWS returns (403 or 404). The
     operator's `s3:ListBucket` grant is conditioned on `s3:prefix`, which these
     requests do not carry, and S3 may answer 403 for a missing key without
     `ListBucket`. If it is 403, `verify-objects` stops with an error instead
     of reporting the object as missing (it fails closed). Runtime handling is
     **not** changed until this evidence exists; the result decides it.
   - **Receipts after a partial failure:** see ADR-033 note 3. A part-way
     removal failure, or a verification that fails or still finds items,
     leaves whatever was removed removed, with no receipt and no purge event
     from that attempt for that version. A failure at or after the receipt
     write (including the event insert and the commit) records no purge
     event, but a receipt may or may not exist in the deletion log; a dataset
     purge can likewise leave earlier versions' receipts while the dataset
     stays `DELETING`. The safe re-run records a receipt for what it removes
     (zero objects if everything was already gone) for a version with a
     recorded key; for a version without one it records no receipt when
     nothing remains. Only for a version with a recorded key, or with any
     earlier purge event, does tombstone require the latest operator purge
     event after the deletion request, a receipt for it that the configured
     deletion log verifies, and a live check that nothing is stored; a
     version with no key and no purge event is tombstoned on the live absence
     check alone, or with no check when no store is configured. A
     legacy-keyed row purges to a verified zero-object receipt.
   - **Recovery when a purge is refused:** a malformed or unexpected
     in-progress upload under a version refuses the purge (fail closed). An
     administrator aborts it after review, or the lifecycle rule removes it
     after one day; then re-run the purge.
9. **IMDS is unreachable** from every container, and no static credential
   exists anywhere.
10. **Audit:**
    - **A-API-META:** an API `HeadObject`, and an API `GetObjectAttributes`,
      each produce a data event naming the API assumed role (session issuer
      `nlw-staging-dataset-api`) and the exact object ARN;
    - **A-INGEST-READ:** an ingest `GetObject` produces a data event naming
      the ingest assumed role and the exact object ARN;
    - **A-DENIED:** a cross-environment read and an unauthorized read (for
      example, ingest reading outside `versions/`, or the API listing) are
      **denied** and appear as events with `errorCode: AccessDenied`, from the
      account where the request is evaluated;
    - **A-WRITE:** the creation calls, the abort and the operator's
      `DeleteObjectVersion` each appear with the correct role;
    - **A-TAMPER:** the API, ingest, bootstrap and operator roles each fail to
      stop, update or delete the trail, change its event selectors, read,
      write or delete in the audit bucket, change its policy, lifecycle or
      retention, or use the audit key;
    - **A-VALIDATE:** `cloudtrail validate-logs` succeeds for the proof
      window;
    - **A-SCOPE:** no event for any other bucket appears in this trail.
11. **Access:** no public access, and non-TLS access is denied, for both
    buckets.

Record ids, counts, event ids and request ids only under `docs/evidence/`.
Then produce a resource inventory and a cleanup decision. Audit records are
retained under §4.3 regardless of that decision.
