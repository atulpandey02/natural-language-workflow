# Dataset S3 provisioning (NOT RUN — templates for review)

Status: **a plan, not a record.** Nothing here has been created. These
templates implement [ADR-033](../adr/ADR-033-s3-dataset-object-storage.md)
(D1–D6 approved on 2026-10-09). Creating or changing any real AWS resource
requires a separate provisioning review and **explicit owner authorization**
(D6). The isolated proof in §7 runs only after that.

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
| `<ADMIN_ROLE>` | the account administration role that manages the dataset bucket and key |
| `<AUDIT_ADMIN_ROLE>` | the role that administers the trail, audit bucket and audit key. It is not an application or operator role. |
| `<AUDIT_READER_ROLE>` | a human, read-only role for audit review |
| `<AUDIT_RETENTION_DAYS>` | audit-log retention. It is set with O-3 and O-5, and must outlast any deletion-evidence need. |

## 1. Dataset KMS key (one per environment)

- Symmetric, customer-managed, alias `alias/nlw-<ENV>-datasets`, with
  automatic rotation on.
- Tagged `nlw-env=<ENV>`; the role denies in §3 rely on the tag.
- **Key policy:** `<ADMIN_ROLE>` administers the key. The API, ingest and
  operator roles of **this** environment may use it only through S3 in
  us-east-1, for this bucket:

<!-- template: dataset-kms-key-statement -->
```json
{
  "Sid": "UseViaS3ForThisBucketOnly",
  "Effect": "Allow",
  "Principal": {"AWS": [
    "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api",
    "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest",
    "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator"
  ]},
  "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
  "Resource": "*",
  "Condition": {"StringEquals": {
    "kms:ViaService": "s3.us-east-1.amazonaws.com",
    "kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::<BUCKET>"
  }}
}
```

The encryption context is the bucket ARN because S3 Bucket Keys are enabled.
The role policies (§3) split `GenerateDataKey`, which only the API holds, from
`Decrypt`. The bootstrap role is absent from the key policy.

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
    {"Sid": "DenyDeleteExceptOperator", "Effect": "Deny", "Principal": "*",
     "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
     "Resource": "arn:aws:s3:::<BUCKET>/*",
     "Condition": {"ArnNotEquals": {"aws:PrincipalArn": [
        "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator"]}}},
    {"Sid": "DenyBucketConfigExceptAdmin", "Effect": "Deny", "Principal": "*",
     "Action": ["s3:PutBucket*", "s3:DeleteBucket*", "s3:PutLifecycleConfiguration",
                "s3:PutEncryptionConfiguration", "s3:PutBucketVersioning"],
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
  instead, for example single-request `PutObject` uploads with both headers,
  which is viable because uploads are capped at 25 MB.
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
  {"Sid": "NeverTouchAudit", "Effect": "Deny",
   "Action": ["cloudtrail:*", "s3:*", "kms:*"],
   "Resource": ["<TRAIL_ARN>", "arn:aws:s3:::<AUDIT_BUCKET>", "arn:aws:s3:::<AUDIT_BUCKET>/*", "<AUDIT_KEY_ARN>"]},
  {"Sid": "NeverAlterAnyTrail", "Effect": "Deny",
   "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
              "cloudtrail:PutEventSelectors", "cloudtrail:PutInsightSelectors"],
   "Resource": "*"}
]}
```

- **Excluded:** no S3, no KMS, and never the operator role.
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
   "Resource": ["arn:aws:s3:::nlw-<OTHER_ENV>-datasets-*", "arn:aws:s3:::nlw-<OTHER_ENV>-datasets-*/*",
                "arn:aws:kms:us-east-1:<ACCOUNT>:key/*"],
   "Condition": {"StringNotEquals": {"aws:ResourceTag/nlw-env": "<ENV>"}}},
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
- `NeverOtherEnvironment` relies on the KMS key tags (§1). A key without the
  tag is denied, which fails closed.

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
   "Resource": ["arn:aws:s3:::nlw-<OTHER_ENV>-datasets-*", "arn:aws:s3:::nlw-<OTHER_ENV>-datasets-*/*"]},
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

### `nlw-<ENV>-dataset-operator`

- **Trust:** named human operator principals only, with
  `aws:MultiFactorAuthPresent = true`. It is **not** the bootstrap role or any
  application role.
- **Policy:**

<!-- template: role-operator -->
```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "ListVersionsBounded", "Effect": "Allow",
   "Action": ["s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"],
   "Resource": "arn:aws:s3:::<BUCKET>",
   "Condition": {"StringLike": {"s3:prefix": ["versions/*"]}}},
  {"Sid": "PurgeAndVerify", "Effect": "Allow",
   "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes",
              "s3:DeleteObjectVersion", "s3:AbortMultipartUpload"],
   "Resource": "arn:aws:s3:::<BUCKET>/versions/*"},
  {"Sid": "Decrypt", "Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "<KEY_ARN>"},
  {"Sid": "NeverTouchAudit", "Effect": "Deny",
   "Action": ["cloudtrail:*", "s3:*", "kms:*"],
   "Resource": ["<TRAIL_ARN>", "arn:aws:s3:::<AUDIT_BUCKET>", "arn:aws:s3:::<AUDIT_BUCKET>/*", "<AUDIT_KEY_ARN>"]},
  {"Sid": "NeverAlterAnyTrail", "Effect": "Deny",
   "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
              "cloudtrail:PutEventSelectors", "cloudtrail:PutInsightSelectors"],
   "Resource": "*"}
]}
```

- The operator purges dataset objects, never audit records. Audit review uses
  `<AUDIT_READER_ROLE>`.
- It is used only through reviewed operator commands:

| Command | Purpose |
|---|---|
| `purge` | Version-aware deletion of a `DELETING` version |
| `purge-rejected` | Bounded removal of rejected objects |
| `rejected-pending` | Lists rejected objects eligible for purge |
| `verify-objects` | Reconciles database keys with stored objects |

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

Management events, such as bucket-policy, KMS and IAM changes, are **not** in
this trail. **Assumption:** an account- or organization-level management-event
trail already exists and is protected the same way. This must be confirmed in
the provisioning review.

### 4.2 Audit KMS key (separate from the dataset key)

- Alias `alias/nlw-<ENV>-dataset-audit`, with rotation on.
- `<AUDIT_ADMIN_ROLE>` administers the key.
- No dataset application or operator role is in this key policy.

<!-- template: audit-kms-key-statements -->
```json
[
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
  after the retention period.

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
                "s3:PutBucketObjectLockConfiguration"],
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

This runs against the **staging** bucket from an isolated session, never
production. Every item must pass. A failure stops provisioning, with no
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
