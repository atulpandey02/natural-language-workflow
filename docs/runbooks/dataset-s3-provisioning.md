# Dataset S3 provisioning (NOT RUN — templates for review)

Status: **a plan, not a record.** Nothing here has been created. These
templates implement [ADR-033](../adr/ADR-033-s3-dataset-object-storage.md)
(D1–D6 approved on 2026-10-09). Creating or changing any real AWS resource
requires a separate provisioning review and **explicit owner authorization**
(D6). The isolated proof in §6 runs only after that.

## Placeholders

| Placeholder | Meaning |
|---|---|
| `<ENV>` | `staging` or `production`. Every resource is created once per environment and never shared. |
| `<OTHER_ENV>` | the other environment, which is explicitly denied |
| `<ACCOUNT>` | AWS account id |
| `<BUCKET>` | `nlw-<ENV>-datasets-<ACCOUNT>-us-east-1[-<suffix>]` |
| `<KEY_ARN>` | the environment's customer-managed KMS key |
| `<LOG_BUCKET>` | CloudTrail data-event log bucket. It is separate from `<BUCKET>` and from the Restic bucket. |
| `<ADMIN_ROLE>` | the account administration role that manages buckets and keys |

## 1. KMS key (one per environment)

- Symmetric, customer-managed, alias `alias/nlw-<ENV>-datasets`, with
  automatic rotation on.
- **Key policy:** `<ADMIN_ROLE>` administers the key. The API, ingest and
  operator roles of **this** environment may use it only through S3 in
  us-east-1, for this bucket:

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

## 2. Bucket

**Settings:**

- us-east-1;
- Block Public Access: all four settings on;
- Object Ownership: `BucketOwnerEnforced`;
- Versioning: enabled;
- Object Lock: off;
- default encryption: SSE-KMS with `<KEY_ARN>` and Bucket Key enabled.

**Lifecycle rule:**

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

**Bucket policy** (deny statements; the role policies grant):

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
    {"Sid": "DenyWrongEncryption", "Effect": "Deny", "Principal": "*",
     "Action": "s3:PutObject", "Resource": "arn:aws:s3:::<BUCKET>/*",
     "Condition": {"StringNotEqualsIfExists": {
        "s3:x-amz-server-side-encryption-aws-kms-key-id": "<KEY_ARN>"}}},
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

To confirm against current AWS documentation during provisioning, and to
prove in §6:

- **`DenyUnconditionalCreate`** must refuse a plain `PutObject` and a
  `CompleteMultipartUpload` without `If-None-Match`. It must still allow
  `CreateMultipartUpload` and `UploadPart`, using the documented
  `s3:ObjectCreationOperation` semantics.
- **`DenyWrongEncryption`** relies on the request header. The default bucket
  encryption still applies when the header is absent.

**Audit:** CloudTrail **data events** (read and write) for `<BUCKET>` only,
delivered to `<LOG_BUCKET>`. The log bucket's retention and access are decided
with O-3 and O-5.

## 3. Roles (one set per environment)

### `nlw-<ENV>-dataset-bootstrap` (EC2 instance profile)

- **Permissions:** only `sts:AssumeRole` on exactly these two ARNs:

```json
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": [
    "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api",
    "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest"]}
]}
```

- **Excluded:** no S3, no KMS, and never the operator role.
- **Instance:** IMDSv2 required, with hop limit **1**.

### `nlw-<ENV>-dataset-api`

- **Trust:** only `nlw-<ENV>-dataset-bootstrap`, with `sts:RoleSessionName`
  conditioned to `nlw-<ENV>-api`.
- **Policy:**

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
   "Condition": {"StringNotEquals": {"aws:ResourceTag/nlw-env": "<ENV>"}}}
]}
```

- `s3:GetObject` is required by `HeadObject` and `GetObjectAttributes`. Code
  calls only those operations (ADR-033 note 1, accepted residual risk).
- There is no delete, no list, and nothing outside `versions/`.
- The KMS keys are tagged `nlw-env=<ENV>`, which lets the deny refuse the
  other environment's key.

### `nlw-<ENV>-dataset-ingest`

- **Trust:** only `nlw-<ENV>-dataset-bootstrap`, with session name
  `nlw-<ENV>-ingest`.
- **Policy:**

```json
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Action": ["s3:GetObject"],
   "Resource": "arn:aws:s3:::<BUCKET>/versions/*"},
  {"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "<KEY_ARN>"},
  {"Sid": "NeverOtherEnvironment", "Effect": "Deny", "Action": ["s3:*", "kms:*"],
   "Resource": ["arn:aws:s3:::nlw-<OTHER_ENV>-datasets-*", "arn:aws:s3:::nlw-<OTHER_ENV>-datasets-*/*"]}
]}
```

- IAM scope is the environment prefix. Exact-object access is enforced in the
  application (ADR-033 note 2).

### `nlw-<ENV>-dataset-operator`

- **Trust:** named human operator principals only, with
  `aws:MultiFactorAuthPresent = true`. It is **not** the bootstrap role or any
  application role.
- **Policy:**

```json
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow",
   "Action": ["s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"],
   "Resource": "arn:aws:s3:::<BUCKET>",
   "Condition": {"StringLike": {"s3:prefix": ["versions/*"]}}},
  {"Effect": "Allow",
   "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes",
              "s3:DeleteObjectVersion", "s3:AbortMultipartUpload"],
   "Resource": "arn:aws:s3:::<BUCKET>/versions/*"},
  {"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "<KEY_ARN>"}
]}
```

- It is used only through reviewed operator commands:

| Command | Purpose |
|---|---|
| `purge` | Version-aware deletion of a `DELETING` version |
| `purge-rejected` | Bounded removal of rejected objects |
| `rejected-pending` | Lists rejected objects eligible for purge |
| `verify-objects` | Reconciles database keys with stored objects |

## 4. Per-container credentials (single Compose host; built with O-6)

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
- credentials expiring within 15 min;
- the startup identity check failing.

## 5. Rejected-object purge (D2, provisional 7 days)

**Cadence:** the operator runs `rejected-pending --dry-run`, then
`purge-rejected --limit N`, at least weekly. Both:

- work in bounded, oldest-first batches;
- refuse while the recovery lock is active or unreadable;
- are idempotent on re-run.

**Monitoring:**

- `NlwDatasetRejectedRetainedTooLong` fires past 7 days. It is dormant until
  O-6, when it is wired with the other dataset alerts.
- **The 7-day value is provisional** (development and staging). It is not the
  customer retention policy, which O-5 sets.

## 6. Isolated real-AWS proof (D6; only after explicit authorization)

This runs against the **staging** bucket from an isolated session, never
production. It must show:

1. **Role isolation:**
   - **bootstrap:** can assume only the API and ingest roles, not the
     operator role, and has no S3 or KMS access;
   - **API:** can create once, but gets 412 on overwrite, is denied writes
     without `If-None-Match`, is denied outside `versions/`, and cannot delete
     or list;
   - **ingest:** can read, but cannot write, copy, delete or list.
2. **Simultaneous writes** to one key: exactly one completion succeeds.
3. **Multipart:**
   - completion works;
   - an application abort works;
   - an abandoned upload is removed by the lifecycle rule (observed after one
     day, or the policy is shown).
4. **Integrity:** the whole-file SHA-256 matches; the composite checksum is
   bound to the part digests.
5. **KMS:** the wrong key is denied; an object is unreadable without
   `kms:Decrypt`.
6. **Cross-environment:** staging roles are denied on the production bucket and
   key, and the reverse, by policy simulation if the production bucket does
   not exist yet.
7. **Operator purge** removes every version and delete marker; listing shows
   none; the receipt lists version ids.
8. **IMDS is unreachable** from every container, and no static credential
   exists anywhere.
9. **Audit:** CloudTrail data events are present for each step.
10. **Access:** no public access, and non-TLS access is denied.

Record ids, counts and request ids only under `docs/evidence/`. Then produce a
resource inventory and a cleanup decision.
