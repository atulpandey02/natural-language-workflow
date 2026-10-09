# Dataset S3 provisioning (NOT RUN — templates for review)

Status: **a plan, not a record.** Nothing here has been created. These
templates implement [ADR-033](../adr/ADR-033-s3-dataset-object-storage.md) and
assume its recommendations D1 (one object per version) and D3 (per-container
assumed roles). Creating or changing any real AWS resource needs separate
owner approval, step by step.

## Placeholders

| Placeholder | Meaning |
|---|---|
| `<ENV>` | `staging` or `production`. Every resource is created once per environment and never shared. |
| `<ACCOUNT>` | AWS account id |
| `<BUCKET>` | `nlw-<ENV>-datasets-<ACCOUNT>-us-east-1[-<suffix>]` |
| `<KEY_ARN>` | the environment's customer-managed KMS key |
| `<LOG_BUCKET>` | CloudTrail data-event log bucket. It is separate from `<BUCKET>` and from the Restic bucket. |

## 1. KMS key (one per environment)

- Symmetric, customer-managed, alias `alias/nlw-<ENV>-datasets`, with automatic
  rotation on.
- **Key policy:** account administration manages the key. The `…-dataset-api`,
  `…-dataset-ingest` and `…-dataset-operator` roles may use it **only via S3
  in us-east-1, for this bucket**:

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
  "Condition": {
    "StringEquals": {
      "kms:ViaService": "s3.us-east-1.amazonaws.com",
      "kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::<BUCKET>"
    }
  }
}
```

The encryption context is the **bucket** ARN because S3 Bucket Keys are
enabled. The per-role split of `GenerateDataKey` (API only) and `Decrypt` is
enforced in the role policies below.

## 2. Bucket

**Settings:**

- region us-east-1;
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
  "Filter": {"Prefix": "quarantine/"},
  "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}
}]}
```

Noncurrent-version expiry is deliberately absent until O-5 decides retention.

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
    {"Sid": "DenyUnconditionalCreate", "Effect": "Deny", "Principal": "*",
     "Action": "s3:PutObject", "Resource": "arn:aws:s3:::<BUCKET>/quarantine/*",
     "Condition": {"Null": {"s3:if-none-match": "true"},
                   "Bool": {"s3:ObjectCreationOperation": "true"}}},
    {"Sid": "DenyWrongEncryption", "Effect": "Deny", "Principal": "*",
     "Action": "s3:PutObject", "Resource": "arn:aws:s3:::<BUCKET>/*",
     "Condition": {"StringNotEqualsIfExists": {
        "s3:x-amz-server-side-encryption-aws-kms-key-id": "<KEY_ARN>"}}},
    {"Sid": "DenyVersionDeleteExceptOperator", "Effect": "Deny", "Principal": "*",
     "Action": ["s3:DeleteObjectVersion"], "Resource": "arn:aws:s3:::<BUCKET>/*",
     "Condition": {"ArnNotEquals": {"aws:PrincipalArn": [
        "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator"]}}},
    {"Sid": "DenyBucketConfigExceptAdmin", "Effect": "Deny", "Principal": "*",
     "Action": ["s3:PutBucket*", "s3:DeleteBucket*", "s3:PutLifecycleConfiguration",
                "s3:PutEncryptionConfiguration", "s3:PutBucketVersioning"],
     "Resource": "arn:aws:s3:::<BUCKET>",
     "Condition": {"ArnNotLike": {"aws:PrincipalArn": [
        "arn:aws:iam::<ACCOUNT>:role/<ACCOUNT-ADMIN-ROLE>"]}}}
  ]
}
```

To verify during the IAM proof:

- **`DenyUnconditionalCreate`** must refuse a plain `PutObject` and a
  `CompleteMultipartUpload` without `If-None-Match`. It must still allow
  `CreateMultipartUpload` and `UploadPart`, which are covered by
  `s3:ObjectCreationOperation` per the AWS conditional-write enforcement
  guide.
- **The condition-key semantics** must be confirmed against the current AWS
  documentation when this is created.
- **`DenyWrongEncryption`** relies on the request header. The default bucket
  encryption still applies when the header is absent.

**Audit:** CloudTrail **data events** (read and write) for `<BUCKET>` only,
delivered to `<LOG_BUCKET>`. Their retention is decided with O-3 and O-5.

## 3. Roles (one set per environment)

### `nlw-<ENV>-dataset-runtime` (EC2 instance profile)

- **Permissions:** only `sts:AssumeRole` on `nlw-<ENV>-dataset-api` and
  `nlw-<ENV>-dataset-ingest`. No S3 and no KMS.
- **Instance:** IMDSv2 required, with hop limit **1**, so containers cannot
  reach IMDS.

### `nlw-<ENV>-dataset-api`

- **Trust:** `nlw-<ENV>-dataset-runtime`.
- **Policy:**

```json
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow",
   "Action": ["s3:PutObject", "s3:AbortMultipartUpload", "s3:GetObject"],
   "Resource": "arn:aws:s3:::<BUCKET>/quarantine/*"},
  {"Effect": "Allow", "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
   "Resource": "<KEY_ARN>"}
]}
```

`kms:Decrypt` is required for multipart uploads to SSE-KMS objects.
`GetObject` serves `HeadObject` for the idempotent-retry check only.

### `nlw-<ENV>-dataset-ingest`

- **Trust:** `nlw-<ENV>-dataset-runtime`.
- **Policy:**

```json
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Action": ["s3:GetObject"],
   "Resource": "arn:aws:s3:::<BUCKET>/quarantine/*"},
  {"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "<KEY_ARN>"}
]}
```

### `nlw-<ENV>-dataset-operator`

- **Trust:** named operator principals, with `aws:MultiFactorAuthPresent`
  required. It is **not** the instance role.
- **Policy:**

```json
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow",
   "Action": ["s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"],
   "Resource": "arn:aws:s3:::<BUCKET>",
   "Condition": {"StringLike": {"s3:prefix": ["quarantine/*"]}}},
  {"Effect": "Allow",
   "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:DeleteObjectVersion",
              "s3:AbortMultipartUpload"],
   "Resource": "arn:aws:s3:::<BUCKET>/quarantine/*"},
  {"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "<KEY_ARN>"}
]}
```

## 4. Per-container credentials (host)

- **The refresher:** a root-owned systemd timer (about 15 minutes) runs
  `aws sts assume-role` for the API and ingest roles, with a 1 h duration and
  session names `nlw-<ENV>-api` and `nlw-<ENV>-ingest`.
- **Delivery:** it writes `/run/nlw/aws/<service>/credentials`, a `0400` file
  owned by the container uid on tmpfs. Each file is mounted read-only into its
  own service only, through `AWS_SHARED_CREDENTIALS_FILE`.
- **What never reaches a container:** the instance role's credentials and any
  static access key.
- **Implementation:** the refresher script is part of the O-6 enablement work,
  not O-2.

## 5. Isolated IAM-separation proof (sequence step 6; separate approval)

This runs against the **staging** bucket from an isolated session. It must
show all of the following:

1. The API role can create once. It cannot overwrite (412), cannot write
   without `If-None-Match` (denied), cannot write outside `quarantine/`,
   cannot `DeleteObjectVersion`, and cannot list.
2. The ingest role can read. It cannot write, delete or list.
3. Non-TLS access and the wrong KMS key are denied.
4. An operator purge removes every version and delete marker, and listing
   then shows none.
5. An abandoned multipart upload is aborted by the application, and the
   lifecycle rule covers the rest.
6. No static credential is used anywhere.

Record only ids, counts and request ids under `docs/evidence/`.
