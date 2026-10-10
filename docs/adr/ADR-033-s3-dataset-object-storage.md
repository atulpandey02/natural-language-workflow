# ADR-033: Production dataset object storage on AWS S3 (owner decision O-2)

Status: **accepted; implemented without AWS contact (branch
`feat/o2-s3-dataset-store`); not deployed, no AWS resources.** The owner
approved D1–D6 on 2026-10-09. The real-AWS proof still needs separate, explicit
authorization (D6). Uploads stay refused in staging and production (O-6).
Date: 2026-10-09.
Builds on [ADR-030](ADR-030-csv-ingestion-and-profiling.md) (storage protocol, write-once,
verified purge), [ADR-031](ADR-031-dataset-ingest-runtime-boundary.md) (ingest boundary) and
[ADR-032](ADR-032-dataset-ingest-dispatcher.md) (dispatcher). Provisioning templates:
[dataset-s3-provisioning](../runbooks/dataset-s3-provisioning.md) (NOT RUN).

> **Principle.** S3 stores one immutable object per dataset version.
> PostgreSQL controls its business lifecycle. The ingest runtime reads it.
> Only an independently authorized operator can physically remove it.

## Implementation status (feat/o2-s3-dataset-store)

| Piece | Where |
|---|---|
| S3 store | `nlw.storage.s3.S3BlobStore` |
| Pinned credentials and identity check | `nlw.storage.s3_credentials` |
| Settings and refusals | `DATASET_STORAGE_BACKEND=s3`, `DATASET_S3_*` in `nlw.core.config` |
| One immutable object per version | `TenantScopedBlobStore.object_key`. There is no runtime delete or copy. |
| Read-only ingest | `nlw.ingest_service.processing` |
| Database layout and guard | Migration `0028_dataset_object_layout`: the `versions/` key check, a key-never-moves guard, `nlw_ingest` losing `UPDATE (storage_object_key)`, and reason `REJECTED_RETENTION` |
| D2 operator tooling | `rejected-pending` and `purge-rejected` |
| Alerts | `NlwDatasetRejectedRetainedTooLong` and `NlwDatasetS3CredentialsExpiring`, both dormant |
| Credential-expiry metric | `nlw_dataset_s3_credentials_expiry_timestamp_seconds`: the ABSOLUTE expiry (Unix seconds) from the last credential-file read, no labels. The alert evaluates `expiry - time() < 900` for 5 m, so it fires even if the refresher stops and the process never re-reads the file. A remaining-duration gauge would freeze in that case. |

- **Credential file:** the shared-credentials file carries a non-standard
  `x_nlw_expiration` (ISO-8601 UTC) written by the refresher. The SDK ignores
  it; the application uses it for the expiry checks.
- **Single or multipart:** an object up to 8 MiB is one `PutObject` with a
  whole-file `ChecksumSHA256`; a larger one is a multipart upload with a
  composite checksum. The choice follows the content size, so retries produce
  the same fingerprint.
- **Tests:** a fake S3 that enforces the bucket policy, plus botocore Stubber
  request-shape tests. No network and no AWS.

## Context

Dataset bytes live behind the `BlobStore` protocol (`nlw.storage.blob`). Only
`LocalBlobStore` exists, and it is refused in staging and production, so no
deployed environment has a dataset store. The local store guarantees:

- keys derived from ids only;
- write-once objects;
- a streamed SHA-256 and a byte cap;
- version-scoped listing for purge, and `verify-objects`.

Today the ingest runtime also **copies** each verified upload from
`quarantine/` to `datasets/` and **deletes** quarantine and rejected bytes,
and the API **deletes** its own object after a size mismatch. The decisions
below remove all three.

## Decisions (owner, 2026-10-09)

### Provider, buckets and bucket security

- **Provider.** AWS S3 in **us-east-1**, with **boto3** as the client (no
  other abstraction).
- **Buckets.** `nlw-staging-datasets-<account>-us-east-1[-suffix]` and
  `nlw-production-datasets-<account>-us-east-1[-suffix]`.
  - **Never:** shared between environments, separated only by prefix in one
    bucket, the Restic backup bucket, or public.
- **Bucket security:**
  - all four Block Public Access settings on;
  - `BucketOwnerEnforced`, so ACLs are disabled;
  - SSE-KMS with a **separate customer-managed KMS key per environment**,
    with the S3 Bucket Key on. **Every creation request must itself name
    `aws:kms` and that key.** The bucket policy denies a missing algorithm
    header, a missing key header, a wrong algorithm and a wrong key in four
    separate statements. The bucket default encryption is defence in depth,
    never a fallback;
  - a TLS-only bucket policy;
  - Versioning on;
  - **no Object Lock** initially, and no public endpoints.
- **Lifecycle.** Incomplete multipart uploads are aborted, by the application
  and by a lifecycle rule. Noncurrent-version expiry waits for O-5.
- **Audit.** A dedicated CloudTrail trail records **object-level data events
  (read and write) for this environment's dataset bucket only**. See
  provisioning runbook §4.
  - **Delivery:** to a separate audit bucket, encrypted with a separate audit
    KMS key, with log-file validation, Object Lock retention, and
    confused-deputy protection (`aws:SourceArn`/`aws:SourceAccount`).
  - **Protection:** the dataset API, ingest, bootstrap and operator roles are
    explicitly denied any change to the trail, the audit bucket or the audit
    key.
  - **Independence:** audit records are kept independently of dataset-object
    deletion.
  - **Not used:** server access logs.
  - **Retention:** set with O-3 and O-5.
  - **Assumption:** management events (policy, KMS and IAM changes) are
    covered by an existing account- or organization-level trail. This is
    confirmed at the provisioning review.

### D1 — one immutable object per version

- **Key.** Each version has **one** object for its whole life:
  `versions/<workspace_id>/<dataset_id>/<version_id>/source.csv`.
- **Never copied, moved or rewritten** during profiling, semantic
  confirmation, activation, superseding, rejection or logical deletion.
- **The database is authoritative** for `QUARANTINED`, `PROFILING`,
  `PROFILED`, `ACTIVE`, `SUPERSEDED`, `REJECTED`, `DELETING` and `DELETED`.
  "Published" is a database state, not a second S3 location.
- `storage_object_key` and `content_sha256` never change after they are
  recorded.
- **The ingest runtime is read-only.** It never uploads, overwrites, copies or
  deletes.
- **Local store.** `LocalBlobStore` follows the same single-object rules, so
  development and production share one code path.
- **Migration follow-up.** A follow-up migration revokes `nlw_ingest`'s
  `UPDATE (storage_object_key)` grant and narrows migration 0025's guard, so
  the key can no longer move.

### D2 — rejected files (provisional)

**The rejection flow:**

1. The ingest runtime records `REJECTED` and deletes nothing.
2. The object stays immutable.
3. The version becomes eligible for **operator purge**.
4. The operator runs the version-aware purge.
5. Deletion is verified.
6. O-3 records the external deletion receipt, once O-3 exists.
7. The database tombstone follows the established lifecycle.

**Provisional policy:** a rejected object **must be purged within 7 days.** This
is a temporary development and staging value, **not** the customer retention
policy (O-5). Customer uploads stay disabled while O-3 and O-5 are open.

**Required support:**

- **Operator listing:** `python -m nlw.ops.datasets rejected-pending
  [--dry-run] [--limit N]` lists rejected versions with stored bytes, oldest
  first. It shows ids, age and counts only.
- **Bounded purge:** `purge-rejected` purges them in **bounded, oldest-first
  batches**. It has a `--dry-run` mode, coordinates with the **recovery lock**
  (it refuses while the lock is active or unreadable), and is **idempotent** on
  re-run, using the same version-aware purge as deletion requests.
- **Metrics:** aggregate only, `nlw_dataset_rejected_retained` and
  `nlw_dataset_rejected_oldest_age_seconds`. They are emitted by the operator
  CLI's metrics file or the restore-validation job; no runtime gains S3 list
  rights.
- **Alert:** `NlwDatasetRejectedRetainedTooLong` fires when the oldest
  retained rejected object is older than 7 days. It stays dormant until O-6,
  like the ADR-032 alerts.

### D3 — credentials on the single Compose host

**Roles**, one set per environment, and never valid in the other environment:

| Role | May | May not |
|---|---|---|
| `nlw-<env>-dataset-bootstrap` (EC2 instance profile) | `sts:AssumeRole` on **only** `nlw-<env>-dataset-api` and `nlw-<env>-dataset-ingest` | Any S3 object action; any KMS encrypt or decrypt; assume the operator role |
| `nlw-<env>-dataset-api` | Under `versions/` of its own bucket only: `PutObject` (conditional create, plus the multipart create, part and complete calls), `AbortMultipartUpload`, and object metadata for retries and orphan adoption (see note 1). KMS `GenerateDataKey` and `Decrypt` on its own key | Delete objects or versions, list, access other prefixes, access the other environment's bucket or key |
| `nlw-<env>-dataset-ingest` | `GetObject` on `versions/` of its own bucket (see note 2), and KMS `Decrypt` | Upload, overwrite, copy, delete or list. Operator credentials |
| `nlw-<env>-dataset-operator` | Bounded listing (prefix-conditioned), version-aware purge (`DeleteObjectVersion`), verification and multipart abort | Assumption by the bootstrap role or any application identity. It requires a separate **human** assumption path with **MFA**, and is used only through reviewed operator commands |

**Note 1, API metadata.** S3 cannot grant metadata-only reads.
`HeadObject` and `GetObjectAttributes` both require `s3:GetObject`. So the
API role can technically read objects under `versions/`. The mitigations are:

- the API code calls only `HeadObject` and `GetObjectAttributes`, which unit
  tests and botocore Stubber tests assert;
- the role is limited to its own bucket and prefix;
- the CloudTrail data-event trail (runbook §4) records every `HeadObject`
  and `GetObjectAttributes` call with the assumed role and object ARN, and
  the D6 proof checks this.

This is accepted as a **residual risk**. The alternative is to drop API reads
entirely, so an orphan after a crash is never adopted by the API, only
reconciled by the operator. That stays available if the reviewer prefers it.

**Note 2, ingest scope.** With per-container credential files, IAM can
restrict ingest to the `versions/` prefix of its environment's bucket, **not**
to the single object of the current message. Exact-object access is enforced
in the application:

- the key is derived from the signed, database-verified envelope;
- the content SHA-256 is re-checked;
- the version's tenant and dataset must match.

A future refinement is per-message STS session policies through a broker. It
is not adopted now, because it would require the ingest container to call STS.

**Credential delivery on the single host** (an explicitly documented
single-host design; on ECS or EKS it is replaced by task or pod identity):

- **Assumption and storage.** A root-owned host service assumes **only** the
  API and ingest roles. It writes **separate** short-lived credential files,
  in separate host directories on tmpfs, with mode `0400`, owned by the
  container uid.
- **Mounting.** Each file is mounted **read-only into exactly one container**.
  The dispatcher receives **no** S3 credentials.
- **Rotation.** Credentials are rotated well before expiry: a 1 h session
  refreshed every 15 min. Each rotation is **atomic** (write a temp file in the
  same directory, `fsync`, `rename`), old credentials are removed, and values
  are **never logged**.
- **IMDS is blocked for containers.** IMDSv2 is required with hop limit **1**,
  and the host firewall drops `169.254.169.254` from the Docker bridges as
  defence in depth. The block is **verified from every application container**
  during deployment checks.
- **Startup checks.** A container **fails to start** when its credentials are
  missing or expired, or belong to the wrong service. It checks the role ARN
  from `sts:GetCallerIdentity` against the expected role for its service and
  environment.
  - There is **never** a fallback from the assigned role to the instance role.
  - The SDK credential chain is pinned to the shared-credentials file.
  - Environment and IMDS providers are disabled.
- **Startup log.** At startup the container logs the effective identity: the
  role ARN and account only, never a credential.
- **Alerts:** a credential refresh failure, and expiry within 15 min
  (`nlw_dataset_s3_credentials_expiry_timestamp_seconds - time() < 900`; the
  gauge is the absolute expiry, so the condition keeps advancing without any
  further read).

### D4 — key layout

| Purpose | Layout |
|---|---|
| Source objects | `versions/<workspace_id>/<dataset_id>/<version_id>/source.csv` |
| Future derived artifacts | A separate namespace: `derived/<workspace_id>/<dataset_id>/<version_id>/<artifact>` |

- **Never in a key:** user-supplied filenames, workspace or dataset names,
  email addresses, or mutable state names such as `active/` or `rejected/`.
  The original filename stays PostgreSQL metadata.
- **Database check.** Migration 0025's rule that a key's fourth segment is the
  version id still holds. The same follow-up migration that narrows the guard
  accepts the `versions/` area and stops accepting `quarantine/` and
  `datasets/` for new keys.
- **Existing data.** Only development data has the old shapes. Purge and
  `verify-objects` keep accepting the old local shapes, so old dev rows can
  still be removed.

### D5 — settings

**The settings**, using the existing vocabulary (no parallel `NLW_DATASET_*`
names):

| Setting | Value |
|---|---|
| `DATASET_STORAGE_BACKEND` | `s3` |
| `DATASET_S3_BUCKET` | the environment's bucket |
| `DATASET_S3_REGION` | `us-east-1` |
| `DATASET_S3_KMS_KEY_ARN` | the environment's key ARN |
| `DATASET_S3_PREFIX` | `versions` |

**Development/test-only settings:**

- `DATASET_S3_ENDPOINT_URL`, an endpoint override;
- `DATASET_S3_PATH_STYLE`, path-style addressing.

**Validated at startup:**

- **Local storage** is allowed only in development and test, as today.
- **Upload enablement** (`DATASETS_API_ENABLED`) stays refused in staging and
  production.
- **Bucket and key identity:**
  - the bucket name must contain the current environment;
  - the KMS key must be in `us-east-1`;
  - production refuses `staging` identifiers, and staging refuses
    `production` ones.
- **Endpoints:**
  - endpoint overrides and path-style addressing are refused outside
    development and test;
  - an `http://` endpoint is refused everywhere except under the test suite.
- **Credentials:** static `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` are
  refused in the environment and in `.env.prod`.
- **Backup separation:** the bucket must differ from the Restic repository's
  bucket.

### D6 — real AWS only later, in an isolated, authorized session

The implementation supports S3 now, but **no AWS resource is created or
contacted** by the code PR. The sequence:

1. ADR and threat model (this document).
2. Storage protocol adaptation.
3. Fake-client unit tests.
4. Local integration tests, with a controlled emulator only if necessary.
5. Adversarial and negative-control tests.
6. PR review and merge.
7. A separate AWS provisioning review.
8. Explicit authorization.
9. An isolated real-AWS proof.
10. A resource inventory and cleanup decision.
11. The O-4 design and restore proof.
12. O-6 staging enablement, only after every gate passes.

The real-AWS proof must show:

- role isolation;
- conditional-write enforcement;
- simultaneous-write behaviour;
- multipart completion, abort and lifecycle cleanup;
- the whole-file SHA-256;
- KMS enforcement: a missing algorithm, a missing key, a wrong algorithm and
  a wrong key are each denied, and a correctly headed multipart upload
  completes;
- cross-environment denial;
- the API cannot delete, and ingest cannot write;
- the operator's version-aware purge;
- containers cannot reach IMDS;
- no static credentials;
- audit evidence: API `HeadObject`/`GetObjectAttributes` and ingest
  `GetObject` each produce a data event naming the assumed role and the object
  ARN, denied cross-environment and unauthorized reads are recorded, and no
  runtime role can alter the trail or the audit bucket;
- no public access.

## Design

AWS facts this design relies on (AWS documentation, checked 2026-10-09):

- conditional writes work on `PutObject`, `CompleteMultipartUpload` and
  `CopyObject`;
- bucket policies can require them with `s3:if-none-match` and
  `s3:ObjectCreationOperation`;
- for multipart uploads, SHA-256 is available only as a **composite**
  checksum;
- with Versioning on, `DeleteObject` without a version id only adds a delete
  marker, and physical removal needs `DeleteObjectVersion`;
- `HeadObject` and `GetObjectAttributes` require `s3:GetObject`.

### Write (API)

1. **Create** with `CreateMultipartUpload` on the derived key, passing:
   - `ChecksumAlgorithm=SHA256`;
   - `ServerSideEncryption=aws:kms`;
   - the environment's `SSEKMSKeyId`;
   - `BucketKeyEnabled=true`;
   - no ACL parameter.
2. **Stream** in fixed 8 MiB parts (at most 4 for 25 MB). Each part carries
   `ChecksumSHA256`, which S3 verifies. Our full-object SHA-256 and the byte
   count are computed while streaming, and the cap is enforced while reading.
3. **Size check before completing.** If the size differs from the declared
   size, `AbortMultipartUpload`. Nothing was created, so the API never
   deletes.
4. **Complete** with `CompleteMultipartUpload` and `If-None-Match: *`. Then
   compute the expected composite checksum (SHA-256 over the concatenated part
   digests, `-N`) and compare it with S3's. That binds the stored bytes to the
   hashed bytes without reading them back.
5. **Outcomes:**
   - **412** (the key exists): `GetObjectAttributes`. If the size and
     composite match ours, it is an idempotent retry or our orphan, and it is
     adopted. Otherwise it is `CONTENT_CONFLICT`.
   - **409** (a concurrent conditional write): one retry, then
     `CONTENT_CONFLICT`.
   - **Any failure:** abort in `finally`.
6. **Record.** The database records the full SHA-256, the size and the key in
   one transaction with the processing request, as today.

### Read (ingest)

- **Integrity:** a streamed, size-capped `GetObject` feeds the isolated
  profiler, which re-hashes and refuses any mismatch with the database
  SHA-256. No object metadata is trusted.
- **Writes:** none. Publishing is a database transition only.

### Purge (operator; deletion requests and D2)

1. Check the recovery lock.
2. `ListMultipartUploads(Prefix=<version key>)`, then abort each.
3. `ListObjectVersions(Prefix=<version key>)`.
4. `DeleteObjectVersion` for every version and delete marker.
5. Verify that nothing remains.
6. The receipt (O-3) records the deleted version ids.
7. Tombstone only after verification. A failure leaves the version `DELETING`.

### `verify-objects`

- **Listing:** `ListObjectVersions` over `versions/`, by the operator.
- **Live versions:** every live recorded key needs a current version whose
  size matches; `--deep` streams and re-hashes.
- **Reported separately:** unaccounted objects, missing objects, noncurrent
  versions, retained rejected objects, and stale multipart uploads.

### Retries and failure mapping

- **Retries:** botocore `standard` mode with 3 attempts, and bounded connect
  and read timeouts.
- **Errors:** S3 errors map to the existing closed codes, for example 503 when
  the store is unavailable. Responses and logs never include the bucket, key,
  ARN, request id or credentials. Logs carry an error class and an id hash
  only.

## Threat model

| Threat | Control |
|---|---|
| Overwriting or replacing a committed upload | `If-None-Match: *` in code; the bucket policy denies unconditional creates; Versioning keeps prior versions; the database records an immutable SHA-256 and key |
| Two concurrent uploads for one version | S3 accepts exactly one conditional completion; the loser gets 412 or 409, then `CONTENT_CONFLICT`; the database `record_content` compare-and-set |
| Partial or abandoned multipart uploads | Abort in `finally`; the lifecycle rule (1 day); the operator listing |
| Silent corruption or truncation | Per-part SHA-256 verified by S3; a locally computed composite compared at completion; full SHA-256 re-checked by ingest before profiling |
| API reading or exfiltrating objects | Prefix-only role; code calls only `HeadObject`/`GetObjectAttributes` (tested); CloudTrail data events. **Residual:** IAM cannot express metadata-only access |
| Ingest writing, copying or deleting | The role has `GetObject` only; the code has no write path (import and Stubber tests); the bucket policy denies version deletion |
| Ingest reading another tenant's object | The key is derived from the signed, database-verified envelope, and tenant and dataset are checked. **Residual:** IAM scope is the environment prefix, not the exact object |
| Physical deletion by an application identity | Only the operator role holds `DeleteObjectVersion`, enforced by a bucket-policy deny for everyone else; the operator role is not assumable by the bootstrap role and needs MFA |
| A plain delete mistaken for deletion | Purge deletes every version and delete marker and verifies none remains; receipts list version ids; no code path calls an unversioned delete "deleted" |
| Cross-environment access | Separate buckets, keys and roles; role policies name only their own bucket and key; startup refuses mismatched identifiers |
| Credential theft from containers | No static keys; per-container 1 h credentials; IMDS blocked and verified; startup checks the role ARN; no fallback chain; values never logged |
| Unencrypted, or encrypted with the wrong key | Four bucket-policy denies (missing algorithm, missing key, wrong algorithm, wrong key); no `…IfExists` operator; no fallback to the bucket default; proven case by case, including multipart, in the D6 proof (a multipart denial stops provisioning, with no exception) |
| Hiding activity by altering the audit trail | A dedicated data-event trail; separate audit bucket and key; explicit denies on trail, audit bucket and audit key for every dataset role; Object Lock retention; log-file validation; confused-deputy conditions on CloudTrail delivery |
| Public exposure | Block Public Access, `BucketOwnerEnforced`, a TLS-only bucket policy, and a deny for principals outside the account |
| KMS misuse | A key per environment; the key policy allows use only through S3 in us-east-1 for this bucket's encryption context; API: `GenerateDataKey`+`Decrypt`; ingest and operator: `Decrypt` |
| Restore inconsistency | `verify-objects` reconciles database keys and objects (O-4 designs replication and restore) |
| Retaining rejected data too long | Provisional 7-day operator purge with listing, metric and alert (D2); O-5 sets the final policy |
| Leaking metadata through errors or logs | Closed error codes; the bucket, keys, ARNs and credentials never appear in responses or logs |

## Implementation plan (separate code PR, no AWS contact)

1. **Dependency.** Pin `boto3`/`botocore` in `uv.lock`. Run them through the
   existing dependency audit and image scans with no suppression. Add a mypy
   override for the untyped SDK behind a small typed client `Protocol`.
2. **`S3BlobStore`** (`nlw.storage.s3`), behind `BlobStore`. It has:
   - the write path above;
   - streamed, capped reads;
   - `head` through `GetObjectAttributes`;
   - version-aware purge helpers;
   - versioned listing.

   `TenantScopedBlobStore` stays the only way to address keys, using
   `versions/`.
3. **D1 refactor.**
   - The ingest runtime stops copying and deleting.
   - `publish_profile` keeps the key.
   - Leftover cleanup is removed.
   - The size refusal happens before finalize in both stores.
   - A migration narrows the key guard and revokes `nlw_ingest`'s key-update
     grant.
   - Tests are updated with **no weakening** of any invariant test.
4. **D2 operator tooling:**
   - `rejected-pending` and `purge-rejected`: bounded, oldest first, with
     dry-run, recovery-lock checks and idempotent re-runs;
   - the aggregate metrics and the dormant 7-day alert, with promtool tests.
5. **D5 settings and refusals.** The factory uses a credential provider pinned
   to the shared-credentials file, checks its identity at startup, and logs
   only the role ARN and account.
6. **Purge and `verify-objects`**, version-aware for S3. The operator CLI
   requires the operator profile and refuses to run with a runtime identity.
7. **Tests, with no network or AWS:**
   - a fake S3 client (conditional create, multipart with composite checksums,
     412/409, versions and delete markers, abort, listing);
   - botocore Stubber request-shape assertions (`IfNoneMatch`, SSE-KMS,
     Bucket Key, checksum, no ACLs, and no `GetObject` from API code);
   - concurrency (simultaneous uploads, a lost completion response, duplicate
     completion, abort);
   - purge (every version and marker removed; verification failing closed);
   - settings refusals and cross-environment refusal;
   - credential-file startup checks (missing, expired or wrong role);
   - negative controls for every guard.
8. **Host credential refresher.** Design and tests only, plus the provisioning
   review. The real script ships with O-6.

## Consequences

- O-2 is a reviewed design. No code, dependency or AWS resource exists yet.
  Uploads stay disabled in staging and production until O-6.
- ADR-031 tightens: the ingest runtime loses its write and delete paths, and
  the key can no longer move.
- **O-3** receives the version ids from each purge.
- **O-4** designs replication and restore for the `versions/` layout.
- **O-5** replaces the provisional 7-day rejected-file window and sets
  noncurrent-version expiry.
- On ECS or EKS, the host credential refresher is replaced by native task or
  pod identities.
