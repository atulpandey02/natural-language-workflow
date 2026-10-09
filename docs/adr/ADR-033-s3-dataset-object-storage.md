# ADR-033: Production dataset object storage on AWS S3 (owner decision O-2)

Status: **proposed — decisions D1–D6 below need owner review before
implementation.** No AWS resource exists or is contacted by this change.
Branch `docs/o2-s3-dataset-storage`.
Date: 2026-10-09.
Builds on [ADR-030](ADR-030-csv-ingestion-and-profiling.md) (storage protocol, write-once,
verified purge), [ADR-031](ADR-031-dataset-ingest-runtime-boundary.md) (ingest boundary) and
[ADR-032](ADR-032-dataset-ingest-dispatcher.md) (dispatcher). Provisioning templates:
[dataset-s3-provisioning](../runbooks/dataset-s3-provisioning.md) (NOT RUN).

## Context

Dataset bytes live behind the `BlobStore` protocol (`nlw.storage.blob`). Only
`LocalBlobStore` exists, and it is refused in staging and production, so no
deployed environment has a dataset store (O-2). The local store guarantees:

- keys derived from ids only;
- write-once objects (temp file + `link(2)`);
- a streamed SHA-256 and a byte cap;
- version-scoped listing for purge, and `verify-objects` for restore checks.

The owner has decided O-2 as follows.

## Approved decisions (owner, 2026-10-09)

| Area | Decision |
|---|---|
| Provider | **AWS S3**, region **us-east-1**. **boto3** is approved as the client. No other abstraction layer. |
| Buckets | Separate buckets: `nlw-staging-datasets-<account>-us-east-1[-suffix]` and `nlw-production-datasets-<account>-us-east-1[-suffix]`. Never shared between environments, never separated only by prefix in one bucket, never the Restic backup bucket, never public. |
| Bucket security | All four Block Public Access settings on; Object Ownership `BucketOwnerEnforced` (ACLs disabled); default SSE-KMS with a **separate customer-managed KMS key per environment**; S3 Bucket Key on; TLS-only bucket policy; Versioning on; no Object Lock initially; no public endpoints. |
| Lifecycle | Abort incomplete multipart uploads (application abort plus a lifecycle rule). Noncurrent-version expiry waits for O-5. |
| Credentials | EC2 instance roles; temporary credentials from the SDK chain. **No static access keys** anywhere, including `.env.prod`. |
| Identities | Separate permissions for the API (create only, conditional), the ingest runtime (read only), and the operator (version-aware deletion). Neither the API nor ingest may physically delete. |
| Write-once | `If-None-Match: *` on `PutObject`, `CompleteMultipartUpload` and `CopyObject`. The bucket policy **denies** unconditional writes under the dataset prefix. |
| Integrity | SHA-256 computed while streaming; bounded part sizes; stored size and checksums verified before the database records the object. |
| Purge | Version-aware: delete every version and delete marker of the exact key, verify none remains, write the receipt (O-3), and only then tombstone. A plain `DeleteObject` is never called physical deletion. |
| Code shape | The S3 store sits behind the existing protocol. The local store stays for development; tests use a fake S3 client. No provider-specific behaviour reaches the API or the ingest runtime. |

Facts this design relies on (AWS documentation, checked 2026-10-09):

- conditional writes work on `PutObject`, `CompleteMultipartUpload` and `CopyObject`;
- bucket policies can require them with the condition keys `s3:if-none-match`
  and `s3:ObjectCreationOperation`;
- for multipart uploads, SHA-256 is only available as a **composite** checksum
  (full-object multipart checksums exist only for the CRC algorithms);
- with Versioning on, `DeleteObject` without a version id only adds a delete
  marker, and physical removal needs `DeleteObjectVersion`.

## Conflicts with today's code, and recommended resolutions (need review)

The approved identity model conflicts with three current behaviours:

- the ingest runtime **writes** a published copy (`quarantine/` → `datasets/`,
  `copy_verified`) and **deletes** quarantine and rejected bytes
  (`processing.py`);
- the API **deletes** its own object after a size mismatch (`ingestion.py`);
- one instance role per environment cannot give containers on the same host
  different permissions.

### D1 — one immutable object per version (recommended)

**Recommendation.** Stop moving bytes. Each version has exactly one object,
written once by the API and never modified or moved. "Published" becomes a
database state only (it already is the source of truth), and the
`storage_object_key` stays the same.

- The ingest runtime needs only `GetObject` (which also covers `HeadObject`)
  and `kms:Decrypt`. It no longer copies or deletes anything.
- The local store gets the same single-object behaviour, so dev and prod
  share one code path.
- Migration 0025's guard already lets the key stay unchanged. A later
  migration can then revoke `nlw_ingest`'s `UPDATE (storage_object_key)`
  grant, tightening ADR-031.

**Alternative.** Keep two areas. The ingest runtime would hold conditional
`PutObject` on `datasets/` and plain `DeleteObject` on `quarantine/`. Under
Versioning that delete only adds a marker, so bytes are not removed anyway.
This is more privilege for no physical benefit.

### D2 — rejected files under Versioning

Today a rejected file's bytes are removed promptly by the ingest runtime.
Under D1 and the "no physical deletion by runtimes" rule, that stops.

**Recommendation.** A rejected version keeps its single object until the
**operator purge** removes every version of it. Rejected versions become
`DELETING` candidates on a schedule that O-5 defines, and the purge already
handles `REJECTED`. Until O-5 decides, the runbook requires purging rejected
versions within **7 days**.

Lifecycle expiry may supplement this later (tag-filtered, O-5). It is never
the evidence for an individual deletion.

This is a documented change of behaviour: a rejected file is no longer deleted
within the same request.

### D3 — per-container credentials on one host (recommended)

Containers on the same EC2 host can all reach the same instance-profile
credentials through IMDS. So "separate API, ingest and operator permissions"
cannot be enforced by one instance role.

**Recommendation.**

- **Instance role** `nlw-<env>-dataset-runtime` holds **only**
  `sts:AssumeRole` on two narrow roles: `nlw-<env>-dataset-api` and
  `nlw-<env>-dataset-ingest`. It has no S3 or KMS permissions itself.
- **IMDSv2 is required, with hop limit 1,** so containers cannot reach IMDS at
  all.
- **A host credential refresher** (a systemd timer, root-owned, about 15
  minutes) assumes each narrow role for one hour. It writes each service's
  temporary credentials into its own `0400` tmpfs file, which is mounted
  read-only into **that service's container only**. The SDK reads the file
  through `AWS_SHARED_CREDENTIALS_FILE`. This mirrors how per-service
  signing-key files are delivered today.
- **The operator role** `nlw-<env>-dataset-operator` is **not** assumable by
  the instance. It is assumed by a named operator principal, with MFA, only
  for purge and verify sessions.

Residual risk: host root can obtain any role the instance can assume. That is
the same trust boundary as the host's signing-key files.

The simpler alternative, accepting one union role for the API and ingest, is
**not** recommended. It hands the API read access to every object and the
ingest runtime write access.

### D4 — object key layout

The key layout is adopted as approved:
`quarantine/<workspace_id>/<dataset_id>/<version_id>/source.csv`. It is built
from ids only and never contains filenames, names or emails. Today's local
keys are `quarantine/<t>/<d>/<v>`.

- The `/source.csv` leaf is added to both stores.
- The migration 0025 check that the key's fourth segment is the version id
  still holds.
- Only development data has the old shape. No migration is needed, and
  `verify-objects` and purge accept both shapes for local stores.

Open question for the reviewer: under D1, the `quarantine/` area name stops
being accurate once a version is published. Keep it, or rename the leaf area
to `uploads/`? The recommendation is to keep it, for parity with the approved
text and existing guards.

### D5 — configuration names

The existing settings convention is recommended, rather than the `NLW_`-prefixed
names in the decision text:

| Setting | Value |
|---|---|
| `DATASET_STORAGE_BACKEND` | `s3` |
| `DATASET_S3_BUCKET` | the environment's bucket |
| `DATASET_S3_REGION` | `us-east-1` |
| `DATASET_S3_KMS_KEY_ARN` | the environment's key ARN |

Settings will refuse:

- static `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in the environment;
- a bucket equal to the Restic repository's bucket;
- a KMS key ARN outside `us-east-1`.

### D6 — where the S3 backend is allowed before O-6

**Recommendation.** `s3` is allowed by configuration in every `APP_ENV`.
`DATASETS_API_ENABLED` stays **refused** in staging and production (O-6), and
no deployed Compose file runs the ingest runtime or dispatcher. So a
configured bucket cannot receive uploads there until O-6.

The real-AWS IAM separation proof (sequence step 6) runs in an isolated
session (`APP_ENV=local`, operator laptop or a disposable host) against the
**staging** bucket, with owner approval.

## Design (subject to D1–D6)

### Write path (API)

1. **Create** with `CreateMultipartUpload` on the derived key, passing:
   - `ChecksumAlgorithm=SHA256`;
   - `ServerSideEncryption=aws:kms`;
   - `SSEKMSKeyId=<env key>`;
   - `BucketKeyEnabled=true`.
2. **Stream** with fixed **8 MiB** parts, so a 25 MB file needs at most 4. Each
   part carries `ChecksumSHA256`, which S3 verifies per part. Our full-object
   SHA-256 and the byte count are computed while streaming, with the cap
   enforced as bytes are read.
3. **Before completing**, if the size is not exactly the declared size,
   `AbortMultipartUpload`. Nothing is created, so no delete is needed, which
   removes today's API delete.
4. **Complete** with `CompleteMultipartUpload` and `If-None-Match: *`. To
   verify, compute the expected composite checksum locally (SHA-256 over the
   concatenated part digests, `-N`) and compare it with the returned
   `ChecksumSHA256`. That binds the stored bytes to the bytes we hashed,
   without reading them back.
5. **Outcomes:**
   - **412** (the key exists): `HeadObject` with checksum mode. If the size
     and composite match ours, it is an idempotent retry (for example, a lost
     response to our own completion); otherwise it is `CONTENT_CONFLICT`.
   - **409** (a concurrent conditional write): retried once, then
     `CONTENT_CONFLICT`.
   - **Any failure:** `AbortMultipartUpload` in `finally`.
6. **Record:** the database then records the full SHA-256, the size and the
   key, as today.

### Read path (ingest)

- **Integrity:** `GetObject` streams into the isolated profiler, which already
  re-hashes and refuses a mismatch against the database's full SHA-256. No
  object metadata is trusted.
- **Bounds:** reads are bounded by the declared size, with a byte cap enforced
  on the stream.

### Purge (operator)

1. Abort any in-progress upload for the key prefix
   (`ListMultipartUploads` + `AbortMultipartUpload`).
2. `ListObjectVersions(Prefix=<exact version key>)`.
3. `DeleteObjectVersion` for every version id and every delete marker.
4. Verify that `ListObjectVersions` returns nothing for the prefix.
5. The receipt (O-3) records the deleted version ids.
6. Tombstone only after verification. A failed verification leaves the
   version `DELETING`.

### `verify-objects` (restore validation)

- **Coverage:** `ListObjectVersions` over the dataset prefix finds both
  unaccounted objects and missing current versions. Every live recorded key
  must have a current version whose size matches the database; a full re-hash
  is available as `--deep`.
- **Noncurrent versions:** reported separately; they are expected until O-5
  expiry.

### Retries and timeouts

- **Retries:** botocore `standard` retry mode, with 3 attempts. Bounded connect
  and read timeouts keep the API and ingest from hanging on S3.
- **Failure mapping:** an S3 error maps to the existing closed error codes,
  such as 503 for an unavailable store. It never echoes the bucket, key or ARN.

### IAM model (templates in the provisioning runbook)

| Principal | S3 (bucket ARN plus prefix) | KMS (environment key, encryption context = bucket ARN, because Bucket Key is on) |
|---|---|---|
| `…-dataset-api` | `PutObject` (conditional only, by bucket policy), `AbortMultipartUpload`, `GetObject` (HeadObject for the idempotent-retry check) on `quarantine/*` | `GenerateDataKey`, `Decrypt` |
| `…-dataset-ingest` | `GetObject` on `quarantine/*` | `Decrypt` |
| `…-dataset-operator` | `ListBucket`, `ListBucketVersions`, `ListBucketMultipartUploads` (prefix-conditioned); `GetObject`, `GetObjectVersion`, `DeleteObjectVersion`, `AbortMultipartUpload` | `Decrypt` |
| `…-dataset-runtime` (instance) | none | none (only `sts:AssumeRole` on the API and ingest roles) |

**Bucket policy (deny statements):**

- deny non-TLS requests;
- deny `PutObject` without `s3:if-none-match` under `quarantine/` (keeping
  the multipart part calls allowed through `s3:ObjectCreationOperation`);
- deny SSE other than `aws:kms` with this environment's key;
- deny `DeleteObjectVersion` and `PutBucket*` to everyone except the operator
  role and the account administration role;
- deny any principal outside the account.

**Audit:** CloudTrail **data events** for this bucket only (object-level
read and write), sent to a separate log bucket. These are the audit source for
O-3 and O-4. Server access logs are not used.

## Implementation plan (separate PR after this ADR is approved)

1. **Dependency.** Pin `boto3` and `botocore` in `pyproject`/`uv.lock`. Run
   them through the existing dependency audit and image scans, with no
   suppression. Add a mypy override for the untyped SDK; the store exposes a
   small typed `Protocol` over the client.
2. **`S3BlobStore`** (`nlw.storage.s3`), behind `BlobStore`:
   - the write path above;
   - `open` (streamed and bounded);
   - `digest` (streamed re-hash);
   - `exists`/`head`;
   - version-aware `delete_version_and_verify`;
   - `list_prefix` over versions.

   `TenantScopedBlobStore` stays the only way callers address keys.
3. **D1 refactor.**
   - The ingest runtime stops copying and deleting.
   - `publish_profile` keeps the key.
   - The leftover-cleanup logic becomes "nothing to remove".
   - The local store follows the same rules.
   - Size refusal happens before finalize in both stores, so the API never
     deletes.
   - Existing tests are updated, with **no weakening** of any invariant test.
4. **Settings and factory.** The D5 settings and refusals; the factory builds
   the S3 store from the default credential chain only; boot checks are
   unchanged.
5. **Purge, `verify-objects` and the operator CLI**, version-aware. The CLI's
   S3 path requires an operator profile and refuses to run with the runtime
   roles.
6. **Tests, with no network or AWS.**
   - A **fake S3 client** implementing the used subset: conditional create,
     multipart parts and composite checksums, 412/409, versions, delete
     markers, abort, and listing.
   - `botocore.stub.Stubber` assertions on exact request shapes: `IfNoneMatch`,
     SSE-KMS parameters, Bucket Key, checksum algorithm, and no ACL
     parameters.
   - Concurrency tests: simultaneous uploads, a lost completion response,
     duplicate completion, and abort after failure.
   - Purge tests: every version and delete marker removed, and verification
     failing closed.
   - Settings refusals.
   - Negative controls for each guard.
7. **Provisioning runbook** (templates only) and its review. **No AWS
   resources are created by the PR.**
8. **After merge, and with separate approval:** the isolated real-AWS IAM
   separation proof (sequence step 6) against the staging bucket.
   - The API role cannot read another prefix or delete a version.
   - The ingest role cannot write.
   - An unconditional put is denied by the bucket policy.
   - Non-TLS access is denied.
   - The wrong KMS key is denied.
   - The operator purge leaves no version behind.

## Consequences

- O-2 becomes a reviewed design. It is not deployed and creates no AWS
  resources. Uploads stay disabled in staging and production until O-6.
- **O-4** (object durability and restore) must design for this layout: a
  second recovery bucket in another region or account, the RPO/RTO targets,
  and restore reconciliation through `verify-objects`.
- **O-3** must receive the version ids deleted by each purge.
- **O-5** must set the noncurrent-version expiry and the rejected-file purge
  window.
- D1 tightens ADR-031: the ingest runtime loses its write and delete paths.
