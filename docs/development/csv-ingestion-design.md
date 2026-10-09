# CSV ingestion and deterministic profiling — design note (Phase 2B)

Status: **local implementation, review-ready; not deployed.** Builds on the
dataset lifecycle foundation ([ADR-029](../adr/ADR-029-dataset-lifecycle-foundation.md),
migration `0024`) and is recorded as a decision in
[ADR-030](../adr/ADR-030-csv-ingestion-and-profiling.md). Written before
implementation from a trace of the code at `main` `9bc5f74`.

## 1. What exists (traced)

| Area | Current state |
|---|---|
| Dataset states | `ACTIVE → DELETING → DELETED` (trigger `dataset_guard`). |
| Version states | `QUARANTINED → PROFILING → PROFILED → ACTIVE → SUPERSEDED`, `REJECTED`, `DELETING → DELETED`; the transition table lives in `nlw.datasets.lifecycle` **and** the `dataset_version_guard` trigger (equal by unit test). |
| Lifecycle service | `nlw.datasets.service`: async functions over one `AsyncSession` that already carries a signed `api_request` context; dataset row locked first, then versions; compare-and-set updates; one `dataset_events` row per transition. `create_version` / `transition_version` / `activate_version` exist with **no route**. |
| Roles and RLS | Forced RLS on all three tables. `nlw_app`: member `SELECT`; admin/owner `INSERT`/`UPDATE`; never `DELETED`; no `DELETE`. Events are admin-readable and append-only. `nlw_worker`, `nlw_scheduler` and `PUBLIC` have nothing. The tombstone uses the owner credential (`python -m nlw.ops.datasets`). |
| API + flag | `nlw.api.routers.datasets`: metadata routes mounted only when `DATASETS_API_ENABLED=true`; `Settings` refuses that flag in staging and production. |
| Files | `nlw.storage.blob`: `LocalBlobStore` (atomic temp + rename, byte cap) and `TenantScopedBlobStore` (`{quarantine\|datasets}/{tenant}/{dataset}/{object}`, traversal refused). No S3 client is in `uv.lock`, and owner decision 2026-09-29 says an S3 client needs its own ADR. |
| Parsing | `nlw.ingest.profile.profile_csv` (`profile-1`): loads the whole file into memory (~14× input), accepts UTF-16/cp1252, sniffs delimiters, guesses headers, keeps sample values. It is not reachable from any route. |
| Async processing | Dramatiq actors on `nlw_worker` for workflow runs only. The worker has no dataset grants. |
| Body limit | `BodySizeLimitMiddleware` buffers every body (1 MB) before routing, so the upload path must be exempted and capped in the route (established in `datasets.md`). |
| BFF | The Next.js `/api/nlw/[...path]` proxy has an exact allowlist and buffers bodies with `req.text()`. |
| Backup | `nlw.backup.validate` checks forced RLS on the dataset tables. The offboarding inventory classifies every table and lists "dataset object bytes" as outside the database. |

## 2. Decisions for this branch

1. **Strict pilot profiler, new contract `profile-2`.** A new streaming profiler,
   `nlw.ingest.strict`, enforces the pilot policy:
   - UTF-8 (BOM optional) only; comma-delimited; exactly one header row;
   - non-empty, unique normalized names; consistent row width;
   - no NUL bytes or control characters;
   - bounds on bytes, rows, columns and field length.

   Memory is bounded by per-column accumulators (distinct counting uses 16-byte
   digests up to a cap), never by holding rows. It stores **no sample values**.

   `profile-1` and `profile_csv` stay unchanged as library code (their golden
   tests remain); uploads use only `profile-2`.
2. **Isolated profiling process.** The profiler runs in a child process
   (`python -m nlw.ingest.runner`). The parent streams the stored object to the
   child's stdin. The child has:
   - no database, storage, credentials or network (sockets disabled);
   - an address-space limit where the OS supports it, and a wall-clock kill;
   - a process-global `csv.field_size_limit` that cannot leak into the API.

   It returns either a validated profile or a reject code, never content.
3. **Processing identity: decided by O-1, see [ADR-031](../adr/ADR-031-dataset-ingest-runtime-boundary.md).**
   - *Originally* (ADR-030) the processing writes ran as `nlw_app` under the
     uploading admin's `api_request` context.
   - **Now** they run in a dedicated runtime, `nlw.ingest_service`, as the
     least-privilege `nlw_ingest` role under a `dataset_ingest` context signed
     with its own key: ONE version in one workspace, no human identity
     (`actor_kind = service`, `actor_user_id` NULL). The API records an
     immutable processing request and enqueues a database-anchored work
     envelope; it can no longer take a lease, insert a profile, or publish or
     reject a version being processed.
   - The general worker and the scheduler still get **nothing**.
   - In staging/production the role is dormant (NOLOGIN, no key, no container)
     until O-6.
4. **Storage.**
   - The key is `quarantine/{tenant}/{dataset}/{version_id}`: opaque, derived
     server-side, never from the filename.
   - The bytes stream to a partial file and are linked into place
     **without overwrite** (`link`, refusing an existing object). Size and
     SHA-256 are computed while streaming.
   - After a successful profile, the object is copied to
     `datasets/{tenant}/{dataset}/{version_id}` with its digest re-verified. The
     version's key moves to the `datasets/` area in the same transaction as
     `PROFILING → PROFILED`, and the quarantine copy is then removed.
   - A rejected version's quarantine object is removed right after rejection.
   - Environment scoping: the local backend root is
     `{DATASET_STORAGE_ROOT}/{APP_ENV}`, and a deployed backend must use a
     per-environment bucket or prefix. Environment is not part of the database
     key format (`0024` CHECK).
   - Local backend: `development`/`local`/`test` only. There is **no S3
     adapter** (dependency not approved; protocol ready). **Owner decision O-2.**
   - The storage root is refused if it is inside, or contains, a configured
     backup repository path.
5. **Migration `0025_dataset_ingestion` (additive).**
   - New tables:
     - `dataset_profiles`: one immutable `profile-2` per version; admin-only
       read and insert; no update or delete for runtime roles.
     - `dataset_semantic_revisions`: append-only, numbered per version, with
       `confirmed_by`/`confirmed_at` and a bounded, validated mapping.
   - New column: `dataset_versions.upload_idempotency_key`, set at insert,
     immutable, unique per dataset.
   - Widened closed vocabularies:
     - new rejection codes;
     - event `VERSION_OBJECT_PURGED`: operator-only, `DELETING → DELETING`,
       evidence and not a transition.
   - Replaced trigger function `dataset_version_guard()` (the function, not the
     `0024` file). It keeps every rule and adds:
     - the key may move `quarantine/ → datasets/` (same name) only on
       `PROFILING → PROFILED`;
     - `PROFILED` requires a profile;
     - `ACTIVE` requires a confirmed semantic revision;
     - the idempotency key is immutable.
   - The signed-policy inventory grows from 61 to 65.
6. **API** (added under the same flag):
   - `POST /datasets/{id}/versions`: initiate; JSON with filename and declared
     size; `Idempotency-Key` header required.
   - `PUT /datasets/{id}/versions/{vid}/content`: raw `text/csv` body, streamed
     with a route-level cap; exempted from the global buffering middleware by
     exact path shape.
   - `POST …/process`: admin **re-dispatch** for a version stuck in
     `QUARANTINED` or in a stale `PROFILING`: it re-enqueues the latest fresh
     processing request (or records a new one). It never processes.
   - `GET …/profile` (admin).
   - `GET`/`POST …/semantics` (admin).
   - `POST …/activate` (admin).

   Processing (ADR-031): the content `PUT` records the content AND an immutable
   processing request in one transaction, then enqueues the request's envelope
   after commit. The dedicated ingest runtime (`nlw_ingest`) claims, profiles
   and settles; the API cannot. The client polls the version status.

   Lost enqueues (commit succeeded, the broker did not): the `PUT` answers 503
   `PROCESSING_NOT_QUEUED` with the request durable. Recovery is an idempotent
   retry of the `PUT` (it re-sends the same request), `POST …/process`, or the
   operator sweep `python -m nlw.ops.datasets dispatch-pending` (bounded,
   oldest first, one at a time). Delivery is at-least-once only once one of
   these has sent the message. The lease makes processing idempotent.

   Unattended recovery (O-7, [ADR-032](../adr/ADR-032-dataset-ingest-dispatcher.md)):
   the `ingest-dispatch` process, running as `nlw_ingest_dispatch` with one
   read-only function, re-sends waiting requests older than about 2 minutes.
   It is bounded and oldest first, and an alert fires on anything pending over
   15 minutes. It is dormant in staging and production until O-6. Without it,
   a lost enqueue waits for one of the manual paths above.

   Object/database boundary: the object is linked before the record commits,
   and these are not one transaction.
   - A failure after the link leaves an unrecorded object. `verify-objects`
     lists it. Only the identical bytes can adopt it (write-once), and the
     purge of a `DELETING` version removes it.
   - A deletion during the stream refuses the record (409); the bytes go with
     the purge.
7. **Deletion.** The API requests deletion (`DELETING`, unusable at once; no
   storage I/O in the request). The operator then runs:
   - `python -m nlw.ops.datasets purge`: deletes every object under the
     dataset's (or version's) keys in both areas, **verifies absence**, writes a
     deletion receipt to the configured sink, and appends
     `VERSION_OBJECT_PURGED`.
   - `tombstone`: refuses any version whose key still resolves to an object, or
     that has no purge event. It then scrubs the key, filename, profile and
     semantic labels.

   The external deletion log is a **narrow interface** with a local fake sink
   only. It is a launch gate (**owner decision O-3**: provider).
8. **Backup and restore.**
   - The PostgreSQL backup holds metadata, profiles, semantics and events,
     never bytes or storage credentials.
   - `python -m nlw.ops.datasets verify-objects` reports version-to-object
     mismatches (missing, orphaned or digest-mismatched) by id only, so a
     database-only restore is never mistaken for a file restore.
   - Object durability and restore policy: **owner decision O-4**.
9. **Failure representation.**
   - Policy and validation failures move the version to `REJECTED` with a
     closed `rejection_code`. Events carry codes only.
   - Internal failures (storage error, crashed profiler) keep the version in
     `QUARANTINED`/`PROFILING` for the admin retry, logged with an error class
     only. A profiler crash or timeout becomes `PROCESSING_FAILED` /
     `PARSE_TIMEOUT` rejections.
   - A `REJECTED` version can never become `ACTIVE`; a new upload is a new
     immutable version.
10. **Planner and model boundary.**
    - `nlw.datasets`, `nlw.storage` and `nlw.ingest` stay out of the planner,
      feasibility, registry, tools and evaluation code.
    - No dataset tool exists, and no model call occurs anywhere in ingestion.
    - Semantic labels are inert data (closed enum plus a bounded display
      label), never instructions.
    - The synthetic `/analytics/datasets` catalogue is untouched.

## 3. Pilot limits (defaults ≤ hard ceilings)

| Limit | Default | Ceiling (config cannot exceed) |
|---|---|---|
| File bytes (= decoded bytes; no compression accepted) | 25,000,000 (stricter than 25 MiB; the `0024` CHECK) | 25,000,000 |
| Data rows | 250,000 | 1,000,000 |
| Columns | 200 | 200 |
| Field length (characters) | 8,192 | 32,768 |
| Header length (characters) | 256 | 256 |
| Exact distinct tracking per column | 1,000 (then reported as "over limit") | 1,000 |
| Profiling wall clock | 60 s | 300 s |
| Profiler address space (Linux) | 768 MiB | 2 GiB |

These are pilot defaults, not permanent product decisions.

## 4. Threat model additions

| Threat | Control |
|---|---|
| Hostile CSV exhausting memory or CPU | streaming parse, bounded accumulators, child-process memory and time limits |
| Path traversal or key forgery | server-derived keys from UUIDs; segment regex; root containment; tenant prefix check; DB CHECK on key shape and tenant |
| Overwriting a stored version | no-clobber link; key set once (trigger); version identity immutable |
| Content-type spoofing | `Content-Type` ignored for trust; magic-byte and text checks on bytes |
| Leaking cell values | no samples; min/max/mean suppressed on flagged columns; logs carry codes, ids and counts only (canary test) |
| Formula injection | formula-like cells counted, headers neutralized for display, nothing evaluated |
| Retry duplication | `Idempotency-Key` unique per dataset; content `PUT` idempotent on an equal digest, 409 otherwise |
| Tombstone of present bytes | tombstone re-checks the store live and requires a purge event |
| Premature exposure | flag refused in staging/production; local backend refused outside development; no planner path |

## 5. Owner decisions (open)

- ~~**O-1**~~ **decided**: dedicated `nlw_ingest` role, `dataset_ingest` purpose
  and ingest runtime ([ADR-031](../adr/ADR-031-dataset-ingest-runtime-boundary.md));
  dormant outside development until O-6;
- **O-2** S3-compatible client dependency and its ADR; per-environment bucket;
  object durability;
- **O-3** external deletion-log provider and record retention;
- **O-4** object backup/restore policy and RPO for uploaded files;
- **O-5** retention periods (ADR-029 decision 14, unchanged);
- **O-6** when `DATASETS_API_ENABLED` may be allowed outside development.
