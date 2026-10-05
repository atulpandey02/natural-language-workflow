# ADR-030: CSV ingestion and deterministic profiling (Phase 2B)

Status: accepted for local implementation; **not deployed**. Branch
`feat/phase2-csv-ingestion-profiling`.
Date: 2026-10-05.
Builds on [ADR-029](ADR-029-dataset-lifecycle-foundation.md) (lifecycle,
`0024`). Design note: [csv-ingestion-design](../development/csv-ingestion-design.md).

## Context

ADR-029 created tenant-isolated dataset metadata, but no bytes, profiles or
review. This ADR adds the first path for an authorized workspace administrator
to upload one CSV. The upload becomes an immutable version that is profiled
deterministically, reviewed, activated and, later, physically deleted. The rule
"models reason, code enforces" holds throughout: no model ever sees uploaded
content, and no planner path reaches it.

## Decision

### Flow and state machine (unchanged states; ADR-029 transitions)

```
initiate (admin, Idempotency-Key)            -> QUARANTINED (no content)
PUT content (streamed, == declared size)     -> QUARANTINED (digest + quarantine key, set once)
claim                                        -> PROFILING                (event)
isolated profiler: profile-2                 -> PROFILED + profile row   (event; key quarantine/ -> datasets/)
              or a closed rejection code     -> REJECTED                 (event; bytes deleted)
admin confirms semantics (revision n)        -> (no state change; append-only revision)
admin activates                              -> ACTIVE (previous ACTIVE -> SUPERSEDED)  (events)
admin requests deletion                      -> DELETING (unusable at once)            (events)
operator purge (delete + verify + receipt)   -> DELETING (VERSION_OBJECT_PURGED evidence)
operator tombstone                           -> DELETED (scrubbed)                     (events)
```

Every state transition appends exactly one `dataset_events` row. A `REJECTED`
version can never become `ACTIVE`; a corrected file is a new version.

### Storage

- A `BlobStore` protocol. The only implementation is `LocalBlobStore`, under
  `{DATASET_STORAGE_ROOT}/{APP_ENV}`, refused in staging and production and
  refused inside the backup repository. **No S3 adapter**: an S3 client is a
  new runtime dependency needing an owner decision and its own ADR (2026-09-29
  owner decision). Without a store, the upload routes are not mounted.
- Keys are server-derived and opaque: `{quarantine|datasets}/{tenant}/{dataset}/{version_id}`.
  They are never built from the filename, never returned by the API and never
  logged.
- Objects are write-once. Bytes stream to a partial file named for the version,
  then are linked into place, which fails if the object exists. Size and SHA-256
  are computed while streaming.
- Publication is a digest-verified copy to `datasets/`, recorded together with
  `PROFILED`, followed by removal of the quarantine copy. Version purge finds
  crash-orphaned partials.

### Validation and profiling (`profile-2`)

`nlw.ingest.strict` streams the bytes once. The policy:
- UTF-8 or UTF-8 with BOM only;
- comma-delimited, strict quoting;
- exactly one header row of non-empty, at most 256-character, non-numeric,
  unique normalized names;
- every row as wide as the header, and at least one data row;
- no NUL bytes or control characters, and no archive or binary signatures;
- limits on bytes, rows, columns, field length and wall clock.

Each limit is a pilot default that configuration can lower but never raise past
a hard ceiling (see the design note).

Memory is bounded by per-column accumulators. Distinct values are counted exactly
up to 1,000 (as 16-byte digests), then reported as "over limit". A 24 MB,
200-column file peaks at about 16 MB traced memory, against 225–336 MB for
`profile-1`.

The profile holds counts, inferred types (documented order and 98 % threshold),
null fractions, distinct counts, string lengths, parse errors, formula-like
counts, sensitivity indicators, encoding, delimiter and the content digest.
**No sample values.** Min, max and mean appear only for numeric and temporal
columns without an indicator. The same bytes give a byte-identical profile.

The profiler runs in a child process (`python -m nlw.ingest.runner`):
- isolated interpreter (`-I`) with an empty environment, so no database URL,
  key or credential;
- sockets disabled, and an address-space and CPU cap where the OS allows;
- a wall-clock kill by the parent.

Its only output is one JSON line: a profile, a rejection code, or a
content-free failure.

### Database (migration `0025_dataset_ingestion`, additive; one head)

- `dataset_profiles` (one immutable profile per version, recorded only while
  `PROFILING` with the version's digest) and `dataset_semantic_revisions`
  (append-only, consecutive, only while `PROFILED`, `confirmed_by` bound to the
  **signed** user by RLS).
- `dataset_versions.upload_idempotency_key` (immutable, unique per dataset).
- Rejection codes and event types widened. The new operator-only
  `VERSION_OBJECT_PURGED` event is excluded from the runtime insert policy.
- `dataset_version_guard()` replaced:
  - the storage key moves `quarantine/ -> datasets/` only on
    `PROFILING -> PROFILED`;
  - `PROFILED` needs the profile;
  - `ACTIVE` needs confirmed semantics.
- Forced RLS on the signed context. `nlw_app` gets SELECT and INSERT as
  admin/owner only. `nlw_worker`, `nlw_scheduler` and PUBLIC get nothing, and
  no SECURITY DEFINER function is added.
- Signed policies: 61 → 65. Downgrade is for disposable environments only; fix
  forward.

### Foundation hardening (pre-PR review, 2026-10-05)

All of the following are in migration `0025`, edited in place because it is
unreleased, and in the service:

- **Storage keys bound to the version.** A key's object component must equal
  the version id (`ck_dataset_versions_key_names_version`). Quarantine and
  published keys are both derived from the immutable id, and no session can
  point a version at another version's object.
- **Leases on PostgreSQL time.** `processing_lease_token` and
  `processing_lease_expires_at` exist only while a version is `PROFILING`.
  - Acquire, stale reclaim and renew are each a single compare-and-set
    `UPDATE` evaluated with `now()`; the API host clock is never consulted.
  - Publishing, and rejection by the processor, require the current token.
    The database refuses leaving `PROFILING` without a live lease.
  - A background renewer keeps the lease (default ttl 120 s, renewed every
    30 s). Losing it abandons the work, which publishes nothing.
- **Profiler termination.** Every exit path stops and reaps the child:
  SIGTERM, a 2 s grace, then SIGKILL, and always a wait for its exit status.
- **One control-character rule.**
  - Unicode Cc (C0, DEL, C1) is refused in every user-controlled field.
  - TAB, LF and CR are allowed only in CSV data cells.
  - Headers, names, descriptions, filenames and semantic labels also refuse
    format characters.
- **Verifiable deletion receipts.** Purge evidence stores the receipt's sink,
  id and deletion-set digest. The tombstone verifies the receipt
  (`deletion-receipt-2`), and anything but `VERIFIED` blocks it. Only a local
  fake verifier exists, refused in staging and production.
- **Authentic lifecycle events.** No SECURITY DEFINER function is involved:
  - An event is accepted only if it records the transition the same
    transaction made: exact from/to, entered at `now()`, one per transition.
  - Runtime events name the signed user.
  - A runtime-role transition cannot commit without its event.

### Identity for ingestion (owner decision O-1 flagged)

There is **no new database role.** Ingestion database steps run as `nlw_app`,
each in a short transaction under a freshly signed `api_request` context for
the uploading admin (`actor_kind = service`), which is the ADR-029 "internal
service, admin authority" row. RLS re-checks admin membership every time, so a
demoted uploader fails closed. The general worker has no dataset access.

A dedicated `nlw_ingest` role would need:
- a new signed purpose, which means replacing the SECURITY DEFINER verifier
  `app_ctx_claims()`;
- a new key class with escrow;
- a deployment secret.

That is only warranted if processing moves to an unattended queue worker. That
is the owner's decision.

### API (behind `DATASETS_API_ENABLED` + a configured store)

The routes are admin/owner only:
- `POST /datasets/{id}/versions`, with a required `Idempotency-Key`;
- `PUT …/versions/{vid}/content`, raw body streamed and capped at the declared
  size;
- `POST …/process`;
- `GET …/profile`;
- `GET`/`POST …/semantics`;
- `POST …/activate`.

Further rules:
- Authentication runs in its own short transaction before the body streams.
- Only that exact PUT path is exempt from the global 1 MB buffering cap, and
  `Content-Type` is not trusted.
- Another workspace's ids return 404.
- Members keep the ADR-029 metadata reads; profiles and semantics are
  admin-only.
- The flag remains refused in staging and production (owner decision O-6).

### Semantic confirmation (`semantics-1`)

Per column the admin sets:
- a label (1–80 characters, no control characters, not starting with a formula
  marker);
- a semantic type from a closed list;
- a role from a closed list, compatible with the type;
- whether the column may be used for analysis.

Columns flagged as possible national-ID or card numbers can never be enabled.
Contact columns can be enabled only as identifiers.

There is no expression, SQL or free-form instruction, and nothing is confirmed
automatically. The UI's starting values are a deterministic suggestion from the
profile. Activation re-validates the latest revision against the profile.

### Deletion

1. The admin request makes the dataset or version `DELETING` at once; the API
   does no storage I/O.
2. The operator's `purge` deletes every stored object, including partials, and
   verifies absence.
3. `purge` then appends a `deletion-receipt-2` record to the deletion log and
   records `VERSION_OBJECT_PURGED`. It refuses to run without a log.
4. The operator's `tombstone` refuses any version whose bytes were ever stored
   unless all of these hold:
   - a purge was recorded after the request;
   - a live check finds nothing stored;
   - the purge's deletion receipt **verifies** (sink, workspace, dataset,
     version, digests, deletion time not before the request).
5. The tombstone scrubs the key, filename, profile and semantic mappings.

The deletion log is a narrow interface with a local fake sink only. The
external provider is a launch gate (owner decision O-3).

### Backup and restore

- PostgreSQL backups hold metadata, profiles, semantics and events, never bytes
  or storage credentials. Uploaded objects need their own durability and
  restore policy (owner decision O-4).
- `python -m nlw.ops.datasets verify-objects` reports missing objects, digest
  mismatches and unaccounted objects by id only. A database-only restore
  therefore shows its live versions as missing objects; it never presents them
  as restored files.

## Consequences

- The workflow is complete and tested locally. Staging and production stay
  disabled by configuration.
- Later planner or query work must add an explicit, separately reviewed path.
  Nothing here is visible to the planner (boundary tests).

### Open owner decisions

| Decision | Topic |
|---|---|
| O-1 | ingest role |
| O-2 | S3 client and per-environment bucket |
| O-3 | external deletion-log provider |
| O-4 | object backup and restore |
| O-5 | retention periods |
| O-6 | enabling the flag outside development |

## Threat model additions

| Threat | Control |
|---|---|
| Hostile CSV (memory, CPU, encoding, shape) | streaming bounded profiler in an isolated, capped, killable child process; stable reject codes |
| Path traversal, key forgery, cross-tenant object access | server-derived keys; segment regex; root containment; tenant-scoped store; database CHECK on key shape and tenant |
| Overwrite of a stored version | link(2) write-once objects; set-once digest and key (trigger) |
| Tampered or missing bytes before publication | stored digest re-checked; verified copy; `CONTENT_MISMATCH` rejection |
| Retries and duplicate uploads | idempotency key (unique per dataset, row lock); idempotent content PUT |
| Data in logs, events or responses | codes, ids and counts only (canary tests); no key, path or filename in logs; no sample values |
| Forged confirmation or purge evidence | RLS binds `confirmed_by` to the signed user; the runtime cannot insert `VERSION_OBJECT_PURGED` |
| Tombstone while bytes remain | purge evidence plus a live store check |
| Premature exposure | flag and local store refused in staging/production; no planner path; UI states the pilot status |
