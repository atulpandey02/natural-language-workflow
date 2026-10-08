# ADR-031: Dataset ingest runtime boundary (owner decision O-1)

Status: accepted for implementation; **not deployed, dormant in staging and
production**. Branch `feat/dataset-ingest-runtime-role`.
Date: 2026-10-07.
Builds on [ADR-024](ADR-024-signed-database-context.md) (signed context),
[ADR-029](ADR-029-dataset-lifecycle-foundation.md) and
[ADR-030](ADR-030-csv-ingestion-and-profiling.md). Design note:
[csv-ingestion-design](../development/csv-ingestion-design.md) §2.3.

## Context

ADR-030 ran every profiling step as `nlw_app` under the uploading admin's
`api_request` context, and named a dedicated ingest role as owner decision O-1.
The owner has now decided O-1: background CSV processing gets its own runtime,
database role, signed purpose and key, so the API never profiles with
privileges it does not otherwise need, and the processor never holds anything
it does not need.

This ADR establishes that boundary only. **Uploads stay disabled.** There is no
upload, processing, profile, activation or deletion route; no S3 (O-2); no
deletion-log provider (O-3); and `DATASETS_API_ENABLED` and local dataset storage
stay refused in staging and production (O-6). This change alone is not
deployable customer-upload functionality.

## Decision

### Responsibilities

| Actor | May | May not |
|---|---|---|
| API (`nlw_app`, `api_request`) | authenticate; check admin/owner; create datasets, versions and an immutable **processing request**; confirm semantics; activate; request deletion | profile; claim, renew or settle a processing lease; insert a profile; move a version to `PROFILING` or `PROFILED`; reject a version that is being processed (review rejection of a `QUARANTINED` version and deletion requests stay the admin's) |
| Ingest (`nlw_ingest`, `dataset_ingest`) | read ONE version (from its signed context) and its dataset, request and events; take/renew the database-time lease; insert that version's profile; publish (`PROFILED`, key moved `quarantine/ → datasets/`) or reject with a closed code; write the matching lifecycle event | create datasets/versions/requests; confirm semantics; activate or supersede; request deletion; purge, tombstone or resurrect; write receipts or operator events; read another version or workspace; choose a storage key; DELETE anything |
| Operator (owner credential) | purge with receipts; tombstone | — (unchanged, ADR-030) |
| Admin user | semantic confirmation; activation | — (unchanged) |
| Worker, scheduler, PUBLIC | nothing on any dataset table | — (unchanged) |

### Database role `nlw_ingest`

`LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT`, member of
nothing, owner of nothing. Provisioning follows the existing split:

- fresh volumes: `docker/postgres/initdb/00-roles.sh` creates it as a LOGIN
  role **only when `NLW_INGEST_DB_PASSWORD` is supplied** (development, CI, E2E);
  otherwise it is created `NOLOGIN` (dormant);
- existing databases: `python -m nlw.ops.roles ensure` (the rollout's
  `prepare-roles`) creates it **`NOLOGIN`**, idempotently, and never alters an
  existing role.

Staging and production keep it dormant (`NOLOGIN`, no password, no key, no
running container) until O-6. The rollout role gate requires exactly that.
Enabling it later is an explicit, reviewed operation (set a password with the
existing rotation runbook, change the gate, install the key, start the service).

### Signed purpose `dataset_ingest` and key class `ingest`

- Purpose `dataset_ingest` is bound to `nlw_ingest` only (in Python and in the
  verifier). Claim shape: **tenant + run, no user**, where the run slot carries
  the **version id**. A context therefore authorizes one version in one
  workspace, nothing else.
- Key class `ingest`, its own key id and its own key file. The verifier requires
  key class `ingest` for this purpose, so an api, worker or scheduler key can
  never mint an ingest context, and the ingest key can never mint theirs.
- `app_ctx_claims()` is **replaced in place** (`CREATE OR REPLACE`, same owner
  `nlw_ctx_verifier`, same `SECURITY DEFINER`, same checks). The change only
  adds the new purpose to the allowed list, its role binding, its claim shape and
  its key class. **No new SECURITY DEFINER function** is added. The existing
  accessors (`ctx_user_id/tenant_id/run_id/purpose`) are untouched, so no
  existing policy changes meaning. Two new SECURITY INVOKER accessors,
  `ctx_ingest_tenant_id()` and `ctx_ingest_version_id()`, return values only
  for a verified `dataset_ingest` context.
- `ctx_keys.key_class` accepts `ingest`.

### Exact privileges (migration `0026_dataset_ingest_role`)

| Object | `nlw_ingest` | RLS predicate (all FORCE RLS) |
|---|---|---|
| `datasets` | SELECT | own tenant, and the dataset of the context's version |
| `dataset_versions` | SELECT; UPDATE (`status`, `processing_lease_token`, `processing_lease_expires_at`, `storage_object_key`, `rejection_code`) only | USING: own tenant, `id` = context version, status `QUARANTINED` or `PROFILING`; WITH CHECK: same row, status `PROFILING`, `PROFILED` or `REJECTED` |
| `dataset_profiles` | SELECT, INSERT | own tenant, context version |
| `dataset_events` | SELECT, INSERT | own tenant, context version; INSERT also `actor_kind = 'service'`, `actor_user_id IS NULL`, event type `VERSION_PROFILING_STARTED`, `VERSION_PROFILED` or `VERSION_REJECTED` |
| `dataset_processing_requests` | SELECT | own tenant, context version |
| `dr_restore_events` | SELECT (4 lock columns, like every runtime) | — (no tenant data) |
| `dataset_semantic_revisions`, every other table | nothing | — |
| `app_ctx_claims()`, `ctx_ingest_*()` | EXECUTE | — |

No DELETE, TRUNCATE, REFERENCES or TRIGGER anywhere; no sequence privileges (all
ids are UUIDs); no schema-wide grant; `CONNECT` and `USAGE ON SCHEMA public`
only. The existing triggers do the rest: the version guard only allows the
processing transitions with a live lease, the profile guard only a `PROFILING`
version with the matching digest, and the event guard only the event of the
transition made in the same transaction. `dataset_event_required()` is replaced
to include `nlw_ingest`, so an ingest transition cannot commit without its
event.

Two invoker triggers are adapted, both stated here because they are the only
role-aware logic added:

- `dataset_version_guard()` gains a role rule: `nlw_app` may not enter
  `PROFILING`/`PROFILED`, change the lease, or move `PROFILING → REJECTED`
  (SQLSTATE 42501); `nlw_ingest` may only move `QUARANTINED → PROFILING` and
  `PROFILING → PROFILED|REJECTED`. The rule is checked before the guard clears
  lease columns, so an admin's deletion of a version being processed
  (`PROFILING → DELETING`) still wins.
- `dataset_consistency_check()` (deferred) counts a dataset's versions to check
  "one ACTIVE version" and "a deleting dataset has only deleting versions". The
  ingest role sees ONE version, so those counts would be partial for it, and the
  check would wrongly fail when the dataset already has an ACTIVE version. Its
  transitions never involve `ACTIVE`, `DELETING` or `DELETED` (policy + guard),
  so those invariants cannot change; for `nlw_ingest` the trigger instead checks
  the one invariant it can affect (its dataset is `ACTIVE`) and refuses anything
  else. Every other role keeps the full check. This replaces what would
  otherwise need a SECURITY DEFINER function or wider visibility, both refused.

API changes in the same migration:

- `nlw_app` loses `INSERT` on `dataset_profiles` (its insert policy is dropped);
- its `dataset_versions` UPDATE policy now refuses a new status of
  `PROFILING`, `PROFILED` or `REJECTED`, so the API cannot take a lease, publish
  or reject even as an admin;
- it gains `dataset_processing_requests` SELECT and INSERT (admin, signed actor).

Signed policies go from 65 to 74 (−1 app profile insert; +3 request policies;
+7 ingest policies).

### Processing request and work envelope

The API records an **immutable `dataset_processing_requests` row** under the
admin's signed context: workspace, dataset, version, the content digest,
`requested_by = ctx_user_id()`. A trigger forces `requested_at = now()`,
requires the version to be `QUARANTINED` (or `PROFILING`, to re-request a crashed
run) with stored content whose digest matches, and computes
`envelope_sha256` itself over a canonical, versioned encoding. UPDATE and DELETE
are refused for every role, the owner included.

The queue message (the **work envelope**) carries exactly those fields. The
ingest service:

1. parses it strictly and recomputes the digest (tamper → reject, no DB access);
2. refuses it when older than the maximum age (stale → reject);
3. signs a `dataset_ingest` context for exactly that workspace and version, and
   reads the request row through RLS: it must exist and match every field and
   the stored digest (forged/replayed-with-changes → reject).

**Integrity anchor, stated precisely:** the envelope is integrity-protected by
its binding to an immutable request row that only an admin's signed API
context can create. It is **not** a MAC by a key shared between the API and the
ingest service. A shared envelope key would break per-service key isolation,
and an asymmetric signature would need a new key type with its own escrow and
rotation. A party able to inject queue messages can only point the service at a
request an admin really made (which is idempotent), never at anything else.

### Queue and runtime

- Redis/Dramatiq (transport only, ADR-002), queue `dataset_ingest`. The ingest
  process loads only `nlw.ingest_service.actors`, which imports no worker, connector,
  planner or model module (tested). Its own broker middleware refuses to boot
  while the DR recovery lock is held or when its key does not verify.
- Duplicate delivery is idempotent: the lease compare-and-set lets one
  delivery win; every other one returns `skipped`.
- Shutdown: on SIGTERM Dramatiq stops consuming; a message that arrives after
  the stop flag is set is re-queued without claiming a lease; in-flight work
  finishes (the grace period exceeds the profile timeout) or, if killed, its
  database-time lease expires and a redelivery reclaims it. Lease loss
  abandons the work and publishes nothing (the profile insert rolls back).
- Compose service `ingest` (development `docker-compose.yml`, opt-in profile
  `ingest`): exec-form command, `init: true`, the image's non-root user (uid
  10001), read-only root, `cap_drop: ALL`, `no-new-privileges`, no published
  port. Environment: its own database URL, Redis URL, its own key id and file,
  and dataset storage settings. **Nothing else**: it is not built from the shared
  app environment, so it gets no owner/migration credential, no LLM provider or
  key, no `DEMO_TOOLS_ENABLED`, no worker secrets file, no Supabase, backup,
  Alertmanager or operator credentials.
- **No ingest service in the staging/production Compose files** until O-6: the
  deployment model does not need a dormant container, and the rollout's
  container inventory, mounts and drain stay unchanged.
- In staging/production the service could not process anything even if
  started: there is no upload route, and local storage is refused there with no
  other backend (O-2).

### Failure, retry, lease loss and shutdown

| Situation | Behaviour |
|---|---|
| Malformed, tampered, forged or stale envelope | refused before any change (`refused`, content-free code logged); not retried |
| Version not claimable (already processed, deleted, another live lease) | `skipped`; a settled version's leftover bytes are cleaned idempotently |
| Duplicate or concurrent delivery | one delivery wins the compare-and-set lease; the rest are `skipped`; exactly one event per transition |
| Transient database/Redis failure | the message is retried (at most 5 times, Dramatiq backoff); nothing was committed |
| Profiler rejects, times out or crashes | `REJECTED` with a closed code; bytes deleted; the child is always reaped |
| Lease lost (expired and reclaimed) | the work is cancelled; publication is refused (`LEASE_LOST`) and its profile insert rolls back |
| Deletion requested during processing | deletion wins; the remaining steps are refused; the purge removes the bytes |
| SIGTERM | consumption stops; a message started after the stop flag is re-queued without a lease; in-flight work finishes within the grace period (180 s > profile timeout) |
| Killed mid-profile | the database-time lease expires (≤ 120 s) and a redelivery reclaims it |
| Restore under recovery lock, key not verifiable, no dataset store | boot refused (framework-fatal); no consumer starts |
| A restore lands while the runtime is up | every ingest transaction (claim, renew, publish, reject) consults the recovery lock first: nothing changes, the message is re-queued (60 s) until the operator enables runtimes; in-flight work cannot settle and its lease expires |

### Secret and key isolation

| Service | Database role | Signing key | Other secrets |
|---|---|---|---|
| api | `nlw_app` | `api.key` | LLM key, Supabase, workspace cookie |
| worker | `nlw_worker` | `worker.key` | connector secrets (`worker.secrets.env`) |
| scheduler | `nlw_scheduler` | `scheduler.key` | none |
| **ingest** | **`nlw_ingest`** | **`ingest.key`** | **none** (dataset storage path only) |
| migrate (one-shot) | owner | none | owner credential |

No service mounts another service's key (tested on every Compose file), and
the ingest service receives no owner, LLM, Supabase, demo-tools, worker-secret,
backup or alerting values.

### Key protocol and rollout (backward-safe)

- `ingest` is an **optional** fourth key class. Release manifests, escrow
  attestations, `ctxkeys fingerprint/verify-files` and the fingerprint gate
  accept exactly the three required classes, or the three plus `ingest`. With
  `ingest` present it must be complete, unique and attested like the others.
- `deploy/staging/target.env` is unchanged, so staging manifests stay at three
  keys and the current escrow attestation stays valid.
- `ctxkeys prepare/install/check/revoke` support `--class ingest`. Existing keys
  are never regenerated or replaced.
- The rollout **refuses a release that declares an ingest key** before any phase
  can run (the `Rollout` cannot even be constructed for it; preflight and
  verify-release re-check) until O-6 makes enablement part of the protocol. No
  phase, `prepare-keys` included, can generate, stage or install an ingest key.
- `prepare-roles` creates dormant `nlw_ingest`; the role gate requires it
  `NOLOGIN`. The policy-count gate expects 74. Restore validation and the
  offboarding inventory include the new table and role.

## Alternatives considered

- **Keep processing in the API** (ADR-030): rejected by the owner (O-1).
- **Reuse the worker**: the worker holds connector secrets and runs
  workflow/LLM-adjacent code; a dataset role there widens both.
- **Cross-tenant ingest scans** (database as the queue): would let the ingest
  role read every workspace's pending versions. Binding each context to one
  version is narrower.
- **Shared-key or asymmetric envelope signatures**: see "Integrity anchor".
- **SECURITY DEFINER processing functions**: unnecessary. Grants, RLS and the
  existing invoker triggers express the boundary.

## Consequences

- PR 2 (upload API) must enqueue processing requests instead of profiling
  in-process. Its processing half now lives here (`nlw.ingest_service.processing`).
- Migration `0026` is additive; it rewrites no data. Downgrade is for
  disposable databases only: never downgrade a live environment; fix forward.
- Staging gains a dormant role and three more privileges-free objects to
  verify, but its runtime set, keys and manifests are unchanged.

### Review notes (pre-existing, not introduced here)

- Every runtime role, `nlw_ingest` included, can execute the pure pgcrypto
  functions installed in `public` (for the verifier) and holds `CONNECT`/`TEMP`
  on the database through PUBLIC. None of these reads or writes data.
- PostgreSQL lets a role change its own session defaults (`ALTER ROLE ... SET`).
  For `nlw_ingest` this can only fail closed (`row_security = off` turns a
  filtered query into an error; superuser-only settings are refused), and the
  rollout/restore checks do not depend on it. Tested.

### Remaining owner decisions and blockers

| | Topic | Status |
|---|---|---|
| O-2 | S3 client, per-environment bucket | open: production processing has no storage backend |
| O-3 | external deletion-log provider | open |
| O-4 | object backup/restore | open |
| O-5 | retention periods | open |
| O-6 | enabling uploads and the ingest runtime outside development | open: role dormant, rollout refuses an ingest key |
