# ADR-029: Dataset lifecycle foundation (metadata only)

Status: accepted for implementation (Phase 2A, first customer-data PR).
Date: 2026-10-03.

## Context

Phase 2 will let a workspace bring its own CSV data. Before any byte of
customer data is accepted, the platform needs a tenant-isolated, auditable
record of *what* a workspace has, *which* version of it may be used, and *how*
it is deleted. The library layer already exists (`nlw.ingest` validation and
profiling, `nlw.storage.blob` tenant-scoped keys; see
[datasets.md](../development/datasets.md)). This ADR fixes the database
contract the later upload, profiling and semantic-model work builds on.

Repository inputs reconciled here:

- `docs/development/datasets.md` sketched `datasets`, `dataset_uploads`,
  `dataset_profiles` and "a tombstone table". This ADR keeps the intent with a
  smaller, stricter grain: an *upload* is a **dataset version**; the profile is a
  future table keyed by version; the tombstone is the scrubbed `DELETED` row plus
  the append-only event trail (no separate tombstone table is needed).
- [offboarding-and-deletion.md](../security/offboarding-and-deletion.md) (reviewed)
  requires that a dataset stays `DELETING` until object deletion is verified and
  that the kept tombstone holds ids, actors, timestamps, counts and digests but
  no names or values. The `DELETED` row below is exactly that.

## Decision

### Scope

In: tables `datasets`, `dataset_versions`, `dataset_events` (migration
`0024_dataset_lifecycle`), database-enforced lifecycle and immutability, RLS on
the signed context, a deterministic domain service (`nlw.datasets`), metadata-only
API routes behind a disabled-by-default flag, an operator tombstone command, and
tests.

Explicit non-goals: file upload, multipart or pre-signed URLs, object-store
writes or reads, file download, CSV parsing in the request path, profiling
execution, semantic models, planner tools or planner visibility, query
execution (SQL, DuckDB or otherwise), UI, physical object deletion, an external
deletion log. **No customer data is accepted by this change.**

### Grain

- **Dataset** (`datasets`): a stable logical container owned by one workspace
  (`tenant_id`). A name unique within the workspace among non-tombstoned
  datasets. An active dataset is *not* analytically usable by itself; only its
  active version could be, in a later milestone.
- **Dataset version** (`dataset_versions`): one immutable record per future
  ingested object: monotonically numbered per dataset (`1, 2, …`, never reused),
  declared file metadata (sanitized original filename, media type, declared
  size), a content digest and a storage-object key placeholder (set once, later,
  by ingestion; never a credential, URL or host path), and its lifecycle state.
- **Dataset event** (`dataset_events`): append-only lifecycle evidence.

### Lifecycle

Dataset states: `ACTIVE → DELETING → DELETED`.

Version states and the only permitted transitions (enforced by a database
trigger for every role, and by the service with compare-and-set updates):

| From | To |
|---|---|
| (insert) | `QUARANTINED` |
| `QUARANTINED` | `PROFILING`, `REJECTED`, `DELETING` |
| `PROFILING` | `PROFILED`, `REJECTED`, `DELETING` |
| `PROFILED` | `ACTIVE`, `REJECTED`, `DELETING` |
| `ACTIVE` | `SUPERSEDED`, `DELETING` |
| `SUPERSEDED` | `DELETING` |
| `REJECTED` | `DELETING` |
| `DELETING` | `DELETED` |
| `DELETED` | nothing (terminal) |

`SUPERSEDED` extends the suggested state list: activating a new version keeps
the previous one immutable and historically addressable instead of mutating it
back into a pre-activation state. `QUARANTINED → REJECTED` covers a file refused
by validation before profiling (the `nlw.ingest` reject codes).

Activation is one transaction: lock the dataset row, move the current `ACTIVE`
version (if any) to `SUPERSEDED`, move the chosen `PROFILED` version to
`ACTIVE`, point `datasets.active_version_id` at it, and append the events. A
partial unique index allows at most one `ACTIVE` version per dataset, and a
deferred constraint trigger requires at commit that `active_version_id` is set
exactly when the dataset has an `ACTIVE` version and points at that version.

### Immutability (database-enforced)

- `datasets`: `id`, `tenant_id`, `created_by`, `created_at` never change; `name`,
  `normalized_name` and `description` change only to `NULL` when the row becomes
  `DELETED`; `last_version_number` only increases, by one, while `ACTIVE`;
  `active_version_id` is `NULL` unless the dataset is `ACTIVE`.
- `dataset_versions`: `id`, `tenant_id`, `dataset_id`, `version_number`,
  `media_type`, `declared_size_bytes`, `created_by`, `created_at` never change;
  `content_sha256` and `storage_object_key` may be set once (from `NULL`) while
  `QUARANTINED`; `original_filename` and `storage_object_key` change only to
  `NULL` when the row becomes `DELETED` (the digest is kept, as the offboarding
  contract requires); `rejection_code` is set exactly when the state is
  `REJECTED`.
- A new version can only be inserted, as `QUARANTINED`, into an `ACTIVE` dataset.
- Nothing leaves `DELETED`, for any role, including the table owner.

### Deletion and tombstones

| Step | Who | Effect |
|---|---|---|
| Deletion request | workspace admin/owner (API) or service | dataset `ACTIVE → DELETING`; every non-deleted version `→ DELETING`; `active_version_id` cleared; the dataset can no longer receive versions or be activated. Repeating the request is a no-op (idempotent). A single version can also be put into `DELETING`; if it was active, the dataset is left without an active version. |
| Logical disablement | automatic | a `DELETING` dataset or version is unusable for any analytical purpose. |
| Physical object deletion | **future** (with ingestion) | must delete and verify absence of every stored object before tombstoning. No objects exist yet, so the tombstone command refuses any version that has a `storage_object_key`. |
| Tombstone | operator only (`python -m nlw.ops.datasets tombstone`, owner credential) | versions `DELETING → DELETED` and dataset `DELETING → DELETED`; names, description, original filename and storage key are scrubbed to `NULL`; ids, version numbers, digests, actors, sizes and timestamps stay. The runtime role cannot write `DELETED` (RLS `WITH CHECK`). |
| Audit | automatic | every transition appends one `dataset_events` row; events are never updated or deleted by runtime roles and survive the tombstone. |

Retention periods (how long after a request the tombstone is applied, how long
tombstones and events are kept) are **not set**: they are pilot proposals
awaiting owner approval (owner decision 14). The external, restore-proof
deletion log (owner decision 13) remains a **launch gate** before any upload is
enabled; this change records evidence only inside PostgreSQL.

### Authorization matrix

| Operation | member | admin / owner | internal service | operator |
|---|---|---|---|---|
| List / read datasets and versions (metadata) | yes | yes | — | — |
| Create a dataset container | no | yes (API, flagged) | — | — |
| Request dataset or version deletion | no | yes (API, flagged) | yes | — |
| Create a version (future upload) | no | — | yes (admin authority; no route) | — |
| `QUARANTINED → PROFILING → PROFILED / REJECTED` | no | — | yes (no route; future ingest role) | — |
| Activate / reject a `PROFILED` version | no | — | yes (admin authority; no route; future review UI) | — |
| Tombstone (`→ DELETED`) | no | no | no | yes (owner credential) |
| Read lifecycle events | no | yes (database) | — | — |

There is no generic "set status" endpoint, and no client-supplied tenant,
actor, version number, status or active-version pointer is accepted anywhere.

### Tenant isolation and roles

RLS is enabled and forced on all three tables with the signed-context
predicates of migration 0016 (`ctx_tenant_id()`, `is_current_user_member`,
`is_current_user_admin_or_owner`). `nlw_app` may read as a member, insert and
update as an admin/owner, never write `DELETED`, never update a `DELETED` row,
and never delete. `nlw_worker`, `nlw_scheduler` and `PUBLIC` have no privileges.
No `SECURITY DEFINER` function is added. Composite foreign keys tie every
version and event to a dataset **of the same tenant**.

### Metadata bounds

Names: NFKC-normalized, trimmed, internal whitespace collapsed, 1–100
characters, no control characters; uniqueness is case-insensitive per workspace.
Descriptions: optional, ≤ 500 characters. Original filenames: base name only,
≤ 255 characters, no path separators, control characters, or `.`/`..`. Media
type: `text/csv` only. Declared size: 1 byte to 25,000,000 bytes (the profiler's
cap). Digest: 64 lowercase hex. Storage key: the `nlw.storage.blob` key format
for **this** tenant and dataset. Reason codes: closed vocabularies. No free-form
JSON column exists.

### API surface (product-honest)

Metadata routes (`/datasets…`) exist only when `DATASETS_API_ENABLED=true`, and
the configuration **refuses** that value in staging and production until upload
and end-to-end deletion exist (owner decision 12). With the flag off the routes
are not mounted. Version creation, ingestion transitions and activation have no
route in this change.

### Planner isolation

`nlw.datasets` is not imported by the planner, feasibility, registry, tools,
capability view or evaluation code, and no dataset tool exists (enforced by the
existing boundary test, extended to the new package). `/analytics/datasets` (the
synthetic M12C catalogue) is unchanged and unrelated.

### Migration, rollback and forward fixes

`0024` only adds objects. Its downgrade drops them and exists for disposable
environments and tests; **never downgrade a live environment that holds dataset
metadata** (the evidence trail would be destroyed). Fix forward. The release
that carries `0024` is a migration release (`0023 → 0024`); the signed-policy
inventory grows from 53 to 61.

### Threat model (summary)

| Threat | Control |
|---|---|
| Cross-tenant read or write by id guessing | RLS on signed context; composite tenant FKs; 404 for invisible rows |
| Client forges tenant, actor, status or pointer | not accepted by any contract; derived server-side |
| Resurrection after deletion | trigger forbids leaving `DELETED`; runtime role cannot touch `DELETED` rows |
| Concurrent activation / numbering | dataset row lock; partial unique index; deferred consistency trigger; atomic counter |
| Tampering with history | events append-only for runtime roles; versions immutable by trigger |
| Sensitive data in metadata or events | bounded, sanitized fields; closed vocabularies; no free-form text |
| Premature exposure | flag refused in staging/production; no planner path; no upload path |

## Consequences

The upload, profiling, review and deletion features can be added without schema
redesign: an upload creates a `QUARANTINED` version and sets its digest and key;
profiling moves it through `PROFILING`; review activates or rejects it; physical
deletion runs between `DELETING` and the tombstone. Open owner decisions:
retention periods, the external deletion log, the future ingest role, and when
the flag may be enabled outside development.
