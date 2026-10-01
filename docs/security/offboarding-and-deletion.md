# Offboarding and deletion contract (Phase 2 plan §0.6)

Status: **contract and read-only inventory implemented; no purge exists.**
Today the platform deletes only memberships (removal) and disables schedules.
Customer data must not be accepted until the purge below exists and is
verified (plan §1, condition 2). Owner decision (2026-09-29): customer uploads
stay disabled until dataset and workspace deletion work end to end, including
object bytes and the external deletion log.

Retention periods in this document (backup horizon, `request_text`, outcome
events, tombstones, the 24-hour deletion figure) are **pilot policy proposals**,
not legal or compliance commitments, until the owner approves them (owner
decision, 2026-09-29).

## Artefact classes

The table-level classification is code: `nlw.ops.offboarding.TABLES`. A test
(`tests/integration/test_offboarding_inventory.py`) fails if any table in the
`public` schema is unclassified, so new tenant data cannot escape offboarding.
`python -m nlw.ops.offboarding inventory --workspace <id>` (owner credential)
prints one workspace's row counts per table; it changes nothing.

| Class | Where | On dataset delete | On workspace offboarding | Backups |
|---|---|---|---|---|
| Workspace metadata (workspaces, memberships, invitations) | PostgreSQL | n/a | Purged after dependants; tombstone kept (ids, actor, timestamps, counts, digests; no names or values) | Remain in PostgreSQL dumps until they expire |
| Dataset metadata (Phase 2A tables) | PostgreSQL | Rows removed after object deletion is verified; tombstone kept | All datasets deleted first | As above |
| Object bytes (quarantine, raw file) | Object store, tenant prefix | Deleted and verified absent per key; the dataset stays `DELETING` until verification holds (`TenantScopedBlobStore.delete_dataset_and_verify`) | Prefix deleted, verified empty | Not in restic; any replica expires by lifecycle |
| Derived artefacts (Parquet, temp files, partial uploads) | Object store / ingest temp dir | Deleted with the version; partial `.upload-*` files are listed and deleted with the dataset | Same | Same |
| Derived profiles (`profile-1`: counts, types, flags, ≤ 10 samples of low-cardinality unflagged columns) | PostgreSQL (Phase 2A `dataset_profiles`) | Removed with the version | Purged | Dump retention |
| Semantic definitions (Phase 2A) | PostgreSQL | Removed with the version; dependent saved workflows fail closed (`STALE_PLAN`) | Purged | Dump retention |
| Workflow definitions (workflows, versions, schedules) | PostgreSQL | n/a | Purged | Dump retention |
| Reports and results (runs, step outputs, approvals) | PostgreSQL | Retained as evidence by default (bounded aggregates, not rows); "full purge" on request | Full purge | Dump retention |
| Planning evidence (`plan_proposals`, incl. `request_text`) | PostgreSQL | n/a | Purged | Dump retention |
| Messages already delivered to Slack | Slack workspace | **Cannot be recalled by NLW**; `external_actions` rows kept as the delivery record | Same | n/a |
| Audit evidence (`authz_audit_events`) | PostgreSQL | Retained (ids, event types; never values) | Retained; tenant marker after the tombstone period (period proposed, not approved) | Dump retention |
| Planner-outcome events (`plan_outcome_events`) | PostgreSQL | n/a | Retained (codes, buckets, counts; no text); proposed 13 months, **no retention job exists yet** | Dump retention |
| Connector credentials | Secret store (the `connectors` row holds only a reference) | n/a | `connectors` row purged; secret versions scheduled for deletion in the store | Provider retention window |
| PostgreSQL backups | restic (client-side encrypted, immutable mode) | **Not edited** | **Not edited**; expire on the configured 14 daily / 8 weekly / 6 monthly retention | — |
| External deletion log (not yet built) | Outside PostgreSQL and its backups (see below) | One entry per verified deletion | One entry per offboarded workspace | Never rolled back by a restore |
| Legal or operational retention exceptions | Recorded per case with the owner's approval | Deletion paused only for a recorded hold (legal request, active incident); never silently | Same | A hold never extends backup expiry beyond the configured schedule |

Physical erasure from immutable backups inside their retention window is not
promised. "Beyond use" is achieved by encryption, access control, expiry and
restore-time controls.

## Restore-time control (design constraint, not yet implemented)

A restore must re-apply deletions for offboarded workspaces before any runtime
starts. The deletion log therefore **cannot live only inside PostgreSQL**:
restoring a snapshot taken before the deletion would restore the log to a
state that does not know about it. Owner decision (2026-09-29): the deletion
log will eventually live outside PostgreSQL backups, in a separately
controlled, versioned or object-locked S3 location, and the restore runbook
must re-apply it before any runtime starts. An S3 client is a new runtime
dependency and needs its own ADR first; until the log exists, offboarding and
customer uploads stay unavailable.

## Customer-facing statement — AWAITING OWNER APPROVAL (plan §22)

> Deleting a dataset removes its files and processed data from live storage
> within 24 hours and is verified before we report it as deleted. Metadata
> copies inside our encrypted database backups expire on a fixed schedule of up
> to six months and are never restored for a deleted workspace. Messages you
> approved for delivery to Slack remain in Slack.

Not to be published or implemented as UI copy until approved. The 24-hour
figure, the six-month backup horizon, the 90-day `request_text` retention and
the 13-month outcome-event retention are all part of that approval; until then
they are pilot proposals, not legal or compliance commitments.
