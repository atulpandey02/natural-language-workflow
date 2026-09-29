# Offboarding and deletion contract (Phase 2 plan §0.6)

Status: **contract and read-only inventory implemented; no purge exists.**
Today the platform deletes only memberships (removal) and disables schedules.
Customer data must not be accepted until the purge below exists and is
verified (plan §1, condition 2).

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
| Derived artefacts (Parquet, profile samples, temp files) | Object store / ingest temp dir | Deleted with the version | Same | Same |
| Semantic definitions (Phase 2A) | PostgreSQL | Removed with the version; dependent saved workflows fail closed (`STALE_PLAN`) | Purged | Dump retention |
| Workflow definitions (workflows, versions, schedules) | PostgreSQL | n/a | Purged | Dump retention |
| Reports and results (runs, step outputs, approvals) | PostgreSQL | Retained as evidence by default (bounded aggregates, not rows); "full purge" on request | Full purge | Dump retention |
| Planning evidence (`plan_proposals`, incl. `request_text`) | PostgreSQL | n/a | Purged | Dump retention |
| Messages already delivered to Slack | Slack workspace | **Cannot be recalled by NLW**; `external_actions` rows kept as the delivery record | Same | n/a |
| Audit (`authz_audit_events`, `plan_outcome_events`) | PostgreSQL | Retained (ids, codes, counts; never values) | Retained; tenant marker after the tombstone period | Dump retention |
| Connector secrets | Secret store | n/a | Secret versions scheduled for deletion | Provider retention window |
| PostgreSQL backups | restic (client-side encrypted, immutable mode) | **Not edited** | **Not edited**; expire on 14 daily / 8 weekly / 6 monthly retention | — |

Physical erasure from immutable backups inside their retention window is not
promised. "Beyond use" is achieved by encryption, access control, expiry and
restore-time controls.

## Restore-time control (design constraint, not yet implemented)

A restore must re-apply deletions for offboarded workspaces before any runtime
starts. The deletion log therefore **cannot live only inside PostgreSQL**:
restoring a snapshot taken before the deletion would restore the log to a
state that does not know about it. The log must be kept where a restore does
not roll it back (for example an append-only operator file stored with the
escrow material, or the object store), and the restore runbook must check it.
Where it lives is an open design decision; recorded here so the purge PR does
not put it in the database alone.

## Customer-facing statement — AWAITING OWNER APPROVAL (plan §22)

> Deleting a dataset removes its files and processed data from live storage
> within 24 hours and is verified before we report it as deleted. Metadata
> copies inside our encrypted database backups expire on a fixed schedule of up
> to six months and are never restored for a deleted workspace. Messages you
> approved for delivery to Slack remain in Slack.

Not to be published or implemented as UI copy until approved. The 24-hour
figure, the six-month backup horizon, the 90-day `request_text` retention and
the 13-month outcome-event retention are all part of that approval.
