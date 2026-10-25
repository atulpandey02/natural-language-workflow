# Offboarding and deletion contract (Phase 2 plan §0.6)

Status: **contract and read-only inventory implemented; dataset purge and
tombstone implemented locally (ADR-030, development only); workspace
offboarding implemented locally ([ADR-037](../adr/ADR-037-workspace-offboarding.md):
`python -m nlw.ops.offboarding request|complete`, with a workspace receipt in
the external log); NOT RUN in staging or against AWS.**
Customer data must not be accepted until the purge below exists and is
verified (plan §1, condition 2). Owner decision (2026-09-29): customer uploads
stay disabled until dataset and workspace deletion work end to end, including
object bytes and the external deletion log.

Retention periods in this document (backup horizon, `request_text`, outcome
events, tombstones, the customer-facing deletion figures) are **pilot policy proposals**,
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
| Workspace-creation grant (platform ledger) | PostgreSQL `workspace_creation_grants` | n/a | The founding grant is scrubbed (ADR-037 amendment, 0032): email, founder id and note set to NULL; grant id, tombstone id, operator labels and timestamps kept; no email-derived value | Dumps keep the email until they expire; `reapply-receipts` re-scrubs a restored grant before any runtime starts |
| Dataset metadata (`datasets`, `dataset_versions`, migrations `0024`/`0025`; [ADR-029](../adr/ADR-029-dataset-lifecycle-foundation.md), [ADR-030](../adr/ADR-030-csv-ingestion-and-profiling.md)) | PostgreSQL | Request → `DELETING` (unusable at once); operator `purge` deletes and verifies the objects (receipt + `VERSION_OBJECT_PURGED`); operator tombstone → `DELETED`: names, description, filename and storage key scrubbed to `NULL`, ids/sizes/digests/actors/timestamps kept ([runbook](../runbooks/dataset-metadata-deletion.md)). The tombstone refuses any version with a storage key or an earlier purge event unless an operator purge event was recorded after the request AND the configured deletion log verifies its receipt AND a live store check finds nothing; a version with neither needs only the live check (none when no store is configured), exactly as in [ADR-033](../adr/ADR-033-s3-dataset-object-storage.md) note 3 | All datasets deleted first | As above |
| Dataset lifecycle events (`dataset_events`) | PostgreSQL | Retained (ids, states, closed reason codes; never names or values); append-only for runtime roles | Retained like audit evidence (period proposed, not approved) | Dump retention |
| Object bytes (quarantine, published raw file) | Dataset object store (local in development; S3 `versions/` per ADR-033, NOT RUN) | `purge`: every version, delete marker and upload deleted and verified absent, with a receipt; a rejected file's bytes are kept immutable until the operator's retention sweep purges them (7 days, ADR-035); the dataset stays `DELETING` until verification holds | Prefix deleted, verified empty | Not in the PostgreSQL backup. AWS Backup recovery points keep them exactly 30 days (O-4, [ADR-036](../adr/ADR-036-dataset-object-backup.md)); a restore never brings back a version a receipt proves deleted |
| Derived artefacts (Parquet, temp files, partial uploads) | Object store / ingest temp dir | Deleted with the version; partial `.upload-*` files are listed and deleted with the dataset | Same | Same |
| Derived profiles (`profile-2`: counts, types, bounded statistics, indicators; **no sample values**) | PostgreSQL `dataset_profiles` (0025) | Tombstone scrubs `profile` to `NULL` (row counts and digest kept) | Purged | Dump retention |
| Semantic confirmations (`semantics-1` labels and choices) | PostgreSQL `dataset_semantic_revisions` (0025) | Tombstone scrubs `mapping` to `NULL` (revision numbers, confirming user and time kept) | Purged | Dump retention |
| Workflow definitions (workflows, versions, schedules) | PostgreSQL | n/a | Purged | Dump retention |
| Reports and results (runs, step outputs, approvals) | PostgreSQL | Retained as evidence by default (bounded aggregates, not rows); "full purge" on request | Full purge | Dump retention |
| Planning evidence (`plan_proposals`, incl. `request_text`) | PostgreSQL | n/a | Purged | Dump retention |
| Messages already delivered to Slack | Slack workspace | **Cannot be recalled by NLW**; `external_actions` rows kept as the delivery record | Same | n/a |
| Audit evidence (`authz_audit_events`) | PostgreSQL | Retained (ids, event types; never values) | Retained; tenant marker after the tombstone period (period proposed, not approved) | Dump retention |
| Planner-outcome events (`plan_outcome_events`) | PostgreSQL | n/a | Retained (codes, buckets, counts; no text); proposed 13 months, **no retention job exists yet** | Dump retention |
| Connector credentials | Secret store (the `connectors` row holds only a reference) | n/a | `connectors` row purged; the operator removes the workspace's entries from the store and `complete --secrets-file` refuses until none remain (recorded in the workspace receipt, ADR-037) | Provider retention window |
| PostgreSQL backups | restic (client-side encrypted, immutable mode) | **Not edited** | **Not edited**; expire on the O-5 retention of 30 daily and 12 monthly recovery points ([ADR-035](../adr/ADR-035-phase2-retention-policy.md)) | — |
| External deletion log (`deletion-receipt-2`, ADR-030; provider: S3 Object Lock, ADR-034, NOT RUN on AWS; local FAKE for development) | Outside PostgreSQL and its backups (see below) | One receipt per purged version (ids, digest, object count, hashed object refs, operator, time; no names or values) | One entry per offboarded workspace | Never rolled back by a restore |
| Legal or operational retention exceptions | Recorded per case with the owner's approval | Deletion paused only for a recorded hold (legal request, active incident); never silently | Same | A hold never extends backup expiry beyond the configured schedule |

Physical erasure from immutable backups inside their retention window is not
promised. "Beyond use" is achieved by encryption, access control, expiry and
restore-time controls.

## Restore-time control

A restore must re-apply deletions before any runtime starts. The deletion log
therefore **cannot live only inside PostgreSQL**: restoring a snapshot taken
before the deletion would restore the log to a state that does not know about
it. Owner decisions (2026-09-29, 2026-10-14): the log lives outside PostgreSQL
backups, in a dedicated S3 Object Lock bucket per environment
([ADR-034](../adr/ADR-034-external-deletion-receipt-log.md)).

- **Dataset version purges: implemented, NOT RUN on AWS.** While the recovery
  lock holds the restored database, `python -m nlw.ops.datasets
  reapply-receipts` moves every version a receipt proves deleted to `DELETING`
  with its purge evidence ([dr-fresh-host-restore](../runbooks/dr-fresh-host-restore.md)).
- **Workspace offboarding: implemented, NOT RUN on AWS** (ADR-037). One
  `workspace-offboarding-receipt-1` per offboarded workspace; `reapply-receipts`
  moves a restored ACTIVE workspace back to OFFBOARDING (no runtime can reach
  it) before any runtime starts, and the operator re-runs `complete` after
  enabling. Connector secrets: `complete` refuses until the secret store file
  (`--secrets-file`) holds no entry of the workspace, and records the check in
  the receipt (ADR-037; the removal itself is an operator step).

## Customer-facing statement — DRAFT FOR OWNER APPROVAL (plan §22)

Status: **draft, not published, not in effect.** It may be published only when
customer data is enabled, which still requires COMPLIANCE retention for
receipts, audit records and object backups and a separate GO decision. The
periods are the owner-approved ones (2026-10-24) and match the implemented
contract (`nlw.core.retention`, ADR-035, ADR-036, ADR-037); the twelve-month
database-backup horizon is part of that contract and is stated so the text is
complete.

<!-- customer-statement -->
> **Deleting a dataset or a workspace.** When you delete a dataset or close a
> workspace, access to it is disabled immediately. We then delete its files
> and processed data from our active storage, with a target of 7 days, and we
> verify that they are gone before we report the deletion as complete.
>
> Earlier versions of stored files and recoverable copies kept for disaster
> recovery expire within 30 days. Metadata copies inside our encrypted
> database backups expire within twelve months. If we ever restore from a
> backup, we re-apply every recorded deletion before the service runs again,
> so deleted data is never brought back into use.
>
> We keep a record that each deletion happened, with identifiers, counts and
> times but never the content, for 365 days as audit evidence. When a
> workspace is closed, the email address used to authorise its creation is
> removed from our workspace records. Your sign-in account is separate from
> the workspace and is not deleted when a workspace is closed.
>
> Messages you approved for delivery to Slack remain in Slack.
<!-- /customer-statement -->

Not to be published or used as UI copy until approved. It does not promise
immediate physical deletion: the 7-day figure is a target for active storage,
and copies in backups expire on the schedule above. The 90-day `request_text`
retention and the 13-month outcome-event retention are not part of this
statement and remain pilot proposals.
