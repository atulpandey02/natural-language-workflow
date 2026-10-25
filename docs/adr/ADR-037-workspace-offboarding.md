# ADR-037: Workspace offboarding and its receipts

Status: **accepted; implemented and tested locally (branch
`feat/workspace-offboarding`); NOT RUN against AWS or staging; uploads stay
refused in staging and production (O-6).** Owner decision (scope): 2026-10-15.
Builds on the offboarding contract
([offboarding-and-deletion](../security/offboarding-and-deletion.md),
`nlw.ops.offboarding.TABLES`), ADR-030 (dataset purge and tombstone) and
ADR-034 (the external deletion log and `reapply-receipts`).

> **Principle.** Offboarding cuts off every runtime at once and in the
> database, removes what the contract says to remove, proves it with a receipt
> outside the database, and a restore can never quietly undo it.

## Context

The contract classified every table, but nothing deleted a workspace: there
was no workspace state, the memberships trigger refused to leave a workspace
without an owner, and the receipt log had only per-version receipts.

## Decision

1. **State** (`workspaces.status`, migration `0031`): `ACTIVE -> OFFBOARDING ->
   OFFBOARDED` only, guarded by a trigger. Only the operator (owner connection)
   changes it. Created workspaces are ACTIVE. An OFFBOARDED row is the
   tombstone: name and slug scrubbed (`offboarded`, `offboarded-<id>`), the id,
   timestamps, operator label, receipt id and row counts kept; it never changes
   and is never deleted (dataset tombstones reference it).
2. **Blocking, in the database.** `workspace_is_active(uuid)` (SECURITY
   DEFINER, `nlw_rls_bypass`) is the one check. `ctx_tenant_id()` and
   `ctx_ingest_tenant_id()` return NULL for a workspace that is not ACTIVE, so
   every tenant RLS policy of the API, the worker and the ingest runtime denies
   it, whatever signed context a caller holds; no policy is added (74).
   `schedule_creator_block_reason` returns `WORKSPACE_NOT_ACTIVE`. The API
   answers 403 "the workspace is unavailable" and hides it from discovery.
3. **`request`** (`python -m nlw.ops.offboarding request`): ACTIVE ->
   OFFBOARDING, and every live dataset -> DELETING (reason
   `WORKSPACE_OFFBOARDING`), in one transaction. Idempotent.
4. **`complete`**: for an OFFBOARDING workspace, while the recovery lock is
   clear: every dataset is purged (verified absent, one receipt per version)
   and tombstoned; then, in ONE transaction, every `purge` table of the
   contract is emptied for the workspace (`PURGE_ORDER`, pinned to the
   contract by a test) and verified empty, one **workspace receipt** is
   appended to the external log, and the tombstone is written.
   `enforce_workspace_owner_present` no longer requires an owner once the
   workspace is not ACTIVE.
5. **Receipt** `workspace-offboarding-receipt-1`, at
   `receipts/<workspace>/workspace/<receipt_id>.json` (inside the reviewed
   `receipts/` prefix, so the bucket policy, lifecycle and grants are
   unchanged): sink, environment, workspace id, number of datasets, a digest of
   their ids (not the ids), rows removed per table, a binding digest, operator,
   time. Never a name or value.
6. **Restore**: `reapply-receipts` also lists workspace receipts and moves a
   restored ACTIVE workspace back to OFFBOARDING (blocked) before any runtime
   starts; the operator re-runs `complete` once runtimes are enabled.
   `reconcile-receipts` verifies the receipt of every OFFBOARDED workspace;
   a receipt no tombstone names is reported, not a failure (as ADR-033 note 3).

## Retained by design

Audit and lifecycle events (`authz_audit_events`, `dataset_events`,
`plan_outcome_events`), the delivery record (`external_actions`; delivered
Slack messages cannot be recalled), `dataset_processing_requests`, and the
dataset and workspace tombstones. Their periods follow ADR-035.

## Consequences and limits

- **Connector secrets: a fail-closed operator step** (review of PR #70). The
  secret store (`EnvironmentSecretStore`, the worker's secrets env file) has no
  delete operation, so the operator removes every `NLW_SECRET_<WORKSPACE_HEX>_*`
  entry and recreates the worker. `complete --secrets-file <that file>` is
  required: it reads the file read-only before anything is purged and again in
  the final transaction, and refuses while any entry of the workspace remains
  or the file is not a readable regular file. The receipt binds
  `secret_refs`, `secret_store: environment-file` and
  `secrets_verified_absent: true` into its digest. Limits: it verifies the
  file it is given (the operator names the store's real file; the
  O-6 operator container mounts it read-only), not a worker process that was
  not recreated; a store with a delete API would replace this step. Before
  customer data, a store with verifiable deletion is still recommended.
- **Users** are platform identities, not workspace data: a user who belonged
  only to this workspace keeps a `users` row (no workspace access).
- **A run in flight** fails at its next transaction (its context no longer
  resolves); its rows are then purged. External actions already sent remain.
- `complete` purges dataset objects only with the operator's store; the object
  backups (O-4) keep copies until they expire.
- The receipt is written before the tombstone commits: a failure in between
  leaves a receipt without a tombstone (reported); re-running `complete` writes
  a new one.
- The customer-facing statement still awaits owner approval.

## Independent review (PR #70) and fixes

| Finding | Fix |
|---|---|
| Medium: the secret-store check missed forms `docker compose env_file` loads (`KEY: v`, a bare `KEY`, a UTF-8 BOM) | every such form counts; any other non-blank, non-comment line refuses `complete` (fail closed) |
| Medium: `accept_workspace_invitation` (SECURITY DEFINER, no tenant context) could add a member to an OFFBOARDING workspace | it refuses a workspace that is not ACTIVE (0031); `request` also revokes pending invitations |
| Low: the discovery policy still showed an OFFBOARDING workspace | `workspaces_app_select` adds `workspace_is_active(id)` (altered in place; 74 policies) |
| Low: the scheduler's cross-tenant `workflow_runs` policies read and could create the workspace's runs; the reconciler would re-enqueue runs no worker can process | both policies add `workspace_is_active(tenant_id)`; `request` fails open runs (`error = WORKSPACE_OFFBOARDING`) |
| Low: the retained delivery record kept where it was sent (`destination_summary`) | `complete` scrubs it to NULL (ids, status and times kept) |
| Low: the receipt is written before the tombstone commits | documented above; `reconcile-receipts` reports such a receipt, re-running `complete` converges |
| Sound | `workspace_is_active` (owner, `search_path`, grants, NULL id), the replaced functions and their exact downgrade, the state trigger, purge order and NOT NULL scopes, B unaffected |

**Decided (owner, 2026-10-24): the grant ledger is scrubbed** (migration
`0032_workspace_grant_scrub`; see the amendment below).

Not covered by the check: secrets injected into the worker by any other means
than the named file (compose `environment:`, other env files). The runbook
step also lists the worker's live variable names
(`docker compose exec worker env | cut -d= -f1`, names only) after recreating it.

## Amendment (2026-10-24): the workspace-creation grant ledger

Owner decision: when offboarding completes, the founder's raw email and every
direct email-to-workspace link leave the grant ledger.

- **Scrubbed** (set to NULL, in `complete`'s final transaction, verified):
  `email_normalized`, `consumed_by_user_id` (it leads to the email through
  `users`) and the operator's free-text `note`.
- **Kept** (non-personal audit evidence): the immutable grant `id`, the
  `consumed_workspace_id` (the tombstone), `granted_by` and `revoked_by`
  (operator labels), `created_at`, `expires_at`, `consumed_at`, `revoked_at`,
  and the new `scrubbed_at` / `scrubbed_by`. No email-derived value of any kind
  (no hash, keyed or not): no actor reference is needed, so none is kept. The
  workspace receipt binds the count (`table_counts["workspace_creation_grants:scrubbed"]`)
  into its digest.
- **Guarded** (0032): a scrub is allowed only for a non-ACTIVE workspace and may
  change nothing but those columns; a scrubbed row never changes and is never
  deleted; constraints refuse a half scrub. Runtime roles still hold no
  privilege on the table.
- **Reuse and replay**: a scrubbed grant stays consumed and its NULL email
  matches no lookup, so it can never found another workspace; the
  one-open-grant-per-email index covers open grants only, so a new, separate
  grant for the same person still works. Scrubbing is idempotent.
- **Restore**: a restored snapshot may predate the scrub. `reapply-receipts`
  scrubs the founding grant of every workspace a receipt proves offboarded
  (`scrubbed_by = restore-reapply`), under the recovery lock, before any runtime
  starts; a dry run only counts.
- **Migration**: additive; an upgrade from a populated 0031 changes no row.
  Downgrade is refused while any grant is scrubbed (the 0022 schema cannot
  hold a row without an email); otherwise it restores the 0022 checks by
  definition. Database backups taken before the scrub keep the email until
  they expire (twelve months, ADR-035); a restore re-scrubs as above.

**Residual (not the ledger):** the founder's `users` row (the sign-in identity,
with its email) is platform data and stays; retained audit events
(`authz_audit_events`, e.g. `workspace.created`) keep the founder's user id with
the tombstone id. An operator holding the owner credential can therefore still
join them; no runtime role can (`users` is own-row only for `nlw_app`). Account
deletion or pseudonymisation of retained actor ids is a separate decision,
required before customer data.
