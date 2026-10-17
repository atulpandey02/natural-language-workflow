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

**Open owner decision:** `workspace_creation_grants` (a platform table) keeps
the founder's normalized email with `consumed_workspace_id`, linking it to the
tombstone. It is the operator's grant ledger; whether to scrub the email or the
link on offboarding is a retention decision for the owner, not changed here.

Not covered by the check: secrets injected into the worker by any other means
than the named file (compose `environment:`, other env files). The runbook
step also lists the worker's live variable names
(`docker compose exec worker env | cut -d= -f1`, names only) after recreating it.
