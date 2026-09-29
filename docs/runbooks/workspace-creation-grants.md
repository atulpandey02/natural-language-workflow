# Runbook: workspace-creation grants

Founding a workspace requires an operator-issued grant for the founder's email
([ADR-023 amendment 1](../adr/ADR-023-membership-approval-sod.md#amendment-1--founding-a-workspace-requires-an-operator-grant-phase-2-b01-2026-09-29),
migration `0022_workspace_creation_grants`). Joining an existing workspace still
uses an [invitation](invitation-operations.md).

Grants are single-use, bound to one normalised email (`lower(trim(email))`),
expire (default 72h, maximum 30 days), and are never deleted: consumption and
revocation are recorded on the row. At most one open grant exists per email.

## Trust boundary

A grant (like an invitation) is bound to the **email claim in the identity
provider's token**. It is exactly as strong as the provider's proof that the
signer-in owns that address: if the hosted Supabase project allows sign-up
without email confirmation, someone who registers the grantee's address first
could consume the grant. Confirm the hosted signup and confirmation settings
(Phase 2 plan §22, question 5) before issuing grants to external customers, and
issue grants shortly before the founder signs in.

## Who may run this

The named operator for the pilot (owner decision pending: Phase 2 plan §22,
"Who operates the operator role"). Commands need the **owner** database
credential, like `python -m nlw.ctxkeys`; no runtime role can read or write the
grant table.

## Issue a grant

```bash
export DATABASE_MIGRATION_URL=...   # owner credential; never paste it into chat or logs
export NLW_OPERATOR="<your name>"
python -m nlw.ops.grants add --email founder@example.com --expires-in 72h --note "pilot customer 3"
# -> granted: <grant-uuid>
```

Tell the founder to sign in and choose **Create and open** on the workspace
page. Without a grant they see "Ask your administrator to set up your
workspace" and nothing is created.

## Inspect and revoke

```bash
python -m nlw.ops.grants list          # open grants
python -m nlw.ops.grants list --all    # include consumed / revoked (and expired)
python -m nlw.ops.grants revoke --id <grant-uuid>
```

A consumed grant cannot be revoked (the workspace exists); offboard the workspace
instead. Structured logs record grant ids only; the `list` output shows emails
to the operator's terminal and must not be pasted into tickets.

## Audit

- `authz_audit_events.event_type = 'workspace.created'`: `tenant_id` and
  `subject_id` are the new workspace; `detail` is the consumed grant id;
  `actor_user_id` is the founder.
- `authz_audit_events.event_type = 'identity.provisioned'`: one tenant-less row
  per identity first seen by the API.

## Emergency: stop all tenant creation

Set `WORKSPACE_CREATION_MODE=closed` for the API and recreate the `api`
service. Every `POST /workspaces` then returns 403
`WORKSPACE_CREATION_CLOSED`, even with a grant; open grants stay unconsumed.
There is no `open` mode.
