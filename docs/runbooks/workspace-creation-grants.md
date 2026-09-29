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
could consume the grant. Owner decision (2026-09-29): external identities
must use **confirmed** email addresses. NLW does not read a confirmation claim
from the token; it relies on the provider issuing sessions only for confirmed
addresses. Before issuing any grant to an external customer, verify in the
hosted Supabase project that email confirmation is required for sign-up and
email change (Phase 2 plan §22, question 5), and issue grants shortly before
the founder signs in.

The email a grant is matched against is `users.email` as recorded at the
identity's **first** sign-in; it is not refreshed if the address later changes
at the provider. Issue a grant for the address the founder signs in with today,
and do not reuse an address that has changed hands.

Public workspace creation stays disabled (owner decision): there is no `open`
mode, and every founding needs a grant or is refused.

## Who may run this

Atul is the primary operator (owner decision, 2026-09-29). A second
operator/reviewer is required **before external customer onboarding**; until
one is named, grants are issued only for the pilot's own test identities.
Commands need the **owner** database credential, like `python -m nlw.ctxkeys`;
no runtime role can read or write the grant table.

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
instead. An **expired** grant still counts as the email's one open grant, so
`add` refuses a new grant for that email until you `revoke` the expired one.
Structured logs record grant ids only; the `list` output shows emails to the
operator's terminal and must not be pasted into tickets.

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

## Downgrade (security sensitive)

Downgrading below `0022_workspace_creation_grants` **restores the ungated
bootstrap** (any authenticated identity can found unlimited workspaces again)
and **drops the grant ledger**, including the consumption and revocation
history; `workspace.created` / `identity.provisioned` audit rows remain. Never
downgrade a live environment past `0022`. To stop founding in an emergency use
`WORKSPACE_CREATION_MODE=closed` and fix forward. The restore validator
(`workspace_bootstrap_requires_grant`) and the rollout signed-context gate both
report an ungated bootstrap as a failure / NO-GO.
