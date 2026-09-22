# ADR-023 — Membership, invitations & approval separation of duties (M11.5 P3A)

- Status: Accepted
- Date: 2026-09-21

## Context

The pilot had two authorization gaps confirmed by the P3 audit:

1. **A workspace owner could not invite a second real user.** The only
   membership-write path was the `create_workspace_for_current_user` bootstrap
   (which makes the creator an owner); `nlw_app` had no way to add anyone else.
2. **Self-approval made the human gate cosmetic.** `approvals` recorded only
   `decided_by`; there was no requester field and no check, so an admin/owner who
   requested an approval-gated action could approve it themselves. The only
   DB rule was "the decider is an admin/owner and stamps themselves" — not
   "the decider is *not* the requester".

This is a pilot, so the fix is the smallest role model + PostgreSQL-native
invariants (constraints, RLS, short locked transactions, hashed single-use
tokens), not an IAM product or a policy engine. Supabase remains responsible for
authentication; NLW owns membership and authorization.

## Decision

### Role model
Three roles (`owner`, `admin`, `member`) — the existing `Role` enum and the
`ck_membership_role` CHECK, unchanged. Authorization is fail-closed:

| Operation | Owner | Admin | Member |
|---|---|---|---|
| View workspace roster | yes | yes | yes (co-members) |
| Invite member/admin | yes | yes | no |
| List/revoke invitation | yes | yes | no |
| Remove/demote a **member/admin** | yes | yes | no |
| Touch an **owner** row (promote-to-owner, demote/remove owner) | yes | **no** | no |
| Remove/demote the **final owner** | no | no | no |
| Decide an approval | yes, **if not the requester** | yes, **if not the requester** | no |

Membership administration is RLS-gated `nlw_app` writes (`memberships_app_admin_
update`/`_delete`): the acting user must be admin/owner of the workspace, and an
**admin cannot target an owner row** (`is_current_user_owner` guards owner rows).
Creating a membership stays function-only (bootstrap / invitation acceptance).

### Owner-preservation invariant
A per-row **constraint trigger** (`trg_workspace_owner_present`, AFTER UPDATE OR
DELETE) locks the workspace row (`SELECT … FOR UPDATE`) and raises if the
workspace would have zero owners. The row lock **serializes concurrent membership
changes for the same workspace**, so two parallel "remove/demote the last owner"
transactions cannot both succeed — a multi-row invariant a CHECK cannot express.

### Invitations (hashed, single-use)
`workspace_invitations` stores only the **sha256 hash** of a high-entropy
(`secrets.token_urlsafe(32)`, ~256-bit) token; the raw token is returned **once**
at creation for manual sharing and is never logged, metered, audited, or
persisted. Each invite binds workspace + normalized email + role (`admin`/`member`
only) + inviter + expiry (default **72h**, configurable). A partial unique index
(`uq_invitation_pending_email`) allows at most one pending invite per
(workspace, email); a per-workspace pending cap bounds spam.

**Acceptance is atomic and non-enumerating.** It runs through the SECURITY DEFINER
`accept_workspace_invitation(token_hash)` (owned by `nlw_workspace_bootstrap`,
`EXECUTE` to `nlw_app` only) because the accepter is not yet a member and cannot
write memberships/read the invite under RLS. It requires an authenticated identity,
matches the invite email to the caller's verified email (normalized), flips
`pending → accepted` (single-use; a lost race aborts), inserts exactly one
membership (`ON CONFLICT DO NOTHING` — concurrent accept → one membership), and
audits. Every failure mode (not-found / used / revoked / expired / wrong-email)
raises the **same** generic error, so acceptance cannot enumerate whether an email
belongs to a user/workspace. Email normalization is conservative (trim + lower;
no provider-specific dot/plus stripping that could merge distinct identities).

### Approval separation of duties (four-eyes), DB-enforced
- `approvals.requested_by_user_id` is the **immutable** identity of the human whose
  action requires approval. It is derived from execution provenance, **never** from
  request JSON: a manual run records `workflow_runs.initiated_by_user_id` (the
  authenticated creator); a scheduled run records the immutable schedule creator
  (`schedules.created_by`, denormalized onto the run by the scheduler so the worker
  — which has no schedules access — can set it). The worker stamps it when it parks
  the approval.
- Deciding requires **all** of: the decider is authenticated, an active admin/owner
  of the workspace, **not** `requested_by_user_id`, on the exact current pending
  approval for the waiting `(run_id, step_id)`, with the connector binding still
  matching the approved preview (P1C). The rule is enforced in the **RLS
  `WITH CHECK`** (`decided_by = app.user_id AND requested_by_user_id IS NOT NULL AND
  decided_by <> requested_by_user_id`), not only at the API — a direct
  self-approval UPDATE as `nlw_app` is rejected. The API pre-checks for clean errors
  (403 self-approval, 409 unknown-requester).
- A legacy approval whose requester is unknown (`NULL`) **fails closed** for
  decision. Backfill is deterministic only where reliable (scheduled →
  `schedules.created_by`); manual-run approvals stay NULL and must be re-requested.

### Audit
`authz_audit_events` is an append-only, tenant-scoped table (no tokens/secrets/
payloads/emails-where-an-id-suffices/exception text) recording invitation
created/accepted/revoked, membership role-changed/removed, and approval decisions
(self-approval denials are logged, not persisted per-attempt, to avoid
attacker-controlled volume).

## Alternatives considered
- **A permission language / policy engine** — rejected; three roles + explicit
  rules suffice for the pilot.
- **Email delivery** — out of scope (no provider wired); a one-time manually
  shareable link is sufficient. Add delivery later without schema change.
- **A CHECK for the owner invariant** — impossible (multi-row); the locked-row
  trigger is the correct PostgreSQL mechanism.
- **Application-only self-approval check** — insufficient; the invariant lives in
  RLS so direct SQL cannot bypass it.

## Consequences
- The forgeable-GUC boundary is unchanged here: an SQL attacker running as
  `nlw_app` who forges `app.user_id` to another admin could still self-approve.
  Closing that is **P3B (signed context)** and remains a launch gate.
- Downgrade of migration `0015` re-opens self-approval and final-owner removal —
  flagged in the migration and requiring operator review.
- New tables/functions/trigger must survive a DR restore — added to the restore
  validation surface (P3B).
