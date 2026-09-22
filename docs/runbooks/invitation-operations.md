# Runbook: workspace invitations

Membership invitations for the pilot ([ADR-023](../adr/ADR-023-membership-approval-sod.md)).
Tokens are single-use and stored only as a sha256 hash; the raw token is shown
**once** at creation for manual sharing. There is no email delivery — share the
link/token out of band.

## Invite a user (admin/owner)

```bash
# X-Workspace-Id selects the active workspace; the caller must be admin/owner.
curl -sX POST "$API/invitations" -H "Authorization: Bearer $JWT" \
  -H "X-Workspace-Id: $WS" -H 'Content-Type: application/json' \
  -d '{"email":"newuser@example.com","role":"member"}'
# -> 201 { "id", "email", "role", "status":"pending", "expires_at", "token": "<RAW>" }
```

- `role` may be `member` or `admin` (never `owner` — ownership transfer is a
  separate, deliberate path).
- The **`token`** is returned only here. It is never logged, metered, audited, or
  returned again. Share it with the invitee over a trusted channel.
- Default expiry is **72h** (`INVITATION_EXPIRY_HOURS`). At most one pending invite
  per (workspace, email); a per-workspace pending cap
  (`INVITATION_MAX_PENDING_PER_WORKSPACE`, default 100) bounds spam.

## Accept an invitation (the invitee)

```bash
curl -sX POST "$API/invitations/accept" -H "Authorization: Bearer $INVITEE_JWT" \
  -H 'Content-Type: application/json' -d '{"token":"<RAW>"}'
# -> 200 { "workspace_id", "role" }   (or 400 "invitation is not valid")
```

- Acceptance requires an authenticated Supabase identity whose **verified email
  matches** the invite. Every invalid case (wrong email, expired, revoked, already
  used, unknown) returns the **same** `400 invitation is not valid` — it never
  reveals whether an email belongs to a user/workspace.
- Acceptance is atomic and single-use; concurrent accepts create exactly one
  membership.

## List / revoke pending invitations (admin/owner)

```bash
curl -s "$API/invitations" -H "Authorization: Bearer $JWT" -H "X-Workspace-Id: $WS"
curl -sX POST "$API/invitations/$INV_ID/revoke" -H "Authorization: Bearer $JWT" \
  -H "X-Workspace-Id: $WS"   # 204
```

Responses never expose the token or its hash.

## Expiry

Expiry is enforced **lazily at acceptance** (an expired invite fails closed). There
is no background expiry job in the pilot; a `pending` row past `expires_at` is
simply un-acceptable. To tidy up, an operator may mark them:

```sql
UPDATE workspace_invitations SET status='expired'
WHERE status='pending' AND expires_at <= now();
```

## Audit

Invitation create/accept/revoke and membership add/role-change/remove are recorded
in `authz_audit_events` (tenant-scoped, append-only, **no tokens/secrets**). Query
as an admin/owner via the DB, e.g.:

```sql
SELECT created_at, event_type, actor_user_id, subject_id
FROM authz_audit_events WHERE tenant_id = :ws ORDER BY created_at DESC LIMIT 50;
```

## Troubleshooting

- **`403` on create/list/revoke** — the caller is not admin/owner of the workspace.
- **`409 a pending invitation for this email already exists`** — revoke the existing
  one first, or wait for it to be accepted/expire.
- **`409 too many pending invitations`** — clear pending invites or raise the cap.
- **`400 invitation is not valid` on accept** — wrong email, expired, revoked, or
  already used. Issue a fresh invite. (This is intentionally uniform — do not read
  more into it.)
