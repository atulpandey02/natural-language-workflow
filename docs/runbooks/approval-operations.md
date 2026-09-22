# Runbook: approvals & separation of duties

Approval-gated actions require a genuine four-eyes decision
([ADR-023](../adr/ADR-023-membership-approval-sod.md)): the human who **requested**
an action can never decide it, even as owner/admin.

## Who can decide

An approval may be decided only by a user who is **all** of:
- authenticated and an **active admin/owner** of the workspace;
- **not** the approval's `requested_by_user_id` (the requester);
- deciding the exact current pending approval for the waiting `(run_id, step_id)`,
  with the connector binding still matching the approved preview (P1C).

This is enforced by the RLS `WITH CHECK` on `approvals` (not only the API), so a
direct SQL self-approval as `nlw_app` is rejected.

## Requester provenance

`approvals.requested_by_user_id` is immutable and derived from execution
provenance, never request JSON:
- **Manual run** → the authenticated creator (`workflow_runs.initiated_by_user_id`).
- **Scheduled run** → the immutable schedule creator (`schedules.created_by`).
- Retry/reconciliation keeps the **original** requester (never the worker,
  scheduler, reconciler, or a retrying operator).

## Deciding

```bash
curl -sX POST "$API/approvals/$ID/approve" -H "Authorization: Bearer $JWT" \
  -H "X-Workspace-Id: $WS"
curl -sX POST "$API/approvals/$ID/reject" -H "Authorization: Bearer $JWT" \
  -H "X-Workspace-Id: $WS"
```

`GET /approvals` lists pending approvals; each carries `requested_by_user_id` and
`viewer_can_decide` (false for the requester and for non-admins) so a UI can
disable self-approval.

## Responses

- `200` — decided (idempotent: repeating the same decision re-enqueues the resume).
- `403 you cannot decide an approval you requested` — separation of duties.
- `403 insufficient role` — the caller is not admin/owner.
- `409 approval already decided` — a different decision already won.
- `409 approval has no recorded requester …` — a **legacy** approval whose requester
  is unknown fails closed. Re-request the action so a requester is recorded, or
  reject it. Do **not** backfill a guessed requester.

## Legacy approvals (migration note)

Migration `0015` backfills `requested_by_user_id` only where reliable (scheduled
runs → schedule creator). Pending **manual-run** approvals created before P3A have
a NULL requester and **cannot be decided** — they must be rejected and the action
re-requested. Find them:

```sql
SELECT id, run_id FROM approvals WHERE status='pending' AND requested_by_user_id IS NULL;
```

## Audit

Approval decisions and denied self-approval attempts are recorded (denials are
logged, not persisted per-attempt, to avoid attacker-controlled volume). Decision
identity (`requested_by_user_id`, `decided_by`, timestamps) is immutable.
