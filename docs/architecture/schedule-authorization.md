# Schedule authorization ownership (M12B final, Part 4)

## Intended policy (explicit)

A schedule is a **workspace asset**, created by an authorized workspace member
(owner/admin — the role `POST /schedules` requires). It is not privately owned, but
its continued authority derives from a currently-authorized human:

- **Occurrence creation is permitted only while the schedule's `created_by` remains
  an active member of the workspace with a sufficient (owner/admin) role.**
- Removal or demotion of the creator **blocks future occurrences** (fail-closed):
  no run is created, nothing is enqueued, and a stable, sanitized reason is
  recorded. The scheduler never continues indefinitely under authority that no
  longer exists.
- **Already-running occurrences** follow the existing run/action safety model
  (durable state, approval gates, connector-identity binding, UNKNOWN semantics).
- Blocking requires an **explicit administrator remediation** to resume:
  1. **restore + unblock** — an admin re-establishes the creator's membership/role,
     then `POST /schedules/{id}/unblock`; or
  2. **recreate** — an admin creates a new schedule under themselves (the creator
     of the new schedule is the acting admin). `created_by` is immutable by P3A
     separation of duties, so ownership *transfer* is a recreate, not an in-place
     rewrite.
- The **LLM never decides** schedule authorization; it is deterministic SQL.

## Mechanism

- `schedules.blocked_reason` / `blocked_at` (migration 0020) record the fail-closed
  state. A blocked schedule is **excluded from the due-scan** (`blocked_reason IS
  NULL`), so it never re-scans and never accumulates failed-run rows.
- Before creating each occurrence, `scan_due` calls the SECURITY DEFINER function
  `schedule_creator_block_reason(schedule_id)`, which returns a stable
  low-cardinality reason or NULL:
  - `CREATOR_NOT_A_MEMBER` — the creator has no membership in the workspace;
  - `CREATOR_ROLE_INSUFFICIENT` — the creator's role is below owner/admin.
  The function is owned by the BYPASSRLS helper role, so the least-privileged
  `nlw_scheduler` (which cannot read `memberships`) never gets a broad grant.
- A blocked scan sets `blocked_reason`/`blocked_at`, advances `next_run_at`, creates
  **no** run, and increments the low-cardinality metric
  `nlw_scheduler_blocked_total{reason}`. The blocked state is exposed to authorized
  users on `GET /schedules/{id}` (`blocked_reason`, `blocked_at`).
- **Status precedence in the UI** is `blocked` → `active` (enabled) → `disabled`:
  a blocked schedule is never shown as active, even while `enabled=true`, and the
  reason is rendered as a fixed human-readable sentence keyed on the stable reason
  code (an unknown code gets a generic sentence — no SQL/policy internals reach the
  screen). There is no unblock UI; `POST /schedules/{id}/unblock` is deliberately
  NOT in the BFF allowlist until one exists.
- **A successful unblock is audited**: the state transition and an append-only
  `authz_audit_events` row (`event_type='schedule.unblocked'`, actor = the
  admin/owner, subject = the schedule id, detail = the prior reason code — nothing
  else) commit in the same transaction, or neither does. A refused unblock (409) or
  a forbidden one (403) writes nothing; unblocking a schedule that is not blocked is
  an idempotent no-op (no event, no `next_run_at` change). `created_by` stays
  immutable and the next occurrence is forward-only (no catch-up).

## What each requirement maps to

| Requirement | Where |
|---|---|
| creator still a member / sufficient role | `schedule_creator_block_reason` (pre-occurrence) |
| schedule enabled/current | existing `enabled` filter in the due-scan |
| workflow/version current | pinned `workflow_version_id` (FK) |
| connector bindings fresh | enforced at **execution** (Part 3): a scheduled run with a stale binding fails STALE_PLAN before any connector I/O — proven by `test_schedule_authorization::test_6` |
| approval policy current / never bypassed | approval is **re-derived at execution**; a scheduled action still parks at WAITING_APPROVAL — `test_7` |
| no unbounded failed runs | blocked schedules excluded from the scan — `test_10` |
| occurrence uniqueness + fairness | unchanged (`uq_run_schedule_occurrence`, SKIP LOCKED, per-tenant limits) |
| cross-tenant reassignment impossible | RLS-scoped endpoint + `_require_admin` — `test_9` |

Adversarial coverage: `tests/integration/test_schedule_authorization.py` (10 cases).
