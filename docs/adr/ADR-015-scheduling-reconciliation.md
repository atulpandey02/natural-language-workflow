# ADR-015 — Durable scheduling & unattended reconciliation

- Status: Accepted
- Date: 2026-09-19

## Context

M8 turns the heartbeat scheduler into a real durable scheduler that fires
recurring workflows and recovers unattended execution — while preserving the
M0–M7 invariants (Postgres is the system of record, Redis is transport only, the
worker is the sole execution/state authority, tenant isolation, approvals,
at-least-once action safety).

## Decision

- **Structured recurrence, no cron.** `schedules` store `timezone` (IANA) +
  `frequency ∈ {hourly, daily, weekly}` + `minute` (+`hour`, +`day_of_week`),
  deterministically validated. The LLM never creates schedules.
- **Immutable version pin.** A schedule pins `workflow_version_id` at creation;
  scheduled runs always execute that exact plan.
- **Exactly one run row per occurrence.** Due-scan claims schedules with
  `SELECT … FOR UPDATE SKIP LOCKED` and creates runs `ON CONFLICT DO NOTHING`
  against `UNIQUE(schedule_id, scheduled_for)`, guaranteeing **exactly one durable
  `workflow_run` row per schedule occurrence across scheduler concurrency and
  restart**. Run creation + `next_run_at` advancement commit in **one
  transaction**; enqueue happens **after** commit. This is a guarantee about the
  run *row*, not about execution: queue delivery and step execution remain
  **idempotent (at-least-once)** via the M3 engine, not exactly-once.
- **DST (wall-clock, `zoneinfo`, `fold=0`).** A nonexistent spring-forward time
  fires shifted forward by the gap duration (day not skipped); a fall-back
  ambiguous time fires once at the earlier offset.
- **Bounded catch-up.** After downtime, fire only the latest missed occurrence
  within a 1h window (config-capped), skip older, always advance `next_run_at`.
  `last_scheduled_for` updates only when a run is actually created.
- **Reconciler triggers the worker.** A second loop reconstructs recovery
  eligibility **entirely from PostgreSQL** (Redis is used only as transport for
  the re-enqueued `run_id`), and re-enqueues (idempotent):
  PENDING older than a threshold (commit-before-enqueue / lost message); RUNNING
  with an in-flight action whose lease expired and whose `next_attempt_at` is
  due/absent; ordinary stale RUNNING (between inline steps); WAITING_APPROVAL
  whose approval is decided (approved **or** rejected). It **writes nothing** —
  the worker's M7 resume logic enforces lease / `next_attempt_at` / approval, so
  a re-enqueue can never duplicate a live action or re-run a SUCCESS step.
- **Least-privilege `nlw_scheduler` role.** LOGIN, NOSUPERUSER, **NOBYPASSRLS**.
  Cross-tenant access is granted only via role-specific RLS policies
  (`USING (true)`) on exactly the tables it needs: `schedules` (SELECT + narrow
  `UPDATE(next_run_at, last_scheduled_for, updated_at)`), `workflow_runs`
  (SELECT + INSERT), `external_actions`/`approvals` (SELECT). It has **no** grant
  on connectors, secrets, or `step_runs` I/O, and never resolves secrets or runs
  tools. The scheduler container receives neither `NLW_SECRET_*` nor
  `NLW_LLM_API_KEY`.
- **Schedule mutation is admin/owner** — enforced by FastAPI role **and** an RLS
  `is_current_user_admin_or_owner` predicate; `created_by` is server-owned.
- **Disable over delete.** Schedules are disabled (retain history), not destroyed.

## Crash windows

- Commit ok, enqueue fails → orphan PENDING run → reconciler re-enqueues.
- Enqueue ok, scheduler dies → worker already has it.
- Crash before `next_run_at` advance → whole txn rolls back → reprocessed; no
  partial state (creation + advance are atomic).
- Duplicate schedulers → SKIP LOCKED + unique constraint.

## Alternatives considered

- **Global `BYPASSRLS` scheduler role** — rejected: too broad; role-specific
  `USING(true)` policies on only the needed tables keep secrets/step-I/O
  unreadable.
- **SECURITY DEFINER functions for the claim** — rejected: DST recurrence math is
  far clearer in Python; the role-scoped policies give the needed cross-tenant
  access without SQL-side date math.
- **Backfill all missed occurrences** — rejected: unbounded thundering herd;
  bounded latest-missed is safer.
- **Reconciler mutating run/step state** — rejected: the worker must stay the
  sole writer; the reconciler only enqueues.

## Consequences

- Each schedule occurrence yields exactly one durable run row (across concurrency
  and restart); execution stays idempotent/at-least-once. Recurring workflows
  survive restarts and duplicate schedulers, respect DST, and recover unattended
  without weakening any M7 guarantee. Raw cron, sub-minute cadence, backfill, and
  approval timeouts are deferred.

**Superseded in part by ADR-021 (M11.5 P1D):** scheduled runs now store NULL
`idempotency_key` (occurrence identity is the sole uniqueness); reconciler
eligibility/horizon filters run before `ORDER BY`/`LIMIT`; RUNNING staleness is
measured by `last_progress_at` (not `updated_at`); per-tenant reconciliation
fairness is added; and WAITING_APPROVAL re-drive is bound to the currently-blocked
step. See ADR-021.
