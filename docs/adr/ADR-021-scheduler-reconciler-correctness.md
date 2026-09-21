# ADR-021 — Scheduler & reconciler correctness (M11.5 P1D)

- Status: Accepted
- Date: 2026-09-21

## Context

M8's scheduler/reconciler (ADR-015) worked but the external review found six
correctness gaps: scheduled-run idempotency collided with the client namespace;
the reconciler applied `LIMIT` before excluding beyond-horizon/ineligible rows
(starvation); staleness was measured by the mutable `updated_at` (misleading
recovery); no per-tenant fairness (one noisy tenant could consume the whole
batch); the WAITING_APPROVAL re-drive was bound to the run, not the blocked step;
and there was no explicit progress signal. This is a pilot, so the fixes are
small PostgreSQL-native mechanisms, not a new distributed system.

## Decision

### Scheduled-occurrence identity & idempotency namespaces

- **Occurrence identity** is the immutable `(schedule_id, scheduled_for)`, where
  `scheduled_for` is a normalized UTC occurrence instant from the recurrence math
  (`latest_occurrence`), NOT the scheduler's execution time, local tz, or a
  mutable expression. Uniqueness is a DB constraint (`uq_run_schedule_occurrence`)
  plus `INSERT ... ON CONFLICT DO NOTHING` — the database, not the application,
  arbitrates concurrent schedulers.
- **Three separate idempotency namespaces:**
  1. *manual/API* runs use the client `Idempotency-Key` (`uq_run_tenant_idempotency`);
  2. *scheduler* runs use the occurrence identity and store **NULL** `idempotency_key`
     (they never occupy the client namespace);
  3. *external-action delivery* keys are the P1C `external_action_key` (a different
     problem: at-least-once effect idempotency, unchanged).
  A client key can never collide with, suppress, or be mistaken for a scheduled
  occurrence. The API additionally rejects the reserved `sched:` prefix.

### Reconciler eligibility, ordering & fairness

- **All deterministic eligibility filters run BEFORE `ORDER BY`/`LIMIT`** (a CTE):
  status, expired-lease/backoff, terminal + P1C-UNKNOWN exclusion, approval state,
  and the recovery horizon. The limited candidate set contains only rows the
  reconciler can actually process; beyond-horizon runs are counted separately for
  the gauge, never allowed to crowd out eligible rows.
- **Stable order** `progress_at ASC, id ASC` (unique tie-breaker), not an unstable
  timestamp-only order.
- **Per-tenant fairness:** `row_number() OVER (PARTITION BY tenant_id ORDER BY
  progress_at, id)` caps each tenant at `scheduler_reconcile_per_tenant_limit`
  (validated `1 <= cap <= scheduler_batch_limit`), then a global `LIMIT
  scheduler_batch_limit`. One tenant contributes at most its cap, so a noisy
  tenant cannot starve a quiet tenant's single eligible row; total never exceeds
  the global batch. Deferred rows are counted (fairness metric) and remain for a
  later scan. Applied at the run-reconciliation query boundary (the only queue).
- The reconciler still **writes nothing**; two reconcilers may both select a run,
  and the worker's `FOR UPDATE` + idempotent replay advance it at most once.

### Progress tracking (`last_progress_at`)

- New `workflow_runs.last_progress_at` (server time, `func.now()`), stamped ONLY on
  genuine state-machine advancement: run entering execution, step claim/start,
  step terminal, retry scheduling/claim, approval resolution that unblocks work,
  action finalization, run terminal. NEVER on a reconciler scan, a read, an
  unrelated metadata write, or a no-op/stale-CAS finalize.
- The reconciler measures RUNNING staleness/horizon by `last_progress_at`
  (COALESCE with `created_at` for pre-backfill rows), so an actively progressing
  long run is left alone while a genuinely stuck one is recovered.
- Backfilled conservatively on migration from `COALESCE(finished_at, started_at,
  updated_at, created_at)` — no pretense that old runs progressed "now".

### Approval-to-step binding

- The reconciler re-drives a WAITING_APPROVAL run ONLY when the CURRENTLY-blocked
  step's own approval is decided: `approvals JOIN step_runs ON (run_id, step_id)
  WHERE step_runs.status='WAITING_APPROVAL' AND approvals.status IN
  (approved,rejected)`. A historical/other-step approval never re-drives a run
  whose current step is still pending. The worker already binds `_handle_waiting`
  by `(run_id, step_id)`; `UNIQUE(run_id, step_id)` on approvals and step_runs
  guarantees one approval per step. Two advances can't double-advance a step
  (`WorkflowRun FOR UPDATE` + CAS approval decide).

### Approval-instance binding (review outcome)

A `(run_id, step_id)` binding is exact and unambiguous because **at most one
approval row can ever exist per `(run_id, step_id)`** — a "historical decided +
current pending" pair for the SAME step is impossible:

- **Constraint:** `uq_approval_run_step UNIQUE(run_id, step_id)` (migration 0008).
  Attempting a second row fails closed (unique violation).
- **Creation:** the only approval producer, `_park_for_approval`, is
  get-or-create (inserts only when none exists); nothing deletes, replaces, or
  supersedes an approval, and `decide` is a CAS `UPDATE` on the single row.
- **No stale generation:** a step is never reset to WAITING_APPROVAL after
  advancing (retries keep it RUNNING); P1C re-approval after a connector change
  **fails the current run** (deterministic `re-approval required`) rather than
  materializing a second approval, so re-approval is a NEW run with its own new
  approval (a different `run_id`).

No `current_approval_id`/schema change is therefore needed — it would add
redundant state. Proven by real-DB tests
(`tests/integration/test_approval_instance_binding.py`): a second same-step
insert is rejected; a pending approval blocks and its decision advances once; an
approval for another run/step/tenant is never consumed; a connector change fails
the run without a second approval; concurrent advances consume the single
approval once.

### Privileges

- `nlw_worker` already had table-level `SELECT,UPDATE` on workflow_runs (writes
  `last_progress_at`). `nlw_scheduler` already had cross-tenant `SELECT` on
  workflow_runs (reads it). The only new grant is a **column-restricted**
  cross-tenant `SELECT (id, tenant_id, run_id, step_id, status)` on step_runs for
  `nlw_scheduler` (approval binding); step I/O (input/output/error) stays
  unreadable. RLS/FORCE-RLS/ownership otherwise unchanged.

## Guarantees (honest)

- **Exactly one run row per scheduled occurrence**, via a database uniqueness
  invariant (not application check-then-insert).
- **At-least-once processing attempts**: the reconciler re-enqueues; the worker
  is idempotent under `FOR UPDATE` + replay.
- **CAS/leases constrain DATABASE ownership** only. This is NOT exactly-once
  execution, and external effects retain P1C's UNKNOWN + receiver-idempotency
  limitations (a DB lease cannot fence an external receiver).

## Consequences

- Scheduler/reconciler are collision-free, starvation-resistant, fair, and
  measure real progress, with small indexed queries (a BitmapOr over partial
  per-status indexes on a mostly-terminal table, not a full-table sort per poll).
- Config defaults: `scheduler_batch_limit=100`,
  `scheduler_reconcile_per_tenant_limit=20`, `scheduler_pending_threshold_s=60`,
  `scheduler_recovery_horizon_s=86400` (24h, WAITING_APPROVAL exempt).
- Deferred: cross-entity fairness frameworks, reconcile latency histograms beyond
  the added counters, and any further scheduler namespacing.
