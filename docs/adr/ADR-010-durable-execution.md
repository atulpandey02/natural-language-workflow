# ADR-010 — Durable workflow execution: checkpointing, idempotency, concurrency

- Status: Accepted
- Date: 2026-09-18

## Context

Workflow execution must be durable, resumable, tenant-isolated, and safe under
**at-least-once** worker delivery. Postgres is authoritative state; Redis carries
only lightweight instructions. The worker must derive workflow state and tenant
ownership from Postgres, not from message payloads.

## Decision

- **Message shape:** `advance_run(run_id)` — no state in the payload. The worker
  loads authoritative state from Postgres by `run_id`.
- **One step per advancement, one transaction.** Each `advance_run`: resolves the
  tenant, `SET LOCAL app.tenant_id`, `SELECT … FOR UPDATE` the run, executes
  exactly one runnable step (pure fake tool), checkpoints the step result + run
  status, and **COMMITs**. Enqueueing the next `advance_run` happens **after**
  the commit and is injectable; its failure **propagates** (the invocation fails
  and is retried) rather than being swallowed.
- **Concurrency:** the `FOR UPDATE` row lock on `workflow_runs` serializes
  advancements per run. A second worker blocks until the holder commits, then
  observes the committed state and advances the next step — two workers can never
  execute the same step.
- **Idempotency:** `UNIQUE(run_id, step_id)` plus "skip if already SUCCESS." A
  committed step is never re-executed; redelivered/duplicate `advance_run`
  messages cause at most harmless extra advancements. Run creation is deduped by
  `UNIQUE(tenant_id, idempotency_key)` (tenant-scoped).
- **Crash recovery:** a crash mid-transaction rolls back (no partial state); a
  crash after commit but before enqueue is recovered because the triggering
  message is still unacked and is redelivered — replay skips the committed step
  and advances the next one. This is why enqueue is post-commit.
- **Worker tenant bootstrap (no GUC self-policy):** the worker resolves
  `run_id → tenant_id` through a hardened, **worker-only** SECURITY DEFINER
  function `resolve_run_tenant` (minimal `search_path`, schema-qualified,
  returns only the tenant uuid), owned by a **non-login BYPASSRLS** role and
  executable only by `nlw_worker`. `workflow_runs` keeps only tenant-scoped RLS.
  A connectable role cannot expose another tenant's row by setting a variable —
  the M2b invariant is preserved and FORCE RLS stays on every table.
- **Roles / least privilege:** `nlw_app` (API) creates/reads; `nlw_worker`
  (execution) has only SELECT on versions, SELECT+UPDATE on runs, SELECT/INSERT/
  UPDATE on step_runs, and EXECUTE on the resolver — both `NOSUPERUSER
  NOBYPASSRLS`, no DELETE. Roles are created by bootstrap, not migrations.
- **Tools:** deterministic, side-effect-free (`fake.echo`, `fake.fail`). Purity
  is what makes at-least-once replay safe in M3.
- **State machines:** run `PENDING→RUNNING→COMPLETED|FAILED`; step
  `PENDING→RUNNING→SUCCESS|FAILED`. No `SKIPPED` (no conditional execution yet).

## Alternatives considered

- **`app.run_id` RLS self-policy** for the worker bootstrap — rejected: any
  connectable role could set the GUC and read another tenant's run, weakening
  M2b. The SECURITY DEFINER resolver confines the elevation to the worker role.
- **Drop FORCE RLS on `workflow_runs`** so the owner-owned resolver bypasses —
  rejected: weakens the uniform FORCE-RLS posture.
- **Multiple steps per message / optimistic concurrency** — rejected for M3:
  one-step-per-advancement with `FOR UPDATE` is the simplest correct design.
- **Temporal / LangGraph** — out of scope; unnecessary at this stage.

## Consequences

- Durable, resumable, concurrency-safe execution proven by tests (crash/resume,
  duplicate delivery, concurrent advancement, tenant isolation, resolver
  boundary).
- Deferred: a reconciliation sweep for runs stuck `RUNNING` if an unacked message
  is permanently lost (M8 scheduler); idempotency keys for **non-idempotent**
  external side effects (M7); step retry/backoff; parallel fan-out; conditional
  execution (`SKIPPED`). Real tools must not run long-running work inside the run
  lock without the mark-RUNNING/execute-outside/finalize pattern.
