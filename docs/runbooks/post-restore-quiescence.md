# Runbook: post-restore quiescence (what it does and why)

Post-restore **quiescence** is the correctness core of DR
([ADR-022](../adr/ADR-022-encrypted-offhost-backup-dr.md)). It runs automatically
inside `restore` (and can be run standalone with `python -m nlw.backup quiesce`).
This runbook explains what it changes so operators can reason about the restored
state — **do not** start the runtime without it.

## The problem it solves

A logical restore reinstates rows exactly as they were mid-flight at backup time:
runs in `RUNNING`/`PENDING`/`WAITING_APPROVAL`, external actions holding leases,
and schedules whose `next_run_at` is now in the past. If the worker/scheduler
started against that snapshot they would **re-drive already-delivered side
effects** (duplicate webhooks / Slack messages) and **replay missed schedule
occurrences**. Restoring is not just about data presence; it is about not
re-executing history.

## The transition matrix (idempotent, owner/superuser, single transaction)

Applied against non-terminal / pre-cutoff state only (so re-running is a no-op):

| Object | From | To | Effect |
|---|---|---|---|
| `workflow_runs` | non-terminal (`PENDING`,`RUNNING`,`WAITING_APPROVAL`,…) | `FAILED`, `error=DR_RESTORE_UNCERTAIN` | in-flight runs are not silently resumed |
| `step_runs` | non-terminal | `FAILED`, `error=DR_RESTORE_UNCERTAIN` | in-flight steps stopped |
| `external_actions` | non-final delivery (e.g. `pending`) | `unknown`, `error_class=ACTION_OUTCOME_UNKNOWN`, lease cleared, `next_attempt_at=NULL` | an at-least-once effect that may already have fired is **never blindly re-driven** (reuses P1C UNKNOWN semantics) |
| `schedules` | `next_run_at <= cutoff` | recomputed via `next_occurrence` | missed occurrences are **not** replayed |
| terminal runs/steps, `success` actions, future schedules | — | **untouched** | completed history preserved |

Terminal and idempotency-key state is preserved (keys are not reused/regenerated).

## Audit

Each quiescence records a `dr_restore_events` row (Alembic `0014`) — outside RLS,
with **no** runtime-role grant, so it is non-forgeable by tenant SQL — capturing
the cutoff, manifest identity (format/revision/snapshot), and the counts
(`runs_quiesced`, `steps_quiesced`, `actions_unknowned`, `schedules_recomputed`).
On a no-op re-run, no new audit row is written.

## Idempotency & the runtime-start gate

- Re-running `quiesce` after a first pass changes nothing (0/0/0/0) and records no
  new event — safe to repeat.
- `restore_ready(engine)` returns true only when a `dr_restore_events` row exists
  **and** no non-terminal runs remain. The runtime must not start until then; the
  `restore` Compose profile deliberately excludes api/worker/scheduler.

## What to tell tenants

Runs marked `DR_RESTORE_UNCERTAIN` were interrupted by recovery and completed with
an **unknown external-effect status** — a webhook/Slack message from such a run
may or may not have been delivered before the incident. Affected work in the lost
RPO window should be re-submitted.

## Standalone use

```bash
# quiesce only (idempotent); prints the counts.
NLW_RESTORE_DATABASE_URL=postgresql://nlw:...@db/nlw \
  docker compose -f docker-compose.prod.yml --profile restore run --rm \
  --entrypoint "python -m nlw.backup" restore quiesce
```
