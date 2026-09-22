# Durable execution, checkpoints & recovery matrix (M12B-A, Part F)

The engine's guarantee, stated precisely: **deterministic state transitions in
Postgres (the system of record) + idempotency where the receiver supports it +
explicit UNKNOWN handling where an external outcome is ambiguous.** It is
**not** exactly-once execution (ADR-013). Redis/Dramatiq carries a `run_id`
wake-up signal only; losing it loses no workflow state (the reconciler re-derives
what to enqueue from SQL). Completed (`SUCCESS`) steps are never re-run
(`select_next_step`). Checkpoints are the durable state transitions themselves
(step claim, step terminal, retry scheduling, approval resolution, run terminal),
each committed under `SELECT … FOR UPDATE` on the run row.

All ten boundaries are also demonstrated as one consolidated, executed
evidence suite in `tests/integration/test_recovery_boundaries.py` (M12B-A
addendum, Part 3), which asserts the durable before/after state, whether the
tool was invoked/re-invoked, the attempt count, and the final status per
scenario.

## Failure-boundary matrix

Behavior categories: **retry** (re-attempt), **resume** (continue from persisted
state), **fail** (deterministic terminal FAILED), **UNKNOWN** (ambiguous side
effect, terminal, never resent).

| # | boundary | behavior | why | proven by |
|---|---|---|---|---|
| 1 | death **before** a step is claimed / message lost | resume | run stays PENDING/RUNNING; reconciler re-enqueues from `last_progress_at` | `test_engine_execution.py`, `test_scheduler_reconcile.py` |
| 2 | death **after claim, before** the side effect | resume | durable leased `external_actions` row + stable `external_action_key`; lease expiry lets the reconciler re-drive | `test_action_lease_safety.py`, `test_crash_windows.py` |
| 3 | death **after a read-only tool result** but before step completion | resume (re-run) | inline read-only step is re-executed in-lock; no external effect, idempotent | `test_engine_execution.py`, `test_ai_core_smoke.py` |
| 4 | death **during** an external action | retry or UNKNOWN | reclaimed via lease/idempotency key; if the retry cap is hit with a dead lease → terminal UNKNOWN | `test_action_execution.py`, `test_action_unknown_outcome.py`, `test_crash_windows.py` |
| 5 | worker restart mid-run | resume | all state in Postgres; no worker memory; SUCCESS steps skipped | `test_worker_roundtrip.py`, `test_engine_execution.py`, `test_ai_core_smoke.py` |
| 6 | duplicate queue delivery | resume (no double effect) | run-row `FOR UPDATE`; a live lease defers; a finalize is guarded by the lease token | `test_engine_execution.py::test_duplicate_delivery_is_idempotent`, `test_action_lease_safety.py` |
| 7 | approval wait and resume | resume | run parks at WAITING_APPROVAL; a durable decision (CAS) resumes it; a lost resume is recovered by the reconciler | `test_action_execution.py`, `test_approval_*`, `test_scheduler_reconcile.py` |
| 8 | scheduled occurrence creation | exactly-once per occurrence | `uq_run_schedule_occurrence` unique constraint | `test_scheduler_idempotency.py`, `test_scheduler_due.py` |
| 9 | retry exhaustion (business) | fail or UNKNOWN | deterministic/auth error → FAILED; retryable exhausted with a delivered-but-unconfirmed attempt → UNKNOWN | `test_action_execution.py`, `test_action_unknown_outcome.py` |
| 10 | UNKNOWN external-action outcome | UNKNOWN (terminal) | the side effect may have transmitted; step/run FAILED with `ACTION_OUTCOME_UNKNOWN`; **never resent**; the reconciler excludes any run with an `unknown` action | `test_action_unknown_outcome.py` |
| 11 | deployment shutdown during a run | resume | in-flight work is durable; the reconciler re-drives after restart; the recovery-lock gate (P2) blocks a restored DB until validated | `test_crash_windows.py`, `test_recovery_lock.py` |

## Invariants (held across all boundaries)

- PostgreSQL is the source of truth; the queue message is a wake-up signal, not
  authoritative workflow state.
- Step/run transitions go through the state machine (now guarded by
  `assert_transition_*`, M12B-A) plus the DB CHECK constraints, and are applied
  under the run-row lock (CAS serialized by that lock + the action lease token).
- Completed steps are not repeated after restart (`test_ai_core_smoke.py`
  asserts a completed step's `attempt` stays 1 after a re-advance).
- Side-effecting actions keep the P1C UNKNOWN semantics; ambiguous outcomes are
  never automatically resent.
- Checkpoints occur at durable state-transition boundaries; no in-memory
  conversation or agent state is required to recover (there is none — ADR-026).
- Stored tool output is bounded/redacted at the source connector (HTTP response
  cap, Postgres row/byte cap) and never contains secrets.
- Recovery never silently replans or changes the approved workflow: a run
  executes its immutable pinned `WorkflowVersion.plan`; an approved action is
  pinned to the approved connector id.

## The grounded result after recovery

`GET /runs/{id}/summary` (M12B-A) reads only persisted state and reports the true
outcome after any of the above: it never converts a FAILED/SKIPPED/UNKNOWN step
into success, and it flags an UNKNOWN external action as "may or may not have
completed" rather than success or definite failure
(`test_ai_core_smoke.py::test_smoke_failure_resume_grounded_no_repeat`,
`test_run_summary.py`).
