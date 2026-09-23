# Durable execution, checkpoints & recovery matrix (M12B-A, Part F)

The engine's guarantee, stated precisely: **deterministic state transitions in
Postgres (the system of record) + a durable pre-transmission boundary so a side
effect that may have started is never automatically resent + explicit UNKNOWN
handling where an external outcome is ambiguous.** It is **not** exactly-once
execution: a generic side effect is at-most-once with an explicit UNKNOWN when the
outcome is unprovable (ADR-013 P4); only a tool with an enforced idempotency
contract may replay. Redis/Dramatiq carries a `run_id`
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
| 4 | death **during** an external action (after the transmission boundary) | **UNKNOWN, never resent** (unless the tool has an enforced idempotency contract) | the durable `transmission_started_at` boundary is committed before the send; a crash after it means the effect MAY have transmitted, and a stable key does not authorize replay → terminal UNKNOWN (ADR-013 P4). Crash BEFORE the boundary → retry. | `test_crash_transmission_boundary.py`, `test_action_execution.py::test_w2_*`, `test_recovery_boundaries.py::test_4_*` |
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

## Crash-after-transmission safety: the three re-execution categories (ADR-013 P4)

An interrupted step is re-executed only when that is provably safe. The engine
distinguishes three cases, and the durable `external_actions.transmission_started_at`
boundary (migration `0018`) is what makes the distinction survive process death.

- **A — read-only tool.** Re-execution has no external effect, so a read may occur
  more than once and it is inherently safe. Read-only tools never take an
  external-action lease. Proof: `test_recovery_boundaries.py::test_3_*`,
  `::test_4_readonly_reexecution_may_occur_more_than_once_and_is_safe`, and the
  negative routing test `::test_4_negative_*`.
- **B — side effect with an ENFORCED idempotency contract** (`ToolSpec.idempotent_
  delivery = True`). The receiver is contractually required and verified to
  deduplicate on the stable `external_action_key`, so a replay after ambiguity
  collapses to one effect. **No production connector is category B** today. Proof:
  `test_crash_transmission_boundary.py::test_9_*` (a test-only contract tool).
- **C — generic / non-contractual side effect** (`webhook.send`,
  `slack.send_message`). A stable key is not a dedup contract. Once the durable
  boundary is crossed, an unconfirmed outcome is terminal `ACTION_OUTCOME_UNKNOWN`
  and is **never resent** — the same rule as within-attempt ambiguity (boundary
  10). A crash **before** the boundary is provably pre-transmission and is retried.
  Proof: `test_crash_transmission_boundary.py` (the full ten-point matrix),
  `test_action_execution.py::test_w2_*`, `test_crash_windows.py`,
  `test_action_lease_safety.py::test_lease_overrun_boundary_prevents_second_transmission`,
  `test_recovery_boundaries.py::test_4_generic_crash_after_boundary_is_unknown_never_resent`.

This deliberately admits a **conservative false UNKNOWN** (a worker that dies just
after committing the boundary, before any bytes leave, becomes UNKNOWN even though
nothing was sent). That availability cost is accepted; an uncontrolled duplicate is
not. It is **not** exactly-once: a category-C effect is at-most-once with an
explicit UNKNOWN when the outcome is unprovable.

## The grounded result after recovery

`GET /runs/{id}/summary` (M12B-A) reads only persisted state and reports the true
outcome after any of the above: it never converts a FAILED/SKIPPED/UNKNOWN step
into success, and it flags an UNKNOWN external action as "may or may not have
completed" rather than success or definite failure
(`test_ai_core_smoke.py::test_smoke_failure_resume_grounded_no_repeat`,
`test_run_summary.py`).
