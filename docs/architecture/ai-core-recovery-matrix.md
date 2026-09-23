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
| 4 | death **during** an external action (crash-after-send / pre-finalize) | **at-least-once redelivery** (duplicate possible), or UNKNOWN on cap exhaustion | reclaimed via lease + stable `external_action_key`; a non-idempotent receiver **may observe a duplicate** — this is NOT safely retryable in the exactly-once sense (ADR-013); if the retry cap is hit with a dead lease → terminal UNKNOWN. See **Known gap** below. | `test_action_execution.py`, `test_action_unknown_outcome.py`, `test_crash_windows.py`, `test_recovery_boundaries.py::test_4_*` |
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

## Known gap (release-blocking): crash-window delivery for non-idempotent connectors

The boundary-4 crash window (a worker dies **after transmitting** a side effect but
**before finalizing**) is currently handled as **at-least-once redelivery**: on
lease expiry the reconciler re-attempts with the *same* stable `external_action_key`
(ADR-013). For a receiver with no enforced idempotency contract — which is **every
current connector** (`webhook.send`, `slack.send_message`); a best-effort
`Idempotency-Key` header is not an enforced contract — this **can produce a
duplicate** side effect. It is honest at-least-once, never exactly-once, and no test
or doc claims otherwise.

The stricter **target contract** is: a generic (non-contractual) side effect whose
transmission is uncertain must become terminal `ACTION_OUTCOME_UNKNOWN` and **never
be resent** — matching how within-attempt ambiguity is already handled (boundary 10,
`test_8_*`). Reconciling the two is an **ADR-013-level durability change**, not an
evidence-pass fix, because the resume path cannot distinguish crash-*before*-send
from crash-*after*-send (the durable state is identical), so a conservative
non-idempotent rule also turns a *provably un-sent* action into UNKNOWN — a
reliability trade-off (a routine worker restart mid-claim would fail the run as
"may have occurred"). It also inverts the deliberate, honestly-documented
crash-window tests (`test_w1/w2_*`, `test_lease_overrun_*`, recovery scenarios
2/4/9).

Minimal correction design (for that follow-up package):
1. add a `ToolSpec.idempotent_delivery: bool = False` capability (an **enforced**
   end-to-end contract, not a header); no current connector sets it;
2. in `_resume_action`, clear `next_attempt_at` on lease acquire so it reliably
   marks "an attempt is/was in flight";
3. in `_resume_action`, when resuming an interrupted in-flight attempt
   (`next_attempt_at is None`, dead lease, under the cap) of a `side_effecting`
   tool that is **not** `idempotent_delivery`, return terminal UNKNOWN instead of
   re-acquiring. A *scheduled retry* (`next_attempt_at` set — a provable
   pre-transmission failure such as a Slack 429) still re-attempts, preserving P1C.

Until then, recovery scenario 4 is stated as **category A** (read-only re-execution
is safe; `test_4_readonly_reexecution_may_occur_more_than_once_and_is_safe`), a
negative regression proves a generic side effect is routed to the leased two-phase
path rather than the read-only re-execution path
(`test_4_negative_generic_side_effect_uses_leased_path_not_readonly_reexecution`),
and the residual at-least-once crash-window behavior is pinned openly as a known gap
(`test_4_known_gap_generic_crash_window_is_at_least_once_not_unknown`).

## The grounded result after recovery

`GET /runs/{id}/summary` (M12B-A) reads only persisted state and reports the true
outcome after any of the above: it never converts a FAILED/SKIPPED/UNKNOWN step
into success, and it flags an UNKNOWN external action as "may or may not have
completed" rather than success or definite failure
(`test_ai_core_smoke.py::test_smoke_failure_resume_grounded_no_repeat`,
`test_run_summary.py`).
