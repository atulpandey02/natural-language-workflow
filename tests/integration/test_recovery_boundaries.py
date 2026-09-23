"""Executed recovery-boundary evidence (M12B-A addendum, Part 3).

Each test drives the REAL engine against real Postgres through a deterministic
injection seam and asserts the durable facts: was the tool invoked, was it
invoked again, the attempt count, and the final run/step/action status, with a
comment on why retry/resume/fail/UNKNOWN is correct. Postgres is authoritative;
Redis is only a wake-up; no completed step is repeated; no ambiguous external
action is resent; recovery never replans or alters an approved workflow. The
real guarantee is deterministic state transitions + idempotency where supported
+ explicit UNKNOWN — NOT exactly-once.

Process-level SIGKILL is intentionally NOT used: the engine keeps NOTHING in
worker memory across an advancement, so a real crash leaves exactly the durable
state that committing at the two-phase boundary (Txn1 claim commit / lease
expiry / pre-finalize) leaves. These seams reproduce that state deterministically
without the flakiness of racing a spawned process against the shared test
container and signed-context key. (See ADR-013 and docs/.../ai-core-recovery-matrix.md.)
"""

import contextlib
import json
import uuid
from collections.abc import Callable
from types import SimpleNamespace

import httpx
import psycopg
import pytest
from sqlalchemy.orm import Session, sessionmaker

from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.domain.workflow import WorkflowPlan
from nlw.engine.actions import ActionExecResult, ActionKind, ActionTask, run_action
from nlw.engine.execution import execute_advancement, process_advance
from nlw.engine.runs import create_run, create_workflow_with_version
from nlw.secrets.store import EnvironmentSecretStore
from nlw.tenancy.session import apply_signed_context_sync
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

ActionRunner = Callable[[ActionTask], ActionExecResult]
STORE = EnvironmentSecretStore()


def _noop(rid: uuid.UUID, delay: float | None = None) -> None:
    return None


class CountingSink:
    """Counts deliveries; every send is a separate business effect."""

    def __init__(self, response: httpx.Response | None = None) -> None:
        self.calls = 0
        self._resp = response or httpx.Response(200, headers={"X-Request-Id": "r1"})

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return self._resp

    def runner(self) -> ActionRunner:
        return lambda task: run_action(task, transport=httpx.MockTransport(self.handler))


def _app_sm(pg_stack: SimpleNamespace) -> sessionmaker[Session]:
    return create_sync_sessionmaker(create_sync_engine(pg_stack.settings))


def _worker_sm(pg_stack: SimpleNamespace) -> sessionmaker[Session]:
    return create_sync_sessionmaker(create_sync_engine(pg_stack.worker_settings))


def _seed(pg_stack: SimpleNamespace, m: SimpleNamespace, plan: WorkflowPlan) -> uuid.UUID:
    with _app_sm(pg_stack)() as s, s.begin():
        apply_signed_context_sync(
            s, pg_stack.sign(Purpose.API_REQUEST, user_id=m.user_id, tenant_id=m.tenant_id)
        )
        wf, ver = create_workflow_with_version(s, m.tenant_id, "wf", plan)
        return create_run(s, m.tenant_id, wf.id, ver.id).id


def _seed_webhook(owner_libpq: str, tenant_id: uuid.UUID, status: str = "active") -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO connectors (id, tenant_id, type, name, config, status) "
            "VALUES (%s,%s,'webhook','hook',%s::jsonb,%s)",
            (uuid.uuid4(), tenant_id, json.dumps({"url": "https://sink.example/hook"}), status),
        )


def _webhook_plan() -> WorkflowPlan:
    return WorkflowPlan.model_validate(
        {
            "steps": [
                {
                    "id": "notify",
                    "tool": "webhook.send",
                    "args": {"payload": {"x": 1}},
                    "connector": "hook",
                }
            ]
        }
    )


def _echo_plan(*ids: str) -> WorkflowPlan:
    steps: list[dict[str, object]] = []
    prev: list[str] = []
    for i in ids:
        steps.append({"id": i, "tool": "fake.echo", "args": {"n": i}, "depends_on": list(prev)})
        prev = [i]
    return WorkflowPlan.model_validate({"steps": steps})


def _row(owner_libpq: str, sql: str, params: tuple[object, ...]) -> tuple[object, ...] | None:
    with psycopg.connect(owner_libpq) as c:
        return c.execute(sql, params).fetchone()


def _expire_lease(owner_libpq: str, run_id: uuid.UUID) -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "UPDATE external_actions SET lease_expires_at = now() - interval '1 second' "
            "WHERE run_id=%s",
            (run_id,),
        )


def _ready_for_retry(owner_libpq: str, run_id: uuid.UUID) -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "UPDATE external_actions SET lease_expires_at = now() - interval '1 second', "
            "next_attempt_at = now() - interval '1 second' WHERE run_id=%s",
            (run_id,),
        )


def _approve(owner_libpq: str, run_id: uuid.UUID, decided_by: uuid.UUID) -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "UPDATE approvals SET status='approved', decided_by=%s, decided_at=now() "
            "WHERE run_id=%s",
            (decided_by, run_id),
        )


def _park_and_approve(
    sm: sessionmaker[Session],
    run_id: uuid.UUID,
    m: SimpleNamespace,
    owner_libpq: str,
    runner: ActionRunner,
) -> None:
    """webhook.send is approval-gated: the first advance PARKS the run; approve it
    so the NEXT advance performs the durable claim + delivery."""
    assert process_advance(sm, run_id, _noop, STORE, runner).result == "waiting"
    _approve(owner_libpq, run_id, m.user_id)


def _drive(sm: sessionmaker[Session], run_id: uuid.UUID, runner: ActionRunner, n: int = 8) -> str:
    last = "noop"
    for _ in range(n):
        last = str(process_advance(sm, run_id, _noop, STORE, runner).result)
        if last in ("completed", "failed", "waiting", "noop"):
            break
    return last


# --- 1. duplicate Redis/wake-up delivery for the same run -----------------------------
def test_1_duplicate_wakeup_is_idempotent(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    run_id = _seed(pg_stack, m, _echo_plan("a"))
    sm = _worker_sm(pg_stack)
    outcomes = [execute_advancement(sm, run_id).result for _ in range(5)]
    # BEFORE: PENDING. AFTER: one advance + completion, the rest no-ops.
    assert outcomes[0] == "advanced" and "completed" in outcomes
    step = _row(
        pg_stack.owner_libpq, "SELECT status, attempt FROM step_runs WHERE run_id=%s", (run_id,)
    )
    assert step == ("SUCCESS", 1)  # tool invoked once; never repeated. WHY: run-row FOR UPDATE.


# --- 2. worker interruption after claim but before tool invocation --------------------
def test_2_crash_after_claim_before_send_delivers_once(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = CountingSink()
    _park_and_approve(sm, run_id, m, pg_stack.owner_libpq, sink.runner())
    # Claim only (execute_advancement commits Txn1: the leased external_actions
    # row + step RUNNING) then "crash" before send: never run/finalize the action.
    claim = execute_advancement(sm, run_id, STORE)
    assert claim.action_task is not None
    assert sink.calls == 0  # tool NOT invoked yet
    ea = _row(
        pg_stack.owner_libpq,
        "SELECT status, attempts FROM external_actions WHERE run_id=%s",
        (run_id,),
    )
    assert ea == ("pending", 1)  # durable claim exists
    # A redelivery BEFORE lease expiry DEFERS (live lease), never double-sends.
    assert execute_advancement(sm, run_id, STORE).result == "deferred"
    assert sink.calls == 0
    # After lease expiry, resume delivers EXACTLY once. WHY: stable idempotency key.
    _expire_lease(pg_stack.owner_libpq, run_id)
    assert _drive(sm, run_id, sink.runner()) == "completed"
    assert sink.calls == 1
    assert _row(
        pg_stack.owner_libpq, "SELECT status FROM step_runs WHERE run_id=%s", (run_id,)
    ) == ("SUCCESS",)


# --- 3. interruption after a read-only tool returns but before durable completion -----
def test_3_inline_crash_before_commit_rolls_back_and_reruns_once(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    import nlw.engine.execution as execmod

    m = pg_stack.seed_member()
    run_id = _seed(pg_stack, m, _echo_plan("a"))
    sm = _worker_sm(pg_stack)
    calls = {"n": 0}
    real = execmod.execute_tool

    def crashing(spec, args, ctx):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 1:
            # The tool "ran" (output produced) but the process dies before the
            # in-lock transaction commits -> a non-business error rolls it back.
            raise RuntimeError("simulated crash after tool returned, before commit")
        return real(spec, args, ctx)

    monkeypatch.setattr(execmod, "execute_tool", crashing)
    with pytest.raises(RuntimeError):
        execute_advancement(sm, run_id)
    # BEFORE COMMIT crash: the whole advancement rolled back -> step still PENDING.
    assert _row(
        pg_stack.owner_libpq, "SELECT status FROM step_runs WHERE run_id=%s", (run_id,)
    ) in (("PENDING",), None)
    # Resume with a clean tool: the step is SUCCESS exactly once (attempt 1) and
    # nothing partial was committed by the aborted attempt. WHY: the inline step
    # is a single atomic transaction — a crash before commit leaves no trace.
    monkeypatch.setattr(execmod, "execute_tool", real)
    assert execute_advancement(sm, run_id).result == "advanced"
    assert _row(
        pg_stack.owner_libpq, "SELECT status, attempt FROM step_runs WHERE run_id=%s", (run_id,)
    ) == ("SUCCESS", 1)


# --- 4. interruption during a step -> CATEGORY A: read-only re-execution is safe ------
# The reviewer's recovery taxonomy requires this boundary to be UNAMBIGUOUS about
# WHY re-execution after an interruption is safe. There are exactly two safe cases:
#   A. the tool is READ-ONLY: it holds no external-action lease and creates no
#      side effect, so re-running it is definitionally harmless (the read may occur
#      more than once).
#   B. the tool has an ENFORCED idempotency contract with the receiver, so a
#      re-attempt with the *same* stable key collapses to one effect.
# This scenario proves case A precisely. A GENERIC side effect (no enforced
# contract) is category C and is governed by UNKNOWN, NOT by free re-execution;
# that separation is proven by ``test_4_negative_*`` and ``test_8_*`` below. See
# the release note in docs/.../ai-core-recovery-matrix.md on the crash-window gap.
def test_4_readonly_reexecution_may_occur_more_than_once_and_is_safe(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    import nlw.engine.execution as execmod

    m = pg_stack.seed_member()
    run_id = _seed(pg_stack, m, _echo_plan("a"))
    sm = _worker_sm(pg_stack)
    calls = {"n": 0}
    real = execmod.execute_tool

    def crashing(spec, args, ctx):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 1:
            # The read-only tool RAN (produced a result) but the worker dies before
            # the in-lock transaction commits -> the whole advancement rolls back.
            raise RuntimeError("simulated crash after read-only tool returned, before commit")
        return real(spec, args, ctx)

    # The wrapper self-heals after the first call, so the RESUME re-execution is
    # also counted (proving the read tool runs more than once across the crash).
    monkeypatch.setattr(execmod, "execute_tool", crashing)
    with pytest.raises(RuntimeError):
        execute_advancement(sm, run_id)
    # Resume: the read-only step re-executes (second invocation) and reaches SUCCESS.
    assert execute_advancement(sm, run_id).result == "advanced"

    # Category-A invariants:
    # (1) the read tool was invoked MORE THAN ONCE across the crash...
    assert calls["n"] >= 2
    # (2) ...yet it NEVER created an external-action lease row (read-only tools do
    #     not enter the two-phase side-effecting path where duplicates could occur)...
    assert _row(
        pg_stack.owner_libpq, "SELECT count(*) FROM external_actions WHERE run_id=%s", (run_id,)
    ) == (0,)
    # (3) ...and the durable result is written exactly once (attempt stays 1).
    assert _row(
        pg_stack.owner_libpq, "SELECT status, attempt FROM step_runs WHERE run_id=%s", (run_id,)
    ) == ("SUCCESS", 1)


def test_4_negative_generic_side_effect_uses_leased_path_not_readonly_reexecution(
    pg_stack: SimpleNamespace,
) -> None:
    """Negative regression: an action WITHOUT an enforced idempotency contract can
    never enter scenario 4's free re-execution path. The engine routes every
    side-effecting tool through the durable two-phase LEASED external-action path
    (a leased ``external_actions`` row + stable key), whose ambiguous-outcome
    resolution is terminal UNKNOWN (scenario 8) — it is NOT re-run like a read-only
    step. A read-only tool, by contrast, never creates such a row."""
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)

    # Read-only echo: inline execution, NO leased external-action row.
    echo_run = _seed(pg_stack, m, _echo_plan("a"))
    sm = _worker_sm(pg_stack)
    assert execute_advancement(sm, echo_run).result == "advanced"
    assert _row(
        pg_stack.owner_libpq, "SELECT count(*) FROM external_actions WHERE run_id=%s", (echo_run,)
    ) == (0,)

    # Generic side effect (webhook.send, no enforced idempotency contract): the
    # claim produces an action_task and a leased row — the two-phase path, never
    # the inline read-only re-execution path.
    hook_run = _seed(pg_stack, m, _webhook_plan())
    sink = CountingSink()
    _park_and_approve(sm, hook_run, m, pg_stack.owner_libpq, sink.runner())
    claim = execute_advancement(sm, hook_run, STORE)
    assert claim.action_task is not None  # routed to the leased side-effecting path
    assert _row(
        pg_stack.owner_libpq, "SELECT count(*) FROM external_actions WHERE run_id=%s", (hook_run,)
    ) == (1,)


def test_4_known_gap_generic_crash_window_is_at_least_once_not_unknown(
    pg_stack: SimpleNamespace,
) -> None:
    """KNOWN DIVERGENCE (release-blocking), documented honestly, not as 'safe'.

    A generic side effect interrupted in its crash-after-send / pre-finalize window
    is currently REDELIVERED at-least-once (ADR-013), reusing the stable key; a
    non-idempotent receiver may therefore observe a DUPLICATE. The reviewer's target
    contract is that a generic (non-contractual) side effect whose transmission is
    uncertain must instead become terminal ACTION_OUTCOME_UNKNOWN and NEVER be
    resent. Reconciling the two is an ADR-013-level durability change (it also turns
    a provable crash-BEFORE-send into UNKNOWN, a reliability trade-off) and is NOT
    performed here; see the release note in ai-core-recovery-matrix.md. This test
    pins the ACTUAL behavior so the gap is explicit and un-hidden — it does not
    assert the behavior is safe, and it never claims exactly-once."""
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = CountingSink()
    _park_and_approve(sm, run_id, m, pg_stack.owner_libpq, sink.runner())
    claim = execute_advancement(sm, run_id, STORE)
    assert claim.action_task is not None
    # Send succeeds but "crash" before finalize (do not call finalize_action).
    run_action(claim.action_task, transport=httpx.MockTransport(sink.handler))
    assert sink.calls == 1
    key_first = _row(
        pg_stack.owner_libpq,
        "SELECT external_action_key FROM external_actions WHERE run_id=%s",
        (run_id,),
    )
    assert _row(
        pg_stack.owner_libpq, "SELECT status FROM external_actions WHERE run_id=%s", (run_id,)
    ) == ("pending",)  # not finalized
    # Resume after lease expiry: the current engine RE-DELIVERS (at-least-once) —
    # a duplicate send is possible here. We assert the stable key is REUSED (the
    # only property that bounds the blast radius), NOT exactly-once, NOT safety.
    _expire_lease(pg_stack.owner_libpq, run_id)
    assert _drive(sm, run_id, sink.runner()) == "completed"
    assert sink.calls >= 1  # at-least-once; may be a duplicate for a non-idempotent receiver
    key_after = _row(
        pg_stack.owner_libpq,
        "SELECT external_action_key FROM external_actions WHERE run_id=%s",
        (run_id,),
    )
    assert key_after == key_first  # stable key reused across the redelivery, never regenerated
    assert _row(
        pg_stack.owner_libpq, "SELECT status FROM step_runs WHERE run_id=%s", (run_id,)
    ) == ("SUCCESS",)


# --- 5. worker restart while waiting for approval -------------------------------------
def test_5_restart_while_waiting_approval_resumes(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _webhook_plan())
    sink = CountingSink()
    # First "worker" parks the run at WAITING_APPROVAL.
    assert process_advance(_worker_sm(pg_stack), run_id, _noop, STORE, sink.runner()).result == (
        "waiting"
    )
    assert _row(
        pg_stack.owner_libpq, "SELECT status FROM workflow_runs WHERE id=%s", (run_id,)
    ) == ("WAITING_APPROVAL",)
    assert sink.calls == 0  # no side effect before approval
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    # A FRESH worker process (new sessionmaker = no shared memory) resumes + delivers.
    assert _drive(_worker_sm(pg_stack), run_id, sink.runner()) == "completed"
    assert sink.calls == 1
    assert _row(
        pg_stack.owner_libpq, "SELECT status FROM workflow_runs WHERE id=%s", (run_id,)
    ) == ("COMPLETED",)


# --- 6. scheduler duplicate occurrence creation --------------------------------------
def test_6_duplicate_scheduled_occurrence_is_exactly_once(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    run_id = _seed(pg_stack, m, _echo_plan("a"))
    vrow = _row(
        pg_stack.owner_libpq, "SELECT workflow_version_id FROM workflow_runs WHERE id=%s", (run_id,)
    )
    wrow = _row(
        pg_stack.owner_libpq, "SELECT workflow_id FROM workflow_runs WHERE id=%s", (run_id,)
    )
    assert vrow is not None and wrow is not None
    version_id, workflow_id = vrow[0], wrow[0]
    sched_id, occ = uuid.uuid4(), "2026-01-01 00:00:00+00"
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO schedules (id, tenant_id, workflow_id, workflow_version_id, timezone, "
            "frequency, minute, hour, enabled, next_run_at, created_by) "
            "VALUES (%s,%s,%s,%s,'UTC','daily',0,0,true,now(),%s)",
            (sched_id, m.tenant_id, workflow_id, version_id, m.user_id),
        )
        for _ in range(2):
            with contextlib.suppress(psycopg.errors.UniqueViolation):
                c.execute(
                    "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, "
                    "status, trigger, schedule_id, scheduled_for) "
                    "VALUES (%s,%s,%s,%s,'PENDING','scheduled',%s,%s)",
                    (uuid.uuid4(), m.tenant_id, workflow_id, version_id, sched_id, occ),
                )
    n = _row(
        pg_stack.owner_libpq,
        "SELECT count(*) FROM workflow_runs WHERE schedule_id=%s AND scheduled_for=%s",
        (sched_id, occ),
    )
    assert n == (1,)  # WHY: uq_run_schedule_occurrence — exactly one run per occurrence.


# --- 7. external-action pre-transmission failure remains retryable --------------------
def test_7_pre_transmission_failure_is_retryable(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _webhook_plan())
    sm = _worker_sm(pg_stack)
    hits = {"n": 0}

    class _Refused(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

    def runner(task: ActionTask) -> ActionExecResult:
        hits["n"] += 1
        return run_action(task, transport=_Refused())

    _park_and_approve(sm, run_id, m, pg_stack.owner_libpq, runner)
    out = process_advance(sm, run_id, _noop, STORE, runner)
    assert out.result == "retry"  # provably before transmission -> retryable
    ea = _row(
        pg_stack.owner_libpq,
        "SELECT status, attempts, next_attempt_at IS NOT NULL FROM external_actions "
        "WHERE run_id=%s",
        (run_id,),
    )
    assert ea == ("pending", 1, True)  # step stays RUNNING; backoff scheduled.
    assert _row(
        pg_stack.owner_libpq, "SELECT status FROM step_runs WHERE run_id=%s", (run_id,)
    ) == ("RUNNING",)


# --- 8. post-transmission ambiguity becomes UNKNOWN and is never resent ---------------
def test_8_ambiguous_outcome_is_unknown_and_not_resent(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sends = {"n": 0}

    def ambiguous(task: ActionTask) -> ActionExecResult:
        sends["n"] += 1
        # A transmitted-but-unconfirmable outcome (e.g. a timeout after send).
        return ActionExecResult(kind=ActionKind.UNKNOWN, error_class="timeout")

    _park_and_approve(sm, run_id, m, pg_stack.owner_libpq, ambiguous)
    assert _drive(sm, run_id, ambiguous) in ("failed", "noop")
    ea = _row(
        pg_stack.owner_libpq,
        "SELECT status, error_class FROM external_actions WHERE run_id=%s",
        (run_id,),
    )
    assert ea == ("unknown", "ACTION_OUTCOME_UNKNOWN")
    assert _row(
        pg_stack.owner_libpq, "SELECT status, error FROM step_runs WHERE run_id=%s", (run_id,)
    ) == ("FAILED", "ACTION_OUTCOME_UNKNOWN")
    before = sends["n"]
    # A re-drive must NOT resend an ambiguous action. WHY: terminal UNKNOWN.
    process_advance(sm, run_id, _noop, STORE, ambiguous)
    assert sends["n"] == before


# --- 9. graceful shutdown during a running step --------------------------------------
def test_9_graceful_shutdown_mid_step_resumes_without_double_effect(
    pg_stack: SimpleNamespace,
) -> None:
    # A graceful shutdown after the durable claim leaves the same state as a crash:
    # the leased row is committed, the process stops before finalize. Resume after
    # lease expiry completes it exactly once (same guarantee as scenario 2, framed
    # as an orderly stop rather than a kill).
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = CountingSink()
    _park_and_approve(sm, run_id, m, pg_stack.owner_libpq, sink.runner())
    execute_advancement(sm, run_id, STORE)  # claim (Txn1 commit) + orderly "stop"
    assert sink.calls == 0
    _expire_lease(pg_stack.owner_libpq, run_id)
    assert _drive(_worker_sm(pg_stack), run_id, sink.runner()) == "completed"
    assert sink.calls == 1


# --- 10. retry exhaustion reaches the documented terminal state -----------------------
def test_10_retry_exhaustion_terminal(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _webhook_plan())
    sm = _worker_sm(pg_stack)

    class _Refused(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

    def runner(task: ActionTask) -> ActionExecResult:
        return run_action(task, transport=_Refused())

    _park_and_approve(sm, run_id, m, pg_stack.owner_libpq, runner)
    # Drive past the attempt cap, clearing the lease + backoff each round so the
    # next attempt actually fires (rather than deferring on a future next_attempt).
    for _ in range(15):
        process_advance(sm, run_id, _noop, STORE, runner)
        status_row = _row(
            pg_stack.owner_libpq,
            "SELECT status FROM external_actions WHERE run_id=%s",
            (run_id,),
        )
        if status_row is not None and status_row[0] in ("failed", "unknown"):
            break
        _ready_for_retry(pg_stack.owner_libpq, run_id)
    ea = _row(
        pg_stack.owner_libpq,
        "SELECT status, attempts FROM external_actions WHERE run_id=%s",
        (run_id,),
    )
    assert ea is not None
    # Terminal: a provably-not-transmitted connect failure exhausts to a terminal
    # state; the run is FAILED. Attempts are bounded by the cap.
    assert ea[0] in ("failed", "unknown")
    assert _row(
        pg_stack.owner_libpq, "SELECT status FROM workflow_runs WHERE id=%s", (run_id,)
    ) == ("FAILED",)
