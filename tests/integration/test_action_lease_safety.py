"""Lease/attempt-ordering safety for external actions (M11.5 P1C).

A live lease is authoritative before attempt-cap evaluation: a duplicate worker
must never fail or steal a legitimate live final attempt.
"""

import threading
import uuid
from types import SimpleNamespace

import httpx
import psycopg
import pytest
from test_action_execution import (  # sibling module (pytest prepend import mode)
    Sink,
    _approve,
    _ea,
    _expire_lease,
    _noop_enqueue,
    _runner,
    _seed_run,
    _seed_webhook,
    _step,
    _webhook_plan,
    _worker_sm,
)

from nlw.engine.actions import (
    effective_attempt_cap,
    finalize_action,
    mark_transmission_started,
    run_action,
)
from nlw.engine.execution import execute_advancement, process_advance
from nlw.secrets.store import EnvironmentSecretStore
from nlw.tenancy.session import set_worker_context_default

pytestmark = pytest.mark.integration


def _count_ea(owner_libpq: str, run_id: uuid.UUID) -> int:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute(
            "SELECT count(*) FROM external_actions WHERE run_id=%s", (run_id,)
        ).fetchone()
    assert row is not None
    return int(row[0])


def _set_attempts(owner_libpq: str, run_id: uuid.UUID, attempts: int) -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute("UPDATE external_actions SET attempts=%s WHERE run_id=%s", (attempts, run_id))


def test_duplicate_cannot_fail_or_steal_a_live_final_attempt(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = Sink()
    store = EnvironmentSecretStore({})

    # Park for approval, approve, then worker A claims (attempt 1, live lease).
    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    claim_a = execute_advancement(sm, run_id, store)
    assert claim_a.action_task is not None
    task_a = claim_a.action_task
    live_lease = str(_ea(pg_stack.owner_libpq, run_id)["lease_token"])

    # This is the FINAL attempt: attempts == cap, A's lease still LIVE.
    _set_attempts(pg_stack.owner_libpq, run_id, effective_attempt_cap())

    # Duplicate worker B resumes while A's lease is live -> must DEFER, never
    # mark failed nor clear/replace A's lease.
    dup = execute_advancement(sm, run_id, store)
    assert dup.result == "deferred", f"duplicate must defer, got {dup.result!r}"
    ea_after_dup = _ea(pg_stack.owner_libpq, run_id)
    assert ea_after_dup["status"] == "pending"  # not failed
    assert str(ea_after_dup["lease_token"]) == live_lease  # A's lease intact
    assert ea_after_dup["attempts"] == effective_attempt_cap()  # not incremented

    # Worker A's external request succeeds and A finalizes.
    result_a = run_action(task_a, transport=sink.transport())
    final_a = finalize_action(sm, task_a, result_a, set_worker_context_default)

    assert len(sink.calls) == 1  # exactly one external effect, and it succeeded
    assert final_a.result == "advanced"
    ea = _ea(pg_stack.owner_libpq, run_id)
    step_status, _out = _step(pg_stack.owner_libpq, run_id)
    assert ea["status"] == "success", "the successful external effect must be recorded, not failed"
    assert step_status == "SUCCESS"


def test_concurrent_claims_serialize_on_the_real_run_lock(pg_stack: SimpleNamespace) -> None:
    """Two workers race to claim the same approved action against a REAL Postgres
    row lock. The ``WorkflowRun ... FOR UPDATE`` lock serializes them: exactly one
    creates the leased external_actions row (attempt 1); the other observes the
    live lease and defers. No duplicate row, no double increment, no stolen lease."""
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    store = EnvironmentSecretStore({})

    # Park + approve so both racers hit the claim/resume path.
    process_advance(_worker_sm(pg_stack), run_id, _noop_enqueue, store, _runner(Sink()))
    _approve(pg_stack.owner_libpq, run_id, m.user_id)

    # Each racer uses its OWN engine/connection so they genuinely contend in the DB.
    sms = [_worker_sm(pg_stack) for _ in range(2)]
    barrier = threading.Barrier(2)
    results: list[object] = [None, None]

    def racer(i: int) -> None:
        barrier.wait()  # line both threads up on the lock as closely as possible
        results[i] = execute_advancement(sms[i], run_id, store)

    threads = [threading.Thread(target=racer, args=(i,)) for i in range(2)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    claimed = [r for r in results if getattr(r, "action_task", None) is not None]
    deferred = [r for r in results if getattr(r, "result", None) == "deferred"]
    assert len(claimed) == 1, "exactly one worker may hold the claim"
    assert len(deferred) == 1, "the loser must defer, never fail or steal the lease"

    assert _count_ea(pg_stack.owner_libpq, run_id) == 1  # no duplicate action row
    ea = _ea(pg_stack.owner_libpq, run_id)
    assert ea["status"] == "pending"
    assert ea["attempts"] == 1  # claimed once, never double-incremented
    assert ea["lease_token"] is not None


def test_lease_overrun_boundary_prevents_second_transmission(
    pg_stack: SimpleNamespace,
) -> None:
    """The durable transmission boundary fences a lease overrun (ADR-013 fix).

    A DB lease cannot fence an external receiver by itself, so the correction adds
    a durable boundary committed under the lease BEFORE transmission. If worker A
    crosses it and is then paused past lease expiry, worker B must NOT reclaim and
    re-transmit: the action is transmission-started, so B recovers it as terminal
    UNKNOWN. We demonstrate:

    - only ONE external transmission occurs (B is fenced, not a second send);
    - a stale worker cannot re-cross the boundary (its lease no longer matches);
    - A's late, stale-lease finalize is a CAS noop; the terminal UNKNOWN stands;
    - DB state stays consistent (exactly one action row, no corruption).

    This is the conservative trade-off the correction accepts: A's send may have
    succeeded, but because it could not be confirmed before the lease expired the
    outcome is UNKNOWN rather than a risked duplicate.
    """
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = Sink()
    store = EnvironmentSecretStore({})

    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)

    # Worker A claims (attempt 1, lease L_A, key K) and crosses the boundary.
    claim_a = execute_advancement(sm, run_id, store)
    assert claim_a.action_task is not None
    task_a = claim_a.action_task
    assert mark_transmission_started(sm, task_a, set_worker_context_default)
    result_a = run_action(task_a, transport=sink.transport())  # A transmits ONCE
    assert len(sink.calls) == 1

    # A is paused past its lease expiry before it can finalize.
    _expire_lease(pg_stack.owner_libpq, run_id)

    # Worker B tries to reclaim: the action is transmission-started, so B is fenced
    # to terminal UNKNOWN -> NO second claim, NO second transmission.
    out_b = execute_advancement(sm, run_id, store)
    assert out_b.action_task is None
    assert len(sink.calls) == 1  # B did not transmit
    ea = _ea(pg_stack.owner_libpq, run_id)
    assert ea["status"] == "unknown"

    # A stale worker cannot re-cross the boundary (lease no longer matches).
    assert mark_transmission_started(sm, task_a, set_worker_context_default) is False

    # A's late, stale-lease finalize is a CAS noop; the terminal UNKNOWN stands.
    final_a = finalize_action(sm, task_a, result_a, set_worker_context_default)
    assert final_a.result == "noop"
    assert _count_ea(pg_stack.owner_libpq, run_id) == 1
    assert _ea(pg_stack.owner_libpq, run_id)["status"] == "unknown"
    assert _step(pg_stack.owner_libpq, run_id)[0] == "FAILED"
    assert _row_run_status(pg_stack.owner_libpq, run_id) == "FAILED"


def _row_run_status(owner_libpq: str, run_id: uuid.UUID) -> str:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute("SELECT status FROM workflow_runs WHERE id=%s", (run_id,)).fetchone()
    assert row is not None
    return str(row[0])


def test_connector_swapped_after_approval_requires_reapproval(pg_stack: SimpleNamespace) -> None:
    """A payload is approved against a specific connector IDENTITY. If the
    connector is recreated (same name, new id, possibly a new destination) after
    approval, the worker must NOT silently redirect the side effect — it fails the
    step deterministically (re-approval required) and delivers nothing."""
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = Sink()
    store = EnvironmentSecretStore({})

    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)

    # Recreate the "hook" connector with a NEW id and a DIFFERENT destination,
    # exactly as a post-approval edit-by-delete-recreate would.
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute("DELETE FROM connectors WHERE tenant_id=%s AND name='hook'", (m.tenant_id,))
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id, url="https://attacker.example/steal")

    out = execute_advancement(sm, run_id, store)
    assert out.result == "failed"
    assert len(sink.calls) == 0  # nothing delivered to the swapped destination
    assert _step(pg_stack.owner_libpq, run_id)[0] == "FAILED"
    # No external_actions row was created against the new connector.
    assert _count_ea(pg_stack.owner_libpq, run_id) == 0


# --- Adversarial concurrency: late first worker vs replacement worker ----------------
#
# The sequential overrun test above proves the state-machine ORDER. These two prove
# the race with REAL concurrency: two workers, two DB connections, one in-flight
# send, and a genuinely racing finalize/resume pair. In every interleaving at most
# ONE transmission occurs and the durable outcome is one of exactly two consistent
# states (finalized SUCCESS, or terminal UNKNOWN with the late finalize a no-op).


def test_late_first_worker_and_replacement_worker_never_both_transmit_concurrently(
    pg_stack: SimpleNamespace,
) -> None:
    """Worker A crosses the boundary and is IN THE MIDDLE of a slow send (blocked
    inside the transport) when its lease expires and replacement worker B resumes
    the run concurrently. B must be fenced to terminal UNKNOWN without a second
    claim or transmission; A's send completes exactly once and its late finalize
    is a CAS no-op against the token B cleared."""
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    store = EnvironmentSecretStore({})
    sink = Sink()

    process_advance(_worker_sm(pg_stack), run_id, _noop_enqueue, store, _runner(sink))  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)

    in_send = threading.Event()
    release = threading.Event()

    class _SlowReceiver(httpx.BaseTransport):
        """The request has left the worker (bytes written) and the receiver is slow
        to respond: A is parked here past its lease expiry."""

        def handle_request(self, request: httpx.Request) -> httpx.Response:
            in_send.set()
            assert release.wait(timeout=30), "test harness never released the slow send"
            resp: httpx.Response = sink.handler(request)
            return resp

    results: dict[str, object] = {}

    def worker_a() -> None:
        sm_a = _worker_sm(pg_stack)
        claim = execute_advancement(sm_a, run_id, store)
        assert claim.action_task is not None
        results["crossed"] = mark_transmission_started(
            sm_a, claim.action_task, set_worker_context_default
        )
        res = run_action(claim.action_task, transport=_SlowReceiver())
        results["final"] = finalize_action(sm_a, claim.action_task, res, set_worker_context_default)

    a = threading.Thread(target=worker_a)
    a.start()
    assert in_send.wait(timeout=30), "worker A never reached the send"

    # A's send is in flight on another thread/connection. Its lease overruns.
    _expire_lease(pg_stack.owner_libpq, run_id)

    # Replacement worker B resumes CONCURRENTLY with A's in-flight transmission.
    out_b = execute_advancement(_worker_sm(pg_stack), run_id, store)
    assert out_b.action_task is None, "B must never obtain a second claim"
    assert out_b.result == "failed"  # fenced to terminal UNKNOWN
    assert _ea(pg_stack.owner_libpq, run_id)["status"] == "unknown"
    assert len(sink.calls) == 0  # B did not transmit; A's send is still blocked

    # Now A's receiver responds; A finalizes late with a stale token.
    release.set()
    a.join(timeout=60)
    assert not a.is_alive(), "worker A did not finish"
    assert results["crossed"] is True
    final = results["final"]
    assert getattr(final, "result", None) == "noop"  # stale-lease finalize is a CAS no-op

    # Exactly one transmission, one action row, terminal UNKNOWN, run FAILED.
    assert len(sink.calls) == 1
    assert _count_ea(pg_stack.owner_libpq, run_id) == 1
    assert _ea(pg_stack.owner_libpq, run_id)["status"] == "unknown"
    assert _step(pg_stack.owner_libpq, run_id)[0] == "FAILED"
    assert _row_run_status(pg_stack.owner_libpq, run_id) == "FAILED"


def _race_finalize_against_replacement(
    pg_stack: SimpleNamespace, m: SimpleNamespace, store: EnvironmentSecretStore
) -> tuple[str, str, str]:
    """One racing iteration: A transmits once with an expired lease; A's finalize
    and B's resume start from a barrier on separate connections. Returns the
    observed (action status, A result, B result) after asserting the invariants
    that hold in EVERY interleaving."""
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sink = Sink()
    process_advance(_worker_sm(pg_stack), run_id, _noop_enqueue, store, _runner(sink))
    _approve(pg_stack.owner_libpq, run_id, m.user_id)

    sm_a = _worker_sm(pg_stack)
    claim = execute_advancement(sm_a, run_id, store)
    assert claim.action_task is not None
    task = claim.action_task
    assert mark_transmission_started(sm_a, task, set_worker_context_default)
    res = run_action(task, transport=sink.transport())  # ONE real transmission
    assert len(sink.calls) == 1
    _expire_lease(pg_stack.owner_libpq, run_id)

    barrier = threading.Barrier(2)
    out: dict[str, object] = {}

    def finalize_late() -> None:
        barrier.wait()
        out["a"] = finalize_action(sm_a, task, res, set_worker_context_default)

    def replacement_resume() -> None:
        barrier.wait()
        out["b"] = execute_advancement(_worker_sm(pg_stack), run_id, store)

    threads = [threading.Thread(target=finalize_late), threading.Thread(target=replacement_resume)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=60)
        assert not th.is_alive()

    a_result = str(getattr(out["a"], "result", ""))
    b_result = str(getattr(out["b"], "result", ""))
    ea = _ea(pg_stack.owner_libpq, run_id)
    outcome = (str(ea["status"]), a_result, b_result)
    assert outcome in {
        ("success", "advanced", "completed"),
        ("unknown", "noop", "failed"),
    }, f"inconsistent race outcome: {outcome}"
    # Never a second transmission, never a second action row, never a claim by B.
    assert len(sink.calls) == 1
    assert _count_ea(pg_stack.owner_libpq, run_id) == 1
    assert getattr(out["b"], "action_task", None) is None
    step_status = _step(pg_stack.owner_libpq, run_id)[0]
    run_status = _row_run_status(pg_stack.owner_libpq, run_id)
    if outcome[0] == "success":
        assert (step_status, run_status) == ("SUCCESS", "COMPLETED")
    else:
        assert (step_status, run_status) == ("FAILED", "FAILED")
    return outcome


def test_finalize_and_replacement_resume_race_is_consistent_and_never_double_sends(
    pg_stack: SimpleNamespace,
) -> None:
    """A has transmitted ONCE (boundary crossed, response received) but its lease
    has expired before finalize. A's finalize and B's resume start from a barrier
    on separate connections. Whichever wins, the durable state is one of exactly
    two consistent outcomes and the receiver is never contacted a second time:

      - A wins: action SUCCESS, step SUCCESS, B observes the finalized step and
        completes the run (no claim, no send);
      - B wins: action terminal UNKNOWN, run FAILED, A's finalize is a CAS no-op.

    Which side wins is scheduler-dependent; the assertion is that EVERY observed
    interleaving is one of the two consistent states.
    """
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    store = EnvironmentSecretStore({})
    seen = {_race_finalize_against_replacement(pg_stack, m, store) for _ in range(6)}
    assert seen
