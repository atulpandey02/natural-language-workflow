"""Lease/attempt-ordering safety for external actions (M11.5 P1C).

A live lease is authoritative before attempt-cap evaluation: a duplicate worker
must never fail or steal a legitimate live final attempt.
"""

import threading
import uuid
from types import SimpleNamespace

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

from nlw.engine.actions import effective_attempt_cap, finalize_action, run_action
from nlw.engine.execution import execute_advancement, process_advance
from nlw.secrets.store import EnvironmentSecretStore
from nlw.tenancy.session import set_current_tenant_sync

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
    final_a = finalize_action(sm, task_a, result_a, set_current_tenant_sync)

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


def test_lease_overrun_two_transmissions_possible_without_state_corruption(
    pg_stack: SimpleNamespace,
) -> None:
    """A database lease CANNOT fence an external receiver (P1C, honest boundary).

    If worker A is paused/suspended past its lease expiry at a point where its send
    may still occur, worker B can reclaim the SAME action (same stable idempotency
    key, fresh lease token) and also send. We demonstrate:

    - the reclaim does NOT manufacture a second idempotency key;
    - BOTH workers can transmit -> two external observations are possible when the
      receiver ignores the key (the DB lease does not prevent this);
    - finalization stays CAS-safe: a stale-lease finalize is a noop, the current
      lease owner wins, and DB state (one success, run COMPLETED, one action row)
      is never corrupted regardless of finalize order.
    """
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = Sink()
    store = EnvironmentSecretStore({})

    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)

    # Worker A claims (attempt 1, lease L_A, key K) and is then held past expiry.
    claim_a = execute_advancement(sm, run_id, store)
    assert claim_a.action_task is not None
    task_a = claim_a.action_task
    _expire_lease(pg_stack.owner_libpq, run_id)

    # Worker B reclaims the expired action: SAME key, fresh lease, attempt 2.
    claim_b = execute_advancement(sm, run_id, store)
    assert claim_b.action_task is not None
    task_b = claim_b.action_task
    assert task_b.external_action_key == task_a.external_action_key  # NO new key
    assert task_b.lease_token != task_a.lease_token  # fresh lease token
    assert task_b.attempt == task_a.attempt + 1  # the reclaim advanced attempts

    # A DB lease does not fence the receiver: BOTH A and B transmit, same key.
    result_a = run_action(task_a, transport=sink.transport())
    result_b = run_action(task_b, transport=sink.transport())
    assert len(sink.calls) == 2  # two external observations occurred
    key = str(task_a.external_action_key)
    assert sink.calls[0].headers["Idempotency-Key"] == key
    assert sink.calls[1].headers["Idempotency-Key"] == key  # identical -> only receiver dedup helps

    # A's STALE-lease finalize arrives first -> CAS rejects it (noop), no corruption.
    final_a = finalize_action(sm, task_a, result_a, set_current_tenant_sync)
    assert final_a.result == "noop"
    # B (the current lease owner) finalizes -> success.
    final_b = finalize_action(sm, task_b, result_b, set_current_tenant_sync)
    assert final_b.result == "advanced"

    # State is consistent: exactly one action row and a recorded success.
    assert _count_ea(pg_stack.owner_libpq, run_id) == 1
    ea = _ea(pg_stack.owner_libpq, run_id)
    assert ea["status"] == "success"
    assert _step(pg_stack.owner_libpq, run_id)[0] == "SUCCESS"

    # A follow-up advance completes the run cleanly (the SUCCESS step is durable);
    # no third transmission occurs.
    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))
    assert _row_run_status(pg_stack.owner_libpq, run_id) == "COMPLETED"
    assert len(sink.calls) == 2  # no additional external send


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
