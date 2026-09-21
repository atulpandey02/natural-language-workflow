"""Approval-instance binding review (M11.5 P1D correction).

The reconciler and the worker both bind a decided approval by ``(run_id,
step_id)``. This suite PROVES that binding is exact and unambiguous because the
database enforces AT MOST ONE approval row per ``(run_id, step_id)`` — so a
"historical decided + current pending" pair for the SAME step cannot coexist, and
no old approval can ever satisfy a newer waiting generation.

These use real database rows and the real engine state-machine paths, not mocks.
"""

import uuid
from types import SimpleNamespace

import psycopg
import pytest
from test_action_execution import (  # sibling module (pytest prepend import mode)
    Sink,
    _approve,
    _noop_enqueue,
    _row,
    _runner,
    _seed_run,
    _seed_webhook,
    _step,
    _webhook_plan,
    _worker_sm,
)

from nlw.engine.execution import execute_advancement, process_advance
from nlw.secrets.store import EnvironmentSecretStore

pytestmark = pytest.mark.integration

_STEP = "notify"  # the webhook plan's single approval-gated step


def _park(pg_stack: SimpleNamespace):  # type: ignore[no-untyped-def]
    """Seed a webhook run and park it at WAITING_APPROVAL (one pending approval)."""
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = Sink()
    store = EnvironmentSecretStore({})
    out = process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))
    assert out.result == "waiting"
    return m, run_id, sm, sink, store


def _approval_count(owner_libpq: str, run_id: uuid.UUID) -> int:
    row = _row(
        owner_libpq,
        "SELECT count(*) FROM approvals WHERE run_id=%s AND step_id=%s",
        (run_id, _STEP),
    )
    assert row is not None
    return int(row[0])


def test_at_most_one_approval_row_per_run_step(pg_stack: SimpleNamespace) -> None:
    """The DB uniqueness invariant `uq_approval_run_step (run_id, step_id)` makes a
    second (historical/current) approval row for the SAME step impossible — the
    insert fails closed. This is the constraint, not an application convention."""
    m, run_id, *_ = _park(pg_stack)
    assert _approval_count(pg_stack.owner_libpq, run_id) == 1  # the current one

    # Attempt to inject a SECOND approval for the same (run_id, step_id) — e.g. a
    # historical APPROVED row alongside the current PENDING one. It is rejected.
    with (
        psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c,
        pytest.raises(psycopg.errors.UniqueViolation),
    ):
        c.execute(
            "INSERT INTO approvals (id, tenant_id, run_id, step_id, connector_id, connector_name, "
            "tool, status) VALUES (%s,%s,%s,%s,%s,'hook','webhook.send','approved')",
            (uuid.uuid4(), m.tenant_id, run_id, _STEP, uuid.uuid4()),
        )
    assert _approval_count(pg_stack.owner_libpq, run_id) == 1  # still exactly one


def test_pending_approval_blocks_then_advances_once_when_decided(
    pg_stack: SimpleNamespace,
) -> None:
    """The current PENDING approval keeps the step blocked; its decision advances
    the step exactly once (the single row IS the current generation)."""
    m, run_id, sm, sink, store = _park(pg_stack)

    # Still pending -> the worker does NOT advance and does NOT deliver.
    assert process_advance(sm, run_id, _noop_enqueue, store, _runner(sink)).result == "waiting"
    assert len(sink.calls) == 0

    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    for _ in range(6):
        out = process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))
        if out.result in ("completed", "failed", "noop"):
            break
    assert len(sink.calls) == 1  # delivered exactly once
    assert _step(pg_stack.owner_libpq, run_id)[0] == "SUCCESS"


def test_worker_does_not_consume_another_runs_approval(pg_stack: SimpleNamespace) -> None:
    """An approval is bound to its own (run_id, step_id): deciding another run's
    approval never advances this run's identically-named step."""
    m_a, run_a, sm, sink_a, store = _park(pg_stack)
    m_b, run_b, _sm_b, _sink_b, _store_b = _park(pg_stack)

    # Approve ONLY run B's approval (same step_id 'notify', different run_id).
    _approve(pg_stack.owner_libpq, run_b, m_b.user_id)

    # Run A must remain blocked — B's decided approval is a different row.
    assert process_advance(sm, run_a, _noop_enqueue, store, _runner(sink_a)).result == "waiting"
    assert len(sink_a.calls) == 0
    assert _step(pg_stack.owner_libpq, run_a)[0] == "WAITING_APPROVAL"


def test_connector_change_fails_run_without_creating_a_second_approval(
    pg_stack: SimpleNamespace,
) -> None:
    """P1C re-approval-after-connector-change fails the CURRENT run (it does not
    re-materialize a second approval for the same (run_id, step_id)); re-approval
    means a NEW run with its OWN newly materialized approval."""
    m, run_id, sm, sink, store = _park(pg_stack)
    _approve(pg_stack.owner_libpq, run_id, m.user_id)

    # Swap the 'hook' connector for a new identity (id) after approval.
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute("DELETE FROM connectors WHERE tenant_id=%s AND name='hook'", (m.tenant_id,))
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id, url="https://other.example/hook")

    out = execute_advancement(sm, run_id, store)
    assert out.result == "failed"  # deterministic re-approval-required failure
    assert len(sink.calls) == 0  # nothing delivered
    # No second approval was created for the same (run_id, step_id).
    assert _approval_count(pg_stack.owner_libpq, run_id) == 1
    run_row = _row(pg_stack.owner_libpq, "SELECT status FROM workflow_runs WHERE id=%s", (run_id,))
    assert run_row is not None and run_row[0] == "FAILED"


def test_concurrent_advance_of_approved_step_advances_once(pg_stack: SimpleNamespace) -> None:
    """Two workers advancing the same approved WAITING_APPROVAL run consume the
    single approval once: exactly one claims the action, the other does not."""
    import threading

    m, run_id, _sm, _sink, store = _park(pg_stack)
    _approve(pg_stack.owner_libpq, run_id, m.user_id)

    sms = [_worker_sm(pg_stack) for _ in range(2)]
    barrier = threading.Barrier(2)
    results: list[object] = [None, None]

    def racer(i: int) -> None:
        barrier.wait()
        results[i] = execute_advancement(sms[i], run_id, store)

    threads = [threading.Thread(target=racer, args=(i,)) for i in range(2)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    claimed = [r for r in results if getattr(r, "action_task", None) is not None]
    assert len(claimed) == 1  # the approval/step is consumed exactly once
    # Exactly one external_actions row was created for the step.
    row = _row(
        pg_stack.owner_libpq, "SELECT count(*) FROM external_actions WHERE run_id=%s", (run_id,)
    )
    assert row is not None and int(row[0]) == 1
