"""last_progress_at semantics (M11.5 P1D, part C).

last_progress_at is stamped (server time) ONLY on genuine execution-state
advancement — never on a replay/no-op, a scan, or a stale-CAS finalize.
"""

import uuid
from datetime import datetime
from types import SimpleNamespace

import psycopg
import pytest
from test_action_execution import (  # sibling module (pytest prepend import mode)
    Sink,
    _approve,
    _expire_lease,
    _noop_enqueue,
    _runner,
    _seed_run,
    _seed_webhook,
    _webhook_plan,
    _worker_sm,
)

from nlw.engine.actions import finalize_action, run_action
from nlw.engine.execution import execute_advancement, process_advance
from nlw.secrets.store import EnvironmentSecretStore
from nlw.tenancy.session import set_worker_context_default

pytestmark = pytest.mark.integration


def _progress(owner_libpq: str, run_id: uuid.UUID) -> datetime | None:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute(
            "SELECT last_progress_at FROM workflow_runs WHERE id=%s", (run_id,)
        ).fetchone()
    assert row is not None
    return row[0]  # type: ignore[no-any-return]


def test_real_transitions_update_progress_and_replay_does_not(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = Sink()
    store = EnvironmentSecretStore({})

    assert _progress(pg_stack.owner_libpq, run_id) is None  # nothing has executed yet

    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))  # park for approval
    after_park = _progress(pg_stack.owner_libpq, run_id)
    assert after_park is not None  # a genuine transition stamped progress

    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    for _ in range(6):
        out = process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))
        if out.result in ("completed", "failed", "noop"):
            break
    after_complete = _progress(pg_stack.owner_libpq, run_id)
    assert after_complete is not None and after_complete >= after_park  # advanced further

    # A replay of a terminal run is a no-op and must NOT refresh progress.
    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))
    assert _progress(pg_stack.owner_libpq, run_id) == after_complete


def test_stale_cas_finalize_does_not_manufacture_progress(pg_stack: SimpleNamespace) -> None:
    """Req 14: a finalize by a worker whose lease was already reclaimed is a CAS
    no-op and must NOT stamp progress."""
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = Sink()
    store = EnvironmentSecretStore({})

    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)

    # Worker A claims (attempt 1). Then A is held past expiry and worker B reclaims.
    claim_a = execute_advancement(sm, run_id, store)
    assert claim_a.action_task is not None
    task_a = claim_a.action_task
    _expire_lease(pg_stack.owner_libpq, run_id)
    claim_b = execute_advancement(sm, run_id, store)  # B reclaims -> stamps progress
    assert claim_b.action_task is not None
    progress_after_b = _progress(pg_stack.owner_libpq, run_id)

    # A finalizes with its STALE lease -> CAS no-op; progress must be unchanged.
    result_a = run_action(task_a, transport=sink.transport())
    outcome = finalize_action(sm, task_a, result_a, set_worker_context_default)
    assert outcome.result == "noop"
    assert _progress(pg_stack.owner_libpq, run_id) == progress_after_b  # no false progress


def test_progress_is_tenant_scoped(pg_stack: SimpleNamespace) -> None:
    """Progress on one tenant's run never touches another tenant's run."""
    a = pg_stack.seed_member()
    b = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, a.tenant_id)
    run_a = _seed_run(pg_stack, a.user_id, a.tenant_id, _webhook_plan())
    _seed_webhook(pg_stack.owner_libpq, b.tenant_id)
    run_b = _seed_run(pg_stack, b.user_id, b.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    store = EnvironmentSecretStore({})

    process_advance(sm, run_a, _noop_enqueue, store, _runner(Sink()))  # advance A only

    assert _progress(pg_stack.owner_libpq, run_a) is not None
    assert _progress(pg_stack.owner_libpq, run_b) is None  # B untouched
