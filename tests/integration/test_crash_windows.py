"""M11 crash-window honesty: at-least-once delivery framed by receiver semantics.

Generic delivery is AT-LEAST-ONCE (ADR-013). The engine guarantees a stable
external_action_key reused across redelivery and durable recovery — it does NOT
guarantee exactly-once side effects. These tests make that explicit two ways:

A) idempotency-aware receiver dedupes on the Idempotency-Key -> ONE business effect
B) non-idempotent receiver -> a duplicate is possible; only the stable key +
   durable recovery are asserted (no exactly-once claim).

The other historical windows (M3 commit->enqueue, M7 W1/W2/W3, M8 orphan recovery,
M10 Run-Now enqueue failure) are covered in test_engine_execution.py,
test_action_execution.py, test_scheduler_reconcile.py, and test_workflows_api.py.
"""

import uuid
from collections.abc import Callable
from types import SimpleNamespace

import httpx
import psycopg
import pytest
from sqlalchemy.orm import Session, sessionmaker

from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.domain.workflow import WorkflowPlan
from nlw.engine.actions import ActionExecResult, ActionTask, run_action
from nlw.engine.execution import execute_advancement, process_advance
from nlw.engine.runs import create_run, create_workflow_with_version
from nlw.secrets.store import EnvironmentSecretStore
from nlw.tenancy.session import apply_signed_context_sync
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

ActionRunner = Callable[[ActionTask], ActionExecResult]


class DedupeSink:
    """Webhook receiver that dedupes on the Idempotency-Key header."""

    def __init__(self) -> None:
        self.calls = 0
        self.seen_keys: set[str] = set()

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self.seen_keys.add(request.headers.get("Idempotency-Key", ""))
        return httpx.Response(200)

    @property
    def effects(self) -> int:
        return len(self.seen_keys)  # one business effect per unique key

    def runner(self) -> ActionRunner:
        return lambda task: run_action(task, transport=httpx.MockTransport(self.handler))


class CountingSink:
    """Non-idempotent receiver: every delivery is a separate business effect."""

    def __init__(self) -> None:
        self.effects = 0
        self.keys: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.effects += 1
        self.keys.append(request.headers.get("Idempotency-Key", ""))
        return httpx.Response(200)

    def runner(self) -> ActionRunner:
        return lambda task: run_action(task, transport=httpx.MockTransport(self.handler))


def _worker_sm(pg_stack: SimpleNamespace) -> sessionmaker[Session]:
    return create_sync_sessionmaker(create_sync_engine(pg_stack.worker_settings))


def _seed_webhook(owner_libpq: str, tenant_id: uuid.UUID) -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO connectors (id, tenant_id, type, name, config, status) "
            "VALUES (%s,%s,'webhook','hook','{\"url\":\"https://sink.example/hook\"}'::jsonb,"
            "'active')",
            (uuid.uuid4(), tenant_id),
        )


def _webhook_plan() -> WorkflowPlan:
    return WorkflowPlan.model_validate(
        {
            "steps": [
                {
                    "id": "notify",
                    "tool": "webhook.send",
                    "args": {"payload": {"hello": "world"}},
                    "connector": "hook",
                }
            ]
        }
    )


def _seed_run(pg_stack: SimpleNamespace, user_id: uuid.UUID, tenant_id: uuid.UUID) -> uuid.UUID:
    engine = create_sync_engine(pg_stack.settings)
    try:
        sm = create_sync_sessionmaker(engine)
        with sm() as s, s.begin():
            apply_signed_context_sync(
                s, pg_stack.sign(Purpose.API_REQUEST, user_id=user_id, tenant_id=tenant_id)
            )
            wf, ver = create_workflow_with_version(s, tenant_id, "wf", _webhook_plan())
            run = create_run(s, tenant_id, wf.id, ver.id)
            return run.id
    finally:
        engine.dispose()


def _approve(owner_libpq: str, run_id: uuid.UUID, by: uuid.UUID) -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "UPDATE approvals SET status='approved', decided_by=%s, decided_at=now() "
            "WHERE run_id=%s",
            (by, run_id),
        )


def _expire_lease(owner_libpq: str, run_id: uuid.UUID) -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "UPDATE external_actions SET lease_expires_at = now() - interval '1 second' "
            "WHERE run_id=%s",
            (run_id,),
        )


def _step_status(owner_libpq: str, run_id: uuid.UUID) -> str:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute("SELECT status FROM step_runs WHERE run_id=%s", (run_id,)).fetchone()
    assert row is not None
    return str(row[0])


def _noop(_rid: uuid.UUID, _delay: float | None = None) -> None:
    return None


def _redeliver_after_crash_before_finalize(
    pg_stack: SimpleNamespace, run_id: uuid.UUID, runner: ActionRunner
) -> str:
    """W2 sequence: claim + send, crash before finalize, expire lease, resume."""
    store = EnvironmentSecretStore({})
    sm = _worker_sm(pg_stack)
    claim = execute_advancement(sm, run_id, store)
    assert claim.action_task is not None
    key = str(claim.action_task.external_action_key)
    runner(claim.action_task)  # external side effect happens; finalize NOT called (crash)
    _expire_lease(pg_stack.owner_libpq, run_id)  # original worker "died"
    # Resume drives to terminal (re-attempt reuses the same key -> at-least-once).
    for _ in range(6):
        out = process_advance(sm, run_id, _noop, store, runner)
        if out.result in ("completed", "failed", "noop"):
            break
    return key


def test_at_least_once_idempotent_receiver_one_effect(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id)
    sm = _worker_sm(pg_stack)
    sink = DedupeSink()

    process_advance(sm, run_id, _noop, EnvironmentSecretStore({}), sink.runner())  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    key = _redeliver_after_crash_before_finalize(pg_stack, run_id, sink.runner())

    assert sink.calls == 2  # delivered at least once, duplicated by the crash window
    assert sink.effects == 1  # idempotency-aware receiver deduped to ONE effect
    assert sink.seen_keys == {key}  # the SAME stable external_action_key both times
    assert _step_status(pg_stack.owner_libpq, run_id) == "SUCCESS"


def test_at_least_once_non_idempotent_receiver_duplicate_possible(
    pg_stack: SimpleNamespace,
) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id)
    sm = _worker_sm(pg_stack)
    sink = CountingSink()

    process_advance(sm, run_id, _noop, EnvironmentSecretStore({}), sink.runner())  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    key = _redeliver_after_crash_before_finalize(pg_stack, run_id, sink.runner())

    # A duplicate business effect is POSSIBLE here (no exactly-once claim). We only
    # assert the durable invariants: a stable correlation key + durable recovery.
    assert sink.effects >= 1
    assert all(k == key for k in sink.keys)  # stable key across every delivery
    assert _step_status(pg_stack.owner_libpq, run_id) == "SUCCESS"
