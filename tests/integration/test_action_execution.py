"""Two-phase action execution: approval, delivery, crash windows, lease, retry,
secret non-leak (M7). Drives the durable engine with an injected mock transport
so no real network is used; the SSRF guard is exercised separately (unit).
"""

import json
import uuid
from collections.abc import Callable
from types import SimpleNamespace

import httpx
import psycopg
import pytest
import structlog
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.domain.workflow import WorkflowPlan
from nlw.engine.actions import ActionExecResult, ActionTask, run_action
from nlw.engine.execution import execute_advancement, process_advance
from nlw.engine.runs import create_run, create_workflow_with_version
from nlw.secrets.store import EnvironmentSecretStore, SecretStore, env_key_for

pytestmark = pytest.mark.integration

ActionRunner = Callable[[ActionTask], ActionExecResult]


def _noop_enqueue(rid: uuid.UUID, delay: float | None = None) -> None:
    return None


class Sink:
    """A mock webhook receiver; counts deliveries and returns scripted responses."""

    def __init__(self) -> None:
        self.calls: list[httpx.Request] = []
        self.responses: list[httpx.Response] = []
        self.default = httpx.Response(200, headers={"X-Request-Id": "req-1"})

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        idx = len(self.calls) - 1
        return self.responses[idx] if idx < len(self.responses) else self.default

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


def _runner(sink: Sink) -> ActionRunner:
    def run(task: ActionTask) -> ActionExecResult:
        return run_action(task, transport=sink.transport())

    return run


def _seed_webhook(
    owner_libpq: str,
    tenant_id: uuid.UUID,
    *,
    name: str = "hook",
    url: str = "https://sink.example/hook",
    secret_ref: str | None = None,
    with_auth: bool = False,
    status: str = "active",
) -> uuid.UUID:
    cid = uuid.uuid4()
    config: dict[str, object] = {"url": url}
    if with_auth:
        config.update({"auth_header_name": "Authorization", "auth_scheme": "Bearer"})
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO connectors (id, tenant_id, type, name, config, secret_ref, status) "
            "VALUES (%s,%s,'webhook',%s,%s::jsonb,%s,%s)",
            (cid, tenant_id, name, json.dumps(config), secret_ref, status),
        )
    return cid


def _seed_run(
    pg_stack: SimpleNamespace, user_id: uuid.UUID, tenant_id: uuid.UUID, plan: WorkflowPlan
) -> uuid.UUID:
    engine = create_sync_engine(pg_stack.settings)
    try:
        sm = create_sync_sessionmaker(engine)
        with sm() as s, s.begin():
            s.execute(text("SELECT set_config('app.user_id', :u, true)"), {"u": str(user_id)})
            s.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)})
            wf, ver = create_workflow_with_version(s, tenant_id, "wf", plan)
            run = create_run(s, tenant_id, wf.id, ver.id)
            return run.id
    finally:
        engine.dispose()


def _worker_sm(pg_stack: SimpleNamespace) -> sessionmaker[Session]:
    return create_sync_sessionmaker(create_sync_engine(pg_stack.worker_settings))


def _webhook_plan(sql_step: bool = False) -> WorkflowPlan:
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


def _approve(
    owner_libpq: str, run_id: uuid.UUID, decided_by: uuid.UUID, decision: str = "approved"
) -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "UPDATE approvals SET status=%s, decided_by=%s, decided_at=now() WHERE run_id=%s",
            (decision, decided_by, run_id),
        )


def _row(owner_libpq: str, sql: str, params: tuple[object, ...]) -> tuple[object, ...] | None:
    with psycopg.connect(owner_libpq) as c:
        return c.execute(sql, params).fetchone()


def _step(owner_libpq: str, run_id: uuid.UUID) -> tuple[object, ...]:
    row = _row(owner_libpq, "SELECT status, output FROM step_runs WHERE run_id=%s", (run_id,))
    assert row is not None
    return row


def _ea(owner_libpq: str, run_id: uuid.UUID) -> dict[str, object]:
    with psycopg.connect(owner_libpq) as c:
        c.row_factory = psycopg.rows.dict_row  # type: ignore[assignment]
        row = c.execute("SELECT * FROM external_actions WHERE run_id=%s", (run_id,)).fetchone()
    return dict(row) if row else {}


def _expire_lease(owner_libpq: str, run_id: uuid.UUID) -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "UPDATE external_actions SET lease_expires_at = now() - interval '1 second' "
            "WHERE run_id=%s",
            (run_id,),
        )


def _drive(
    sm: sessionmaker[Session],
    run_id: uuid.UUID,
    runner: ActionRunner,
    store: SecretStore,
    n: int = 6,
) -> list[str]:
    results: list[str] = []
    enq: list[tuple[uuid.UUID, float | None]] = []

    def enqueue(rid: uuid.UUID, delay: float | None = None) -> None:
        enq.append((rid, delay))

    for _ in range(n):
        out = process_advance(sm, run_id, enqueue, store, runner)
        results.append(str(out.result))
        if out.result in ("completed", "failed", "waiting", "noop"):
            break
    return results


# --- Happy path + reject ---


def test_approval_park_then_approve_delivers(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = Sink()
    store = EnvironmentSecretStore({})

    # First advance parks for approval; no delivery.
    out = process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))
    assert out.result == "waiting"
    assert len(sink.calls) == 0
    assert _step(pg_stack.owner_libpq, run_id)[0] == "WAITING_APPROVAL"
    appr = _row(pg_stack.owner_libpq, "SELECT status FROM approvals WHERE run_id=%s", (run_id,))
    assert appr is not None and appr[0] == "pending"

    # Approve, then resume -> delivers exactly once, step SUCCESS, run COMPLETED.
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    _drive(sm, run_id, _runner(sink), store)
    assert len(sink.calls) == 1
    step_status, output = _step(pg_stack.owner_libpq, run_id)
    assert step_status == "SUCCESS"
    assert output == {"http_status": 200}
    ea = _ea(pg_stack.owner_libpq, run_id)
    assert ea["status"] == "success" and ea["provider_request_id"] == "req-1"
    assert ea["attempts"] == 1
    run_row = _row(pg_stack.owner_libpq, "SELECT status FROM workflow_runs WHERE id=%s", (run_id,))
    assert run_row is not None and run_row[0] == "COMPLETED"


def test_reject_fails_run_without_delivery(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = Sink()
    store = EnvironmentSecretStore({})

    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id, decision="rejected")
    out = process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))
    assert out.result == "failed"
    assert len(sink.calls) == 0
    assert _step(pg_stack.owner_libpq, run_id)[0] == "FAILED"


# --- Crash windows ---


def test_w1_crash_before_send_delivers_once_after_lease_expiry(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = Sink()
    store = EnvironmentSecretStore({})

    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    # Claim only (Txn1) then "crash" before send: never call run_action/finalize.
    claim = execute_advancement(sm, run_id, store)
    assert claim.action_task is not None
    assert len(sink.calls) == 0

    # A redelivery BEFORE lease expiry must DEFER (live lease), not re-execute.
    deferred = execute_advancement(sm, run_id, store)
    assert deferred.result == "deferred"

    # After lease expiry, resume delivers exactly once.
    _expire_lease(pg_stack.owner_libpq, run_id)
    _drive(sm, run_id, _runner(sink), store)
    assert len(sink.calls) == 1
    assert _step(pg_stack.owner_libpq, run_id)[0] == "SUCCESS"


def test_w2_crash_after_send_redelivers_at_least_once(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = Sink()
    store = EnvironmentSecretStore({})

    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    # Claim + send, but "crash" before finalize (do not call finalize_action).
    claim = execute_advancement(sm, run_id, store)
    assert claim.action_task is not None
    run_action(claim.action_task, transport=sink.transport())
    assert len(sink.calls) == 1  # delivered once
    key_first = str(claim.action_task.external_action_key)

    # Lease still live -> redelivery defers (no premature duplicate).
    assert execute_advancement(sm, run_id, store).result == "deferred"

    # Simulate the original worker's death; a resume re-attempts with the SAME
    # idempotency key -> AT-LEAST-ONCE: the sink sees a second delivery.
    _expire_lease(pg_stack.owner_libpq, run_id)
    _drive(sm, run_id, _runner(sink), store)
    assert len(sink.calls) == 2  # duplicate window demonstrated
    assert sink.calls[1].headers["Idempotency-Key"] == key_first  # stable key reused
    assert _step(pg_stack.owner_libpq, run_id)[0] == "SUCCESS"


def test_w3_replay_after_finalize_is_noop(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = Sink()
    store = EnvironmentSecretStore({})

    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    _drive(sm, run_id, _runner(sink), store)  # deliver + complete
    assert len(sink.calls) == 1
    # Replays after terminal state do nothing.
    out = process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))
    assert out.result == "noop"
    assert len(sink.calls) == 1


# --- Retry + attempt cap ---


def test_retryable_5xx_schedules_backoff_and_gates_early_redelivery(
    pg_stack: SimpleNamespace,
) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    store = EnvironmentSecretStore({})
    sink = Sink()
    sink.responses = [httpx.Response(503)]  # first attempt fails transiently

    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    out = process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))
    assert out.result == "retry"
    ea = _ea(pg_stack.owner_libpq, run_id)
    assert ea["status"] == "pending" and ea["next_attempt_at"] is not None
    assert ea["error_class"] == "retryable"
    assert _step(pg_stack.owner_libpq, run_id)[0] == "RUNNING"  # still in-flight

    # An early redelivery before next_attempt_at must NOT execute the action.
    assert execute_advancement(sm, run_id, store).result == "deferred"
    assert len(sink.calls) == 1


def test_attempt_cap_fails_run(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    store = EnvironmentSecretStore({})
    sink = Sink()
    sink.responses = [httpx.Response(503) for _ in range(10)]  # always transient

    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    # Repeatedly attempt: clear the retry gate each time by expiring lease + due.
    result = "retry"
    for _ in range(8):
        out = process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))
        result = out.result
        if result == "failed":
            break
        with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
            c.execute(
                "UPDATE external_actions SET next_attempt_at = now() - interval '1 second', "
                "lease_expires_at = now() - interval '1 second' WHERE run_id=%s",
                (run_id,),
            )
    assert result == "failed"
    assert _ea(pg_stack.owner_libpq, run_id)["status"] == "failed"
    assert _step(pg_stack.owner_libpq, run_id)[0] == "FAILED"


# --- Secret non-leak ---


def test_webhook_secret_never_persisted(pg_stack: SimpleNamespace) -> None:
    secret_value = "SUPER-SECRET-WEBHOOK-TOKEN"
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id, secret_ref="WEBHOOK_AUTH", with_auth=True)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    store = EnvironmentSecretStore({env_key_for(m.tenant_id, "WEBHOOK_AUTH"): secret_value})
    sink = Sink()

    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    with structlog.testing.capture_logs() as logs:
        _drive(sm, run_id, _runner(sink), store)

    # The destination legitimately received the auth header...
    assert sink.calls[0].headers["Authorization"] == f"Bearer {secret_value}"
    # ...but the secret is absent from every persisted / logged surface.
    with psycopg.connect(pg_stack.owner_libpq) as c:
        ea_dump = str(
            c.execute(
                "SELECT to_jsonb(e) FROM external_actions e WHERE run_id=%s", (run_id,)
            ).fetchone()
        )
        step_dump = str(
            c.execute(
                "SELECT input, output, error FROM step_runs WHERE run_id=%s", (run_id,)
            ).fetchall()
        )
    for surface in (ea_dump, step_dump, json.dumps(logs, default=str)):
        assert secret_value not in surface
