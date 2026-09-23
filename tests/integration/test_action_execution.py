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
from sqlalchemy.orm import Session, sessionmaker

from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.domain.workflow import WorkflowPlan
from nlw.engine.actions import (
    ACTION_OUTCOME_UNKNOWN,
    ActionExecResult,
    ActionTask,
    mark_transmission_started,
    run_action,
)
from nlw.engine.execution import execute_advancement, process_advance
from nlw.engine.runs import create_run, create_workflow_with_version
from nlw.secrets.store import EnvironmentSecretStore, SecretStore, env_key_for
from nlw.tenancy.session import apply_signed_context_sync, set_worker_context_default
from nlw.tenancy.signing import Purpose

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


def _connect_error_runner(sink: Sink) -> ActionRunner:
    """A runner whose send fails PROVABLY before transmission (connect refused) ->
    RETRY. Records each invocation on the sink so attempts can be counted."""

    class _Boom(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

    def run(task: ActionTask) -> ActionExecResult:
        sink.calls.append(httpx.Request("POST", "https://sink.example/hook"))
        return run_action(task, transport=_Boom())

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
            apply_signed_context_sync(
                s, pg_stack.sign(Purpose.API_REQUEST, user_id=user_id, tenant_id=tenant_id)
            )
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
    # The worker emitted exactly one append-only approval.requested audit event in
    # the SAME transaction as the park (no token/secret in it).
    audit = _row(
        pg_stack.owner_libpq,
        "SELECT count(*), max(event_type) FROM authz_audit_events "
        "WHERE subject_id=(SELECT id FROM approvals WHERE run_id=%s)",
        (run_id,),
    )
    assert audit is not None and audit[0] == 1 and audit[1] == "approval.requested"

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


def test_w2_crash_after_transmission_boundary_becomes_unknown(pg_stack: SimpleNamespace) -> None:
    # ADR-013 correction: once the durable transmission boundary is crossed, a
    # worker death is NOT redelivered (a stable key does not authorize replay for a
    # non-idempotent receiver) -> terminal UNKNOWN.
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    sink = Sink()
    store = EnvironmentSecretStore({})

    process_advance(sm, run_id, _noop_enqueue, store, _runner(sink))  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    claim = execute_advancement(sm, run_id, store)
    assert claim.action_task is not None
    # Cross the durable boundary exactly as process_advance does, then send and
    # "crash" before finalize (do not call finalize_action).
    assert mark_transmission_started(sm, claim.action_task, set_worker_context_default)
    run_action(claim.action_task, transport=sink.transport())
    assert len(sink.calls) == 1  # delivered once

    # Lease still live -> a redelivery defers (no premature duplicate).
    assert execute_advancement(sm, run_id, store).result == "deferred"

    # Original worker dies: resume must NOT resend a transmission-started action.
    _expire_lease(pg_stack.owner_libpq, run_id)
    _drive(sm, run_id, _runner(sink), store)
    assert len(sink.calls) == 1  # NEVER resent
    ea = _ea(pg_stack.owner_libpq, run_id)
    assert ea["status"] == "unknown" and ea["error_class"] == ACTION_OUTCOME_UNKNOWN
    assert _step(pg_stack.owner_libpq, run_id)[0] == "FAILED"


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


def test_retryable_connect_error_schedules_backoff_and_gates_early_redelivery(
    pg_stack: SimpleNamespace,
) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, _webhook_plan())
    sm = _worker_sm(pg_stack)
    store = EnvironmentSecretStore({})
    sink = Sink()
    # The retryable case is a PROVABLY pre-transmission failure (connect refused);
    # a webhook 429 or 5xx is now UNKNOWN, not retried (P1C).
    runner = _connect_error_runner(sink)

    process_advance(sm, run_id, _noop_enqueue, store, runner)  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    out = process_advance(sm, run_id, _noop_enqueue, store, runner)
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
    # Every attempt fails PROVABLY before transmission (connect refused), so the
    # attempt cap finally fails the run DEFINITIVELY (not UNKNOWN).
    runner = _connect_error_runner(sink)

    process_advance(sm, run_id, _noop_enqueue, store, runner)  # park
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    # Repeatedly attempt: clear the retry gate each time by expiring lease + due.
    result = "retry"
    for _ in range(8):
        out = process_advance(sm, run_id, _noop_enqueue, store, runner)
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
    # Provable pre-transmission failures at the cap are a DEFINITE failure, not
    # UNKNOWN (the effect provably never occurred).
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
