"""Durable transmission-boundary crash semantics (ADR-013 correction).

Proves the corrected crash-window guarantee: an external action that may have
begun transmitting must never be automatically resent. A durable
``external_actions.transmission_started_at`` boundary is committed immediately
BEFORE the out-of-lock network send; if an attempt crosses it but never
finalizes (worker death / lease loss), lease recovery transitions the action to
terminal ACTION_OUTCOME_UNKNOWN instead of redelivering it. Only a tool with an
explicit, enforced idempotency contract (``ToolSpec.idempotent_delivery``) may
safely replay — a stable idempotency KEY alone never authorizes replay.

All proof uses an in-process controlled receiver (httpx.MockTransport); no real
network endpoint is ever contacted. The within-attempt P1C classification
(connect→retry, 5xx/ambiguous→UNKNOWN, success→success) is unchanged.
"""

import json
import uuid
from collections.abc import Callable
from types import SimpleNamespace

import httpx
import psycopg
import pytest
from sqlalchemy.orm import Session, sessionmaker

from nlw.connectors.webhook import execute_webhook_action
from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.domain.workflow import WorkflowPlan
from nlw.engine.actions import (
    ACTION_OUTCOME_UNKNOWN,
    ActionExecResult,
    ActionTask,
    finalize_action,
    mark_transmission_started,
    run_action,
)
from nlw.engine.execution import execute_advancement, process_advance
from nlw.engine.runs import create_run, create_workflow_with_version
from nlw.registry.registry import REGISTRY, ToolCategory, ToolSpec, UnknownToolError
from nlw.scheduler.reconcile import find_stuck_runs
from nlw.secrets.store import EnvironmentSecretStore
from nlw.tenancy.keys import process_signer
from nlw.tenancy.session import (
    apply_signed_context_sync,
    set_scheduler_context_sync,
    set_worker_context_default,
)
from nlw.tenancy.signing import Purpose
from nlw.tools.action_schemas import WebhookSendArgs

pytestmark = pytest.mark.integration

ActionRunner = Callable[[ActionTask], ActionExecResult]
STORE = EnvironmentSecretStore({})

# Point 9: a TEST-ONLY tool with an explicit, enforced idempotency contract. No
# production connector has one; this exists solely to prove that ONLY such a tool
# may replay after the transmission boundary. Registered once (process-global).
IDEMPOTENT_TOOL = "test.idempotent_webhook"
try:
    REGISTRY.get(IDEMPOTENT_TOOL)
except UnknownToolError:
    REGISTRY.register(
        ToolSpec(
            name=IDEMPOTENT_TOOL,
            description="test-only webhook whose receiver enforces idempotency",
            category=ToolCategory.ACTION,
            connector_type="webhook",
            input_model=WebhookSendArgs,
            read_only=False,
            requires_approval=False,  # claim directly (no approval park) for the test
            timeout_seconds=15,
            side_effecting=True,
            execute_action=execute_webhook_action,
            idempotent_delivery=True,
        )
    )


class CountingSink:
    """In-process receiver; every delivery is a distinct business effect."""

    def __init__(self, status_code: int = 200) -> None:
        self.calls = 0
        self.keys: list[str] = []
        self._status = status_code

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self.keys.append(request.headers.get("Idempotency-Key", ""))
        return httpx.Response(self._status, headers={"X-Request-Id": "r1"})

    def runner(self) -> ActionRunner:
        return lambda task: run_action(task, transport=httpx.MockTransport(self.handler))


def _connect_error_runner(sink: CountingSink) -> ActionRunner:
    """Provably pre-transmission failure (connection refused) -> RETRY."""

    class _Boom(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

    def run(task: ActionTask) -> ActionExecResult:
        sink.calls += 1  # a send was ATTEMPTED (but provably failed before transmit)
        return run_action(task, transport=_Boom())

    return run


def _worker_sm(pg_stack: SimpleNamespace) -> sessionmaker[Session]:
    return create_sync_sessionmaker(create_sync_engine(pg_stack.worker_settings))


def _seed_webhook(owner_libpq: str, tenant_id: uuid.UUID) -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO connectors (id, tenant_id, type, name, config, status) "
            "VALUES (%s,%s,'webhook','hook',%s::jsonb,'active')",
            (uuid.uuid4(), tenant_id, json.dumps({"url": "https://sink.example/hook"})),
        )


def _plan(tool: str = "webhook.send") -> WorkflowPlan:
    return WorkflowPlan.model_validate(
        {
            "steps": [
                {"id": "notify", "tool": tool, "args": {"payload": {"x": 1}}, "connector": "hook"}
            ]
        }
    )


def _seed(pg_stack: SimpleNamespace, m: SimpleNamespace, plan: WorkflowPlan) -> uuid.UUID:
    engine = create_sync_engine(pg_stack.settings)
    try:
        with create_sync_sessionmaker(engine)() as s, s.begin():
            apply_signed_context_sync(
                s, pg_stack.sign(Purpose.API_REQUEST, user_id=m.user_id, tenant_id=m.tenant_id)
            )
            wf, ver = create_workflow_with_version(s, m.tenant_id, "wf", plan)
            return create_run(s, m.tenant_id, wf.id, ver.id).id
    finally:
        engine.dispose()


def _row(owner_libpq: str, sql: str, params: tuple[object, ...]) -> tuple[object, ...] | None:
    with psycopg.connect(owner_libpq) as c:
        return c.execute(sql, params).fetchone()


def _ea(owner_libpq: str, run_id: uuid.UUID) -> dict[str, object]:
    with psycopg.connect(owner_libpq) as c:
        c.row_factory = psycopg.rows.dict_row  # type: ignore[assignment]
        row = c.execute("SELECT * FROM external_actions WHERE run_id=%s", (run_id,)).fetchone()
    return dict(row) if row else {}


def _approve(owner_libpq: str, run_id: uuid.UUID, by: uuid.UUID) -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "UPDATE approvals SET status='approved', decided_by=%s, decided_at=now() "
            "WHERE run_id=%s",
            (by, run_id),
        )


def _park_and_approve(
    sm: sessionmaker[Session], run_id: uuid.UUID, m: SimpleNamespace, owner_libpq: str
) -> None:
    assert process_advance(sm, run_id, _noop, STORE, _sink_never).result == "waiting"
    _approve(owner_libpq, run_id, m.user_id)


def _expire_lease(owner_libpq: str, run_id: uuid.UUID) -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "UPDATE external_actions SET lease_expires_at = now() - interval '1 second' "
            "WHERE run_id=%s",
            (run_id,),
        )


def _cross_boundary(sm: sessionmaker[Session], task: ActionTask) -> bool:
    """Commit the durable transmission boundary exactly as process_advance does."""
    return mark_transmission_started(sm, task, set_worker_context_default)


def _noop(_rid: uuid.UUID, _delay: float | None = None) -> None:
    return None


def _sink_never(_task: ActionTask) -> ActionExecResult:
    raise AssertionError("no delivery expected during approval park")


def _drive(sm: sessionmaker[Session], run_id: uuid.UUID, runner: ActionRunner, n: int = 8) -> str:
    last = "noop"
    for _ in range(n):
        last = str(process_advance(sm, run_id, _noop, STORE, runner).result)
        if last in ("completed", "failed", "waiting", "noop"):
            break
    return last


# --- 1. crash BEFORE the durable boundary -> eligible for retry -----------------------
def test_1_crash_before_boundary_is_retryable(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _plan())
    sm = _worker_sm(pg_stack)
    sink = CountingSink()
    _park_and_approve(sm, run_id, m, pg_stack.owner_libpq)
    claim = execute_advancement(sm, run_id, STORE)  # claim only; boundary NOT crossed
    assert claim.action_task is not None
    assert _ea(pg_stack.owner_libpq, run_id)["transmission_started_at"] is None
    # The worker "died" before crossing the boundary: nothing was transmitted, so
    # on lease expiry the action is re-claimed and delivered (eligible for retry).
    _expire_lease(pg_stack.owner_libpq, run_id)
    assert _drive(sm, run_id, sink.runner()) == "completed"
    assert sink.calls >= 1
    assert _row(
        pg_stack.owner_libpq, "SELECT status FROM step_runs WHERE run_id=%s", (run_id,)
    ) == ("SUCCESS",)


# --- 2. crash AFTER boundary, before opening a connection -> conservative UNKNOWN ------
def test_2_crash_after_boundary_before_connection_is_unknown(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _plan())
    sm = _worker_sm(pg_stack)
    sink = CountingSink()
    _park_and_approve(sm, run_id, m, pg_stack.owner_libpq)
    claim = execute_advancement(sm, run_id, STORE)
    assert claim.action_task is not None
    assert _cross_boundary(sm, claim.action_task)  # boundary committed; NO send performed
    # Worker dies before any bytes leave. We CANNOT prove non-transmission -> UNKNOWN.
    _expire_lease(pg_stack.owner_libpq, run_id)
    assert _drive(sm, run_id, sink.runner()) == "failed"
    assert sink.calls == 0  # never resent
    ea = _ea(pg_stack.owner_libpq, run_id)
    assert ea["status"] == "unknown" and ea["error_class"] == ACTION_OUTCOME_UNKNOWN


# --- 3. crash after request bytes are accepted, before response -> UNKNOWN -------------
def test_3_crash_after_bytes_before_response_is_unknown(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _plan())
    sm = _worker_sm(pg_stack)
    sink = CountingSink()
    _park_and_approve(sm, run_id, m, pg_stack.owner_libpq)
    claim = execute_advancement(sm, run_id, STORE)
    assert claim.action_task is not None
    assert _cross_boundary(sm, claim.action_task)
    run_action(claim.action_task, transport=httpx.MockTransport(sink.handler))  # bytes sent
    assert sink.calls == 1
    # Worker dies before finalize: the effect MAY have happened -> UNKNOWN, no resend.
    _expire_lease(pg_stack.owner_libpq, run_id)
    assert _drive(sm, run_id, sink.runner()) == "failed"
    assert sink.calls == 1  # NOT redelivered
    assert _ea(pg_stack.owner_libpq, run_id)["status"] == "unknown"


# --- 4. crash after response, before finalization -> UNKNOWN unless finalize committed -
def test_4a_crash_after_response_before_finalize_is_unknown(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _plan())
    sm = _worker_sm(pg_stack)
    sink = CountingSink()
    _park_and_approve(sm, run_id, m, pg_stack.owner_libpq)
    claim = execute_advancement(sm, run_id, STORE)
    assert claim.action_task is not None
    assert _cross_boundary(sm, claim.action_task)
    run_action(claim.action_task, transport=httpx.MockTransport(sink.handler))  # 200 received
    assert sink.calls == 1  # finalize NOT called (crash after response)
    _expire_lease(pg_stack.owner_libpq, run_id)
    assert _drive(sm, run_id, sink.runner()) == "failed"
    assert sink.calls == 1
    assert _ea(pg_stack.owner_libpq, run_id)["status"] == "unknown"


def test_4b_finalized_success_before_crash_stands_and_is_not_resent(
    pg_stack: SimpleNamespace,
) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _plan())
    sm = _worker_sm(pg_stack)
    sink = CountingSink()
    _park_and_approve(sm, run_id, m, pg_stack.owner_libpq)
    claim = execute_advancement(sm, run_id, STORE)
    assert claim.action_task is not None
    assert _cross_boundary(sm, claim.action_task)
    result = run_action(claim.action_task, transport=httpx.MockTransport(sink.handler))
    finalize_action(sm, claim.action_task, result, set_worker_context_default)  # SUCCESS committed
    assert sink.calls == 1
    # A later replay after the finalized success is a noop; success stands.
    _expire_lease(pg_stack.owner_libpq, run_id)
    assert _drive(sm, run_id, sink.runner()) in ("completed", "noop")
    assert sink.calls == 1
    ea = _ea(pg_stack.owner_libpq, run_id)
    assert ea["status"] == "success"


# --- 5. expired lease on a transmission-started action -> UNKNOWN, no resend -----------
def test_5_expired_lease_on_transmission_started_is_unknown(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _plan())
    sm = _worker_sm(pg_stack)
    sink = CountingSink()
    _park_and_approve(sm, run_id, m, pg_stack.owner_libpq)
    claim = execute_advancement(sm, run_id, STORE)
    assert claim.action_task is not None
    assert _cross_boundary(sm, claim.action_task)
    # The action is transmission-started but its lease simply expires (slow/dead
    # worker). A duplicate wake-up BEFORE expiry defers; AFTER expiry -> UNKNOWN.
    assert execute_advancement(sm, run_id, STORE).result == "deferred"
    _expire_lease(pg_stack.owner_libpq, run_id)
    assert _drive(sm, run_id, sink.runner()) == "failed"
    assert sink.calls == 0
    assert _ea(pg_stack.owner_libpq, run_id)["status"] == "unknown"


# --- 6. the reconciler cannot re-arm an UNKNOWN action --------------------------------
def test_6_reconciler_excludes_boundary_unknown(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _plan())
    sm = _worker_sm(pg_stack)
    _park_and_approve(sm, run_id, m, pg_stack.owner_libpq)
    claim = execute_advancement(sm, run_id, STORE)
    assert claim.action_task is not None
    assert _cross_boundary(sm, claim.action_task)
    _expire_lease(pg_stack.owner_libpq, run_id)
    assert _drive(sm, run_id, CountingSink().runner()) == "failed"
    assert _ea(pg_stack.owner_libpq, run_id)["status"] == "unknown"
    # The stale-run reconciler must never re-enqueue a run bearing an UNKNOWN action.
    with (
        create_sync_sessionmaker(create_sync_engine(pg_stack.scheduler_settings))() as s,
        s.begin(),
    ):
        set_scheduler_context_sync(s, process_signer(Purpose.SCHEDULER_RECONCILE))
        from datetime import UTC, datetime

        batch = find_stuck_runs(
            s,
            datetime.now(UTC),
            pending_threshold_s=0,
            batch_limit=100,
            recovery_horizon_s=10**9,
            per_tenant_limit=100,
        )
    assert run_id not in set(batch.run_ids)


# --- 7. duplicate wake-ups cannot resend an UNKNOWN action ----------------------------
def test_7_duplicate_wakeups_cannot_resend_unknown(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _plan())
    sm = _worker_sm(pg_stack)
    sink = CountingSink()
    _park_and_approve(sm, run_id, m, pg_stack.owner_libpq)
    claim = execute_advancement(sm, run_id, STORE)
    assert claim.action_task is not None
    assert _cross_boundary(sm, claim.action_task)
    _expire_lease(pg_stack.owner_libpq, run_id)
    assert _drive(sm, run_id, sink.runner()) == "failed"
    assert sink.calls == 0
    # Every subsequent wake-up is a terminal noop; the UNKNOWN is never resent.
    for _ in range(4):
        assert process_advance(sm, run_id, _noop, STORE, sink.runner()).result == "noop"
    assert sink.calls == 0


# --- 8. a generic webhook + stable key cannot use the contractual-idempotency path ----
def test_8_generic_webhook_stable_key_cannot_replay(pg_stack: SimpleNamespace) -> None:
    # The stable idempotency KEY does not authorize replay: webhook.send has no
    # enforced contract, so a boundary crash is UNKNOWN, not a keyed resend.
    assert REGISTRY.get("webhook.send").idempotent_delivery is False
    assert REGISTRY.get("slack.send_message").idempotent_delivery is False
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _plan())
    sm = _worker_sm(pg_stack)
    sink = CountingSink()
    _park_and_approve(sm, run_id, m, pg_stack.owner_libpq)
    claim = execute_advancement(sm, run_id, STORE)
    assert claim.action_task is not None
    assert _cross_boundary(sm, claim.action_task)
    run_action(claim.action_task, transport=httpx.MockTransport(sink.handler))
    assert sink.calls == 1
    _expire_lease(pg_stack.owner_libpq, run_id)
    assert _drive(sm, run_id, sink.runner()) == "failed"
    assert sink.calls == 1  # a stable key did NOT authorize a second delivery
    assert _ea(pg_stack.owner_libpq, run_id)["status"] == "unknown"


# --- 9. ONLY an explicit, enforced idempotency contract permits safe replay -----------
def test_9_enforced_idempotency_contract_permits_replay(pg_stack: SimpleNamespace) -> None:
    assert REGISTRY.get(IDEMPOTENT_TOOL).idempotent_delivery is True
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed(pg_stack, m, _plan(tool=IDEMPOTENT_TOOL))
    sm = _worker_sm(pg_stack)
    sink = CountingSink()
    # This tool does not require approval: the first advance claims + delivers.
    claim = execute_advancement(sm, run_id, STORE)
    assert claim.action_task is not None
    assert _cross_boundary(sm, claim.action_task)
    run_action(claim.action_task, transport=httpx.MockTransport(sink.handler))  # crash before final
    assert sink.calls == 1
    key_first = sink.keys[0]
    # Because the receiver ENFORCES idempotency on the stable key, replay is safe:
    # the action re-attempts (at-least-once) and is NOT forced to UNKNOWN.
    _expire_lease(pg_stack.owner_libpq, run_id)
    assert _drive(sm, run_id, sink.runner()) == "completed"
    assert sink.calls == 2  # replayed under contract
    assert sink.keys[1] == key_first  # SAME stable key both times
    assert _ea(pg_stack.owner_libpq, run_id)["status"] == "success"


# --- 10. P1C within-attempt classification is unchanged by the boundary ----------------
def test_10_p1c_classification_matrix_unchanged(pg_stack: SimpleNamespace) -> None:
    o = pg_stack.owner_libpq

    # (a) provable pre-transmission failure (connect refused) -> RETRY; the retry
    #     scheduling CLEARS the boundary so resume does not force a spurious UNKNOWN.
    m = pg_stack.seed_member()
    _seed_webhook(o, m.tenant_id)
    r_retry = _seed(pg_stack, m, _plan())
    sm = _worker_sm(pg_stack)
    _park_and_approve(sm, r_retry, m, o)
    assert process_advance(
        sm, r_retry, _noop, STORE, _connect_error_runner(CountingSink())
    ).result == ("retry")
    ea = _ea(o, r_retry)
    assert ea["status"] == "pending" and ea["next_attempt_at"] is not None
    assert ea["transmission_started_at"] is None  # cleared on retry

    # (b) generic webhook 5xx -> UNKNOWN (never retried).
    m2 = pg_stack.seed_member()
    _seed_webhook(o, m2.tenant_id)
    r_5xx = _seed(pg_stack, m2, _plan())
    _park_and_approve(sm, r_5xx, m2, o)
    assert _drive(sm, r_5xx, CountingSink(status_code=500).runner()) == "failed"
    assert _ea(o, r_5xx)["status"] == "unknown"

    # (c) success -> success.
    m3 = pg_stack.seed_member()
    _seed_webhook(o, m3.tenant_id)
    r_ok = _seed(pg_stack, m3, _plan())
    _park_and_approve(sm, r_ok, m3, o)
    assert _drive(sm, r_ok, CountingSink().runner()) == "completed"
    assert _ea(o, r_ok)["status"] == "success"
