"""Authoritative connector identity binding — adversarial coverage (M12B, Part 3).

A materialized workflow version pins each connector-backed step to the connector
UUID + a non-secret config fingerprint. Execution loads BY THE BOUND UUID and
fails closed (STALE_PLAN) if the connector was deleted/recreated, type-changed, or
its execution-relevant config changed — before any connector I/O. A secret-only
rotation stays valid. The model never chooses a connector id.

Each case approves the action while the connector is FRESH, then changes the
connector before the claim — modelling a real approval whose connector is
mutated before execution — and asserts the claim fails STALE_PLAN with no send.
"""

import json
import uuid
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import httpx
import psycopg
import pytest
from sqlalchemy.orm import Session, sessionmaker

from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.domain.workflow import WorkflowPlan
from nlw.engine.actions import ActionExecResult, ActionTask, run_action
from nlw.engine.execution import process_advance
from nlw.engine.runs import create_run, create_workflow_with_version
from nlw.feasibility.connector_binding import build_binding
from nlw.secrets.store import EnvironmentSecretStore, env_key_for
from nlw.tenancy.session import apply_signed_context_sync
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

ActionRunner = Callable[[ActionTask], ActionExecResult]
STORE = EnvironmentSecretStore({})
WEBHOOK_CFG = {"url": "https://sink.example/hook"}


class CountingSink:
    def __init__(self) -> None:
        self.calls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return httpx.Response(200)

    def runner(self) -> ActionRunner:
        return lambda task: run_action(task, transport=httpx.MockTransport(self.handler))


def _worker_sm(pg_stack: SimpleNamespace) -> sessionmaker[Session]:
    return create_sync_sessionmaker(create_sync_engine(pg_stack.worker_settings))


def _seed_webhook(
    owner_libpq: str,
    tenant_id: uuid.UUID,
    *,
    name: str = "hook",
    config: dict[str, Any] | None = None,
    secret_ref: str | None = None,
    cid: uuid.UUID | None = None,
) -> uuid.UUID:
    cid = cid or uuid.uuid4()
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO connectors (id, tenant_id, type, name, config, secret_ref, status) "
            "VALUES (%s,%s,'webhook',%s,%s::jsonb,%s,'active')",
            (cid, tenant_id, name, json.dumps(config or WEBHOOK_CFG), secret_ref),
        )
    return cid


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


def _current(owner_libpq: str, tenant_id: uuid.UUID, name: str = "hook") -> tuple[Any, ...]:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute(
            "SELECT id, type, config FROM connectors WHERE tenant_id=%s AND name=%s",
            (tenant_id, name),
        ).fetchone()
    assert row is not None
    return row


def _seed_bound_run(pg_stack: SimpleNamespace, m: SimpleNamespace) -> uuid.UUID:
    """A version whose connector binding is pinned to the CURRENT 'hook' connector."""
    cid, ctype, cfg = _current(pg_stack.owner_libpq, m.tenant_id)
    bindings: dict[str, Any] = {"notify": build_binding(str(cid), ctype, cfg)}
    engine = create_sync_engine(pg_stack.settings)
    try:
        with create_sync_sessionmaker(engine)() as s, s.begin():
            apply_signed_context_sync(
                s, pg_stack.sign(Purpose.API_REQUEST, user_id=m.user_id, tenant_id=m.tenant_id)
            )
            wf, ver = create_workflow_with_version(
                s, m.tenant_id, "wf", _webhook_plan(), connector_bindings=bindings
            )
            return create_run(s, m.tenant_id, wf.id, ver.id).id
    finally:
        engine.dispose()


def _approve(owner_libpq: str, run_id: uuid.UUID, by: uuid.UUID) -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "UPDATE approvals SET status='approved', decided_by=%s, decided_at=now() "
            "WHERE run_id=%s",
            (by, run_id),
        )


def _mutate(owner_libpq: str, sql: str, params: tuple[object, ...]) -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(sql, params)


def _noop(_rid: uuid.UUID, _delay: float | None = None) -> None:
    return None


def _drive(sm: sessionmaker[Session], run_id: uuid.UUID, runner: ActionRunner) -> str:
    last = "noop"
    for _ in range(8):
        last = str(process_advance(sm, run_id, _noop, STORE, runner).result)
        if last in ("completed", "failed", "waiting", "noop"):
            break
    return last


def _step_error(owner_libpq: str, run_id: uuid.UUID) -> str | None:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute("SELECT error FROM step_runs WHERE run_id=%s", (run_id,)).fetchone()
    return str(row[0]) if row and row[0] else None


def _run_approved_fresh_then(
    pg_stack: SimpleNamespace,
    m: SimpleNamespace,
    run_id: uuid.UUID,
    mutate: Callable[[], None],
    store: EnvironmentSecretStore = STORE,
) -> tuple[str, CountingSink]:
    """Park + approve while the connector is fresh, apply ``mutate``, then drive."""
    sm = _worker_sm(pg_stack)
    sink = CountingSink()
    assert process_advance(sm, run_id, _noop, store, sink.runner()).result == "waiting"
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    mutate()
    last = "noop"
    for _ in range(8):
        last = str(process_advance(sm, run_id, _noop, store, sink.runner()).result)
        if last in ("completed", "failed", "waiting", "noop"):
            break
    return last, sink


# --- 1. delete + recreate under the same name -> STALE (new UUID) ---------------------
def test_1_delete_recreate_same_name_is_stale(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_bound_run(pg_stack, m)

    def mutate() -> None:
        _mutate(
            pg_stack.owner_libpq,
            "DELETE FROM connectors WHERE tenant_id=%s AND name='hook'",
            (m.tenant_id,),
        )
        _seed_webhook(pg_stack.owner_libpq, m.tenant_id)  # same name, NEW id

    result, sink = _run_approved_fresh_then(pg_stack, m, run_id, mutate)
    assert result == "failed" and sink.calls == 0
    assert _step_error(pg_stack.owner_libpq, run_id) == "CONNECTOR_NOT_FOUND"


# --- 2. same connector name in ANOTHER tenant does not satisfy the binding ------------
def test_2_same_name_other_tenant_is_isolated(pg_stack: SimpleNamespace) -> None:
    a = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, a.tenant_id)
    run_id = _seed_bound_run(pg_stack, a)
    b = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, b.tenant_id)  # B owns a same-named connector

    def mutate() -> None:
        _mutate(
            pg_stack.owner_libpq,
            "DELETE FROM connectors WHERE tenant_id=%s AND name='hook'",
            (a.tenant_id,),
        )

    result, sink = _run_approved_fresh_then(pg_stack, a, run_id, mutate)
    assert result == "failed" and sink.calls == 0
    assert _step_error(pg_stack.owner_libpq, run_id) == "CONNECTOR_NOT_FOUND"


# --- 3. connector type changed -> STALE ----------------------------------------------
def test_3_type_change_is_stale(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_bound_run(pg_stack, m)

    def mutate() -> None:
        _mutate(
            pg_stack.owner_libpq,
            "UPDATE connectors SET type='slack' WHERE tenant_id=%s AND name='hook'",
            (m.tenant_id,),
        )

    result, sink = _run_approved_fresh_then(pg_stack, m, run_id, mutate)
    assert result == "failed" and sink.calls == 0
    assert _step_error(pg_stack.owner_libpq, run_id) == "CONNECTOR_TYPE_MISMATCH"


# --- 4. execution-relevant config (destination) changed -> STALE ----------------------
def test_4_destination_change_is_stale(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_bound_run(pg_stack, m)

    def mutate() -> None:
        _mutate(
            pg_stack.owner_libpq,
            "UPDATE connectors SET config=%s::jsonb WHERE tenant_id=%s AND name='hook'",
            (json.dumps({"url": "https://evil.example/steal"}), m.tenant_id),
        )

    result, sink = _run_approved_fresh_then(pg_stack, m, run_id, mutate)
    assert result == "failed" and sink.calls == 0  # never sent to the changed destination
    assert _step_error(pg_stack.owner_libpq, run_id) == "CONNECTOR_CONFIG_CHANGED"


# --- 5. secret-only rotation stays VALID ---------------------------------------------
def test_5_secret_only_rotation_remains_valid(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id, secret_ref="OLD_REF")
    run_id = _seed_bound_run(pg_stack, m)
    store = EnvironmentSecretStore(
        {
            env_key_for(m.tenant_id, "OLD_REF"): "old-secret",
            env_key_for(m.tenant_id, "NEW_REF"): "new-secret",
        }
    )

    def mutate() -> None:
        _mutate(
            pg_stack.owner_libpq,
            "UPDATE connectors SET secret_ref='NEW_REF' WHERE tenant_id=%s AND name='hook'",
            (m.tenant_id,),
        )

    result, sink = _run_approved_fresh_then(pg_stack, m, run_id, mutate, store)
    assert result == "completed" and sink.calls == 1  # rotation did not invalidate


# --- 6. connector disabled -> blocked ------------------------------------------------
def test_6_disabled_connector_is_blocked(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_bound_run(pg_stack, m)

    def mutate() -> None:
        _mutate(
            pg_stack.owner_libpq,
            "UPDATE connectors SET status='disabled' WHERE tenant_id=%s AND name='hook'",
            (m.tenant_id,),
        )

    result, sink = _run_approved_fresh_then(pg_stack, m, run_id, mutate)
    assert result == "failed" and sink.calls == 0
    assert _step_error(pg_stack.owner_libpq, run_id) == "CONNECTOR_UNUSABLE"


# --- 7. an old version's binding is independent of a freshly materialized one ---------
def test_7_old_version_binding_independent(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    orig = _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    old_run = _seed_bound_run(pg_stack, m)  # bound to orig id

    def mutate() -> None:
        _mutate(pg_stack.owner_libpq, "DELETE FROM connectors WHERE id=%s", (orig,))
        _seed_webhook(pg_stack.owner_libpq, m.tenant_id)  # replacement, new id

    result, sink = _run_approved_fresh_then(pg_stack, m, old_run, mutate)
    assert result == "failed" and sink.calls == 0  # old binding never hits the replacement
    # A NEW version binds to the replacement and runs cleanly.
    new_id, _, _ = _current(pg_stack.owner_libpq, m.tenant_id)
    assert new_id != orig
    fresh_run = _seed_bound_run(pg_stack, m)
    result2, sink2 = _run_approved_fresh_then(pg_stack, m, fresh_run, lambda: None)
    assert result2 == "completed" and sink2.calls == 1


# --- 8. a run started from a stale-bound version is blocked before I/O ----------------
def test_8_stale_binding_blocks_before_connect(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_bound_run(pg_stack, m)

    def mutate() -> None:
        _mutate(
            pg_stack.owner_libpq,
            "UPDATE connectors SET config=%s::jsonb WHERE tenant_id=%s AND name='hook'",
            (json.dumps({"url": "https://elsewhere.example/hook"}), m.tenant_id),
        )

    result, sink = _run_approved_fresh_then(pg_stack, m, run_id, mutate)
    assert result == "failed" and sink.calls == 0


# --- 9. no bytes or credentials leave when the binding is stale -----------------------
def test_9_no_delivery_when_stale(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_webhook(pg_stack.owner_libpq, m.tenant_id)
    run_id = _seed_bound_run(pg_stack, m)

    def mutate() -> None:
        _mutate(
            pg_stack.owner_libpq,
            "UPDATE connectors SET type='slack' WHERE tenant_id=%s AND name='hook'",
            (m.tenant_id,),
        )

    class ExplodingSink(CountingSink):
        def handler(self, request: httpx.Request) -> httpx.Response:  # pragma: no cover
            raise AssertionError("no connection bytes may be sent for a stale binding")

    sm = _worker_sm(pg_stack)
    sink = ExplodingSink()
    assert process_advance(sm, run_id, _noop, STORE, sink.runner()).result == "waiting"
    _approve(pg_stack.owner_libpq, run_id, m.user_id)
    mutate()
    assert _drive(sm, run_id, sink.runner()) == "failed"
    assert sink.calls == 0
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT transmission_started_at FROM external_actions WHERE run_id=%s", (run_id,)
        ).fetchone()
    assert row is None or row[0] is None  # boundary never crossed
