"""Connector-backed tool execution through the durable engine (M4).

Proves ownership gating, worker-side health transitions, secret resolution, and
that the secret never leaks. Seeds connectors as owner (bypassing RLS) and runs
workflows as nlw_app (create) / nlw_worker (execute).
"""

import json
import uuid
from types import SimpleNamespace

import psycopg
import pytest
import structlog
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.domain.workflow import WorkflowPlan
from nlw.engine.execution import execute_advancement
from nlw.engine.runs import create_run, create_workflow_with_version
from nlw.secrets.store import EnvironmentSecretStore

pytestmark = pytest.mark.integration

SECRET = "topsecret-must-not-leak"
STORE = EnvironmentSecretStore({"NLW_SECRET_STATIC_DEMO": SECRET})
EMPTY_STORE = EnvironmentSecretStore({})


def _seed_connector(
    owner_libpq: str,
    tenant_id: uuid.UUID,
    *,
    name: str = "demo",
    type_: str = "static",
    secret_ref: str | None = "STATIC_DEMO",
    status: str = "unchecked",
) -> uuid.UUID:
    cid = uuid.uuid4()
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO connectors (id, tenant_id, type, name, config, secret_ref, status) "
            "VALUES (%s,%s,%s,%s,%s::jsonb,%s,%s)",
            (cid, tenant_id, type_, name, json.dumps({"label": "x"}), secret_ref, status),
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


def _steps(owner_libpq: str, run_id: uuid.UUID) -> dict[str, tuple[str, object, object]]:
    with psycopg.connect(owner_libpq) as c:
        rows = c.execute(
            "SELECT step_id, status, output, error FROM step_runs WHERE run_id=%s", (run_id,)
        ).fetchall()
    return {r[0]: (r[1], r[2], r[3]) for r in rows}


def _connector_status(owner_libpq: str, cid: uuid.UUID) -> str:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute("SELECT status FROM connectors WHERE id=%s", (cid,)).fetchone()
    assert row is not None
    return str(row[0])


def test_connector_backed_execution_and_health(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    cid = _seed_connector(pg_stack.owner_libpq, m.tenant_id)  # unchecked
    plan = WorkflowPlan.model_validate(
        {
            "steps": [
                {"id": "a", "tool": "static.echo", "args": {"msg": "hi"}, "connector": "demo"},
                {
                    "id": "b",
                    "tool": "static.secret_check",
                    "connector": "demo",
                    "depends_on": ["a"],
                },
            ]
        }
    )
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, plan)
    sm = _worker_sm(pg_stack)

    with structlog.testing.capture_logs() as logs:
        for _ in range(4):
            if execute_advancement(sm, run_id, STORE).result in ("completed", "failed", "noop"):
                break

    steps = _steps(pg_stack.owner_libpq, run_id)
    assert steps["a"][0] == "SUCCESS" and steps["a"][1] == {"echo": {"msg": "hi"}}
    assert steps["b"][0] == "SUCCESS" and steps["b"][1] == {"secret_available": True}
    assert _connector_status(pg_stack.owner_libpq, cid) == "active"  # unchecked -> active

    # Secret non-leak across every surface the worker touched.
    blob = json.dumps(steps) + json.dumps(logs, default=str)
    with psycopg.connect(pg_stack.owner_libpq) as c:
        conn_dump = str(c.execute("SELECT id, config, secret_ref FROM connectors").fetchall())
        plan_dump = str(c.execute("SELECT plan FROM workflow_versions").fetchall())
        io_dump = str(
            c.execute(
                "SELECT input, output, error FROM step_runs WHERE run_id=%s", (run_id,)
            ).fetchall()
        )
    assert SECRET not in blob
    assert SECRET not in conn_dump
    assert SECRET not in plan_dump
    assert SECRET not in io_dump


def test_missing_connector_selector_fails(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _seed_connector(pg_stack.owner_libpq, m.tenant_id)
    plan = WorkflowPlan.model_validate(
        {"steps": [{"id": "a", "tool": "static.echo", "args": {}}]}  # no connector
    )
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, plan)
    assert execute_advancement(_worker_sm(pg_stack), run_id, STORE).result == "failed"


def test_unowned_connector_fails(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()  # no connector seeded
    plan = WorkflowPlan.model_validate(
        {"steps": [{"id": "a", "tool": "static.echo", "args": {}, "connector": "demo"}]}
    )
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, plan)
    assert execute_advancement(_worker_sm(pg_stack), run_id, STORE).result == "failed"


def test_disabled_connector_fails_and_stays_disabled(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    cid = _seed_connector(pg_stack.owner_libpq, m.tenant_id, status="disabled")
    plan = WorkflowPlan.model_validate(
        {"steps": [{"id": "a", "tool": "static.echo", "args": {}, "connector": "demo"}]}
    )
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, plan)
    assert execute_advancement(_worker_sm(pg_stack), run_id, STORE).result == "failed"
    assert _connector_status(pg_stack.owner_libpq, cid) == "disabled"


def test_unresolved_secret_marks_error_then_recovers(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    cid = _seed_connector(pg_stack.owner_libpq, m.tenant_id)
    plan = {"steps": [{"id": "a", "tool": "static.echo", "args": {}, "connector": "demo"}]}
    sm = _worker_sm(pg_stack)

    # First run with an EMPTY store -> health fails -> status=error, step FAILED.
    run1 = _seed_run(pg_stack, m.user_id, m.tenant_id, WorkflowPlan.model_validate(plan))
    assert execute_advancement(sm, run1, EMPTY_STORE).result == "failed"
    assert _connector_status(pg_stack.owner_libpq, cid) == "error"

    # error is recoverable: a later run with the secret available -> active + success.
    run2 = _seed_run(pg_stack, m.user_id, m.tenant_id, WorkflowPlan.model_validate(plan))
    execute_advancement(sm, run2, STORE)
    execute_advancement(sm, run2, STORE)  # completion
    assert _connector_status(pg_stack.owner_libpq, cid) == "active"
    assert _steps(pg_stack.owner_libpq, run2)["a"][0] == "SUCCESS"
