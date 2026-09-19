"""Security boundary of the worker-only run->tenant resolver and roles."""

import uuid
from types import SimpleNamespace

import psycopg
import pytest
from sqlalchemy import text

from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.domain.workflow import WorkflowPlan
from nlw.engine.runs import create_run, create_workflow_with_version

pytestmark = pytest.mark.integration

_PLAN = WorkflowPlan.model_validate({"steps": [{"id": "a", "tool": "fake.echo"}]})


def _seed(pg_stack: SimpleNamespace, tenant_id: uuid.UUID) -> uuid.UUID:
    engine = create_sync_engine(pg_stack.settings)
    try:
        sm = create_sync_sessionmaker(engine)
        with sm() as s, s.begin():
            s.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)})
            wf, ver = create_workflow_with_version(s, tenant_id, "wf", _PLAN)
            run = create_run(s, tenant_id, wf.id, ver.id)
            return run.id
    finally:
        engine.dispose()


def test_worker_can_execute_resolver(pg_stack: SimpleNamespace) -> None:
    tenant = uuid.uuid4()
    run_id = _seed(pg_stack, tenant)
    with psycopg.connect(pg_stack.worker_libpq) as c:
        row = c.execute("SELECT resolve_run_tenant(%s)", (str(run_id),)).fetchone()
        c.rollback()
    assert row is not None and row[0] == tenant


def test_app_role_cannot_execute_resolver(pg_stack: SimpleNamespace) -> None:
    run_id = _seed(pg_stack, uuid.uuid4())
    with (
        psycopg.connect(pg_stack.app_libpq) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute("SELECT resolve_run_tenant(%s)", (str(run_id),))


def test_public_cannot_execute_resolver(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.owner_libpq) as c:
        pub = c.execute(
            "SELECT has_function_privilege('public', 'resolve_run_tenant(uuid)', 'EXECUTE')"
        ).fetchone()
        app = c.execute(
            "SELECT has_function_privilege('nlw_app', 'resolve_run_tenant(uuid)', 'EXECUTE')"
        ).fetchone()
        wrk = c.execute(
            "SELECT has_function_privilege('nlw_worker', 'resolve_run_tenant(uuid)', 'EXECUTE')"
        ).fetchone()
    assert pub is not None and pub[0] is False
    assert app is not None and app[0] is False
    assert wrk is not None and wrk[0] is True


def test_app_cannot_expose_other_tenant_via_gucs(pg_stack: SimpleNamespace) -> None:
    tenant = uuid.uuid4()
    run_id = _seed(pg_stack, tenant)
    with psycopg.connect(pg_stack.app_libpq) as c:
        # Set an arbitrary tenant and the (now non-existent) run_id GUC.
        c.execute("SELECT set_config('app.tenant_id', %s, true)", (str(uuid.uuid4()),))
        c.execute("SELECT set_config('app.run_id', %s, true)", (str(run_id),))
        rows = c.execute("SELECT count(*) FROM workflow_runs WHERE id=%s", (run_id,)).fetchone()
        c.rollback()
    assert rows is not None and rows[0] == 0


def test_worker_remains_rls_restricted_after_bootstrap(pg_stack: SimpleNamespace) -> None:
    tenant = uuid.uuid4()
    run_id = _seed(pg_stack, tenant)
    with psycopg.connect(pg_stack.worker_libpq) as c:
        c.execute("SELECT set_config('app.tenant_id', %s, true)", (str(tenant),))
        mine = c.execute("SELECT count(*) FROM workflow_runs WHERE id=%s", (run_id,)).fetchone()
        c.execute("SELECT set_config('app.tenant_id', %s, true)", (str(uuid.uuid4()),))
        other = c.execute("SELECT count(*) FROM workflow_runs WHERE id=%s", (run_id,)).fetchone()
        c.rollback()
    assert mine is not None and mine[0] == 1
    assert other is not None and other[0] == 0


def test_role_attributes(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.owner_libpq) as c:
        rows = c.execute(
            "SELECT rolname, rolsuper, rolbypassrls, rolcanlogin FROM pg_roles "
            "WHERE rolname IN ('nlw_app','nlw_worker','nlw_rls_bypass')"
        ).fetchall()
    attrs = {r[0]: (r[1], r[2], r[3]) for r in rows}
    assert attrs["nlw_app"] == (False, False, True)
    assert attrs["nlw_worker"] == (False, False, True)
    assert attrs["nlw_rls_bypass"] == (False, True, False)  # NOLOGIN, BYPASSRLS
