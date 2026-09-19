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


def _seed_run(pg_stack: SimpleNamespace) -> SimpleNamespace:
    """Seed a member + workspace + a run in that tenant (creation as nlw_app)."""
    member = pg_stack.seed_member()
    engine = create_sync_engine(pg_stack.settings)
    try:
        sm = create_sync_sessionmaker(engine)
        with sm() as s, s.begin():
            s.execute(
                text("SELECT set_config('app.user_id', :u, true)"), {"u": str(member.user_id)}
            )
            s.execute(
                text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(member.tenant_id)}
            )
            wf, ver = create_workflow_with_version(s, member.tenant_id, "wf", _PLAN)
            run = create_run(s, member.tenant_id, wf.id, ver.id)
            run_id = run.id
    finally:
        engine.dispose()
    return SimpleNamespace(user_id=member.user_id, tenant_id=member.tenant_id, run_id=run_id)


def test_worker_can_execute_resolver(pg_stack: SimpleNamespace) -> None:
    seeded = _seed_run(pg_stack)
    with psycopg.connect(pg_stack.worker_libpq) as c:
        row = c.execute("SELECT resolve_run_tenant(%s)", (str(seeded.run_id),)).fetchone()
        c.rollback()
    assert row is not None and row[0] == seeded.tenant_id


def test_app_role_cannot_execute_resolver(pg_stack: SimpleNamespace) -> None:
    seeded = _seed_run(pg_stack)
    with (
        psycopg.connect(pg_stack.app_libpq) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute("SELECT resolve_run_tenant(%s)", (str(seeded.run_id),))


def test_execute_privileges(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.owner_libpq) as c:

        def priv(role: str, fn: str) -> bool:
            row = c.execute(
                "SELECT has_function_privilege(%s, %s, 'EXECUTE')", (role, fn)
            ).fetchone()
            assert row is not None
            return bool(row[0])

        # resolver: worker only
        assert priv("nlw_worker", "resolve_run_tenant(uuid)") is True
        assert priv("nlw_app", "resolve_run_tenant(uuid)") is False
        assert priv("public", "resolve_run_tenant(uuid)") is False
        # membership helper: app only
        assert priv("nlw_app", "is_current_user_member(uuid)") is True
        assert priv("nlw_worker", "is_current_user_member(uuid)") is False
        assert priv("public", "is_current_user_member(uuid)") is False
        # workspace bootstrap: app only
        assert priv("nlw_app", "create_workspace_for_current_user(text,text)") is True
        assert priv("public", "create_workspace_for_current_user(text,text)") is False


def test_app_cannot_expose_other_tenant_via_gucs(pg_stack: SimpleNamespace) -> None:
    """Forge app.user_id (non-member) + app.tenant_id = the REAL tenant -> 0 rows."""
    seeded = _seed_run(pg_stack)
    attacker = pg_stack.seed_user()
    with psycopg.connect(pg_stack.app_libpq) as c:
        c.execute("SELECT set_config('app.user_id', %s, true)", (str(attacker),))
        c.execute("SELECT set_config('app.tenant_id', %s, true)", (str(seeded.tenant_id),))
        runs = c.execute(
            "SELECT count(*) FROM workflow_runs WHERE id=%s", (seeded.run_id,)
        ).fetchone()
        c.rollback()
    assert runs is not None and runs[0] == 0


def test_worker_remains_rls_restricted_after_bootstrap(pg_stack: SimpleNamespace) -> None:
    seeded = _seed_run(pg_stack)
    with psycopg.connect(pg_stack.worker_libpq) as c:
        c.execute("SELECT set_config('app.tenant_id', %s, true)", (str(seeded.tenant_id),))
        mine = c.execute(
            "SELECT count(*) FROM workflow_runs WHERE id=%s", (seeded.run_id,)
        ).fetchone()
        c.execute("SELECT set_config('app.tenant_id', %s, true)", (str(uuid.uuid4()),))
        other = c.execute(
            "SELECT count(*) FROM workflow_runs WHERE id=%s", (seeded.run_id,)
        ).fetchone()
        c.rollback()
    assert mine is not None and mine[0] == 1
    assert other is not None and other[0] == 0


def test_role_attributes(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.owner_libpq) as c:
        rows = c.execute(
            "SELECT rolname, rolsuper, rolbypassrls, rolcanlogin FROM pg_roles "
            "WHERE rolname IN ('nlw_app','nlw_worker','nlw_rls_bypass','nlw_workspace_bootstrap')"
        ).fetchall()
    attrs = {r[0]: (r[1], r[2], r[3]) for r in rows}
    assert attrs["nlw_app"] == (False, False, True)
    assert attrs["nlw_worker"] == (False, False, True)
    assert attrs["nlw_rls_bypass"] == (False, True, False)  # NOLOGIN, BYPASSRLS
    assert attrs["nlw_workspace_bootstrap"] == (False, True, False)  # NOLOGIN, BYPASSRLS
