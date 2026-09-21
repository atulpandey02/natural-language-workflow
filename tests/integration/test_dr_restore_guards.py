"""Restore destructive-safety guards + the runtime-start gate (P2)."""

from types import SimpleNamespace

import psycopg
import pytest
from sqlalchemy import create_engine, text

from nlw.backup.config import RestoreSettings
from nlw.backup.quiescence import quiesce
from nlw.backup.restore import (
    assert_no_runtime_connections,
    assert_target_empty,
    restore_ready,
    run_restore,
)

pytestmark = pytest.mark.integration


def test_target_empty_guard(pg_stack: SimpleNamespace) -> None:
    engine = create_engine(pg_stack.owner_sa)
    # The migrated stack DB is NON-empty -> refuse.
    with pytest.raises(RuntimeError, match="not empty"):
        assert_target_empty(engine)

    # A genuinely fresh empty DB -> allowed.
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute("CREATE DATABASE dr_empty_target")
    empty_url = pg_stack.owner_sa.rsplit("/", 1)[0] + "/dr_empty_target"
    assert_target_empty(create_engine(empty_url))  # no public tables -> ok


def test_active_runtime_connection_blocks_restore(pg_stack: SimpleNamespace) -> None:
    owner_engine = create_engine(pg_stack.owner_sa)
    assert_no_runtime_connections(owner_engine)  # nothing connected yet

    app_engine = create_engine(pg_stack.settings.database_url)
    # A live nlw_app connection = runtime active -> restore must refuse.
    with (
        app_engine.connect() as _held,
        pytest.raises(RuntimeError, match="runtime services appear active"),
    ):
        assert_no_runtime_connections(owner_engine)


def test_run_restore_refuses_without_matching_confirmation(pg_stack: SimpleNamespace) -> None:
    settings = RestoreSettings(
        app_env="local",
        NLW_RESTORE_DATABASE_URL=pg_stack.owner_sa,
        NLW_RESTORE_TARGET_ID="dr-target-x",
        NLW_RESTORE_CONFIRM="",  # missing confirmation
    )
    with pytest.raises(ValueError, match="NLW_RESTORE_CONFIRM"):
        run_restore(settings)


def test_restore_ready_gate(pg_stack: SimpleNamespace) -> None:
    engine = create_engine(pg_stack.owner_sa)
    # No restore event yet -> not ready.
    assert restore_ready(engine) is False
    # A non-terminal run present + no event -> not ready.
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        m = pg_stack.seed_member()
        wf, ver, run = (__import__("uuid").uuid4() for _ in range(3))
        c.execute(
            "INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'w')", (wf, m.tenant_id)
        )
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,'{\"steps\":[]}'::jsonb)",
            (ver, m.tenant_id, wf),
        )
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status) "
            "VALUES (%s,%s,%s,%s,'RUNNING')",
            (run, m.tenant_id, wf, ver),
        )
    assert restore_ready(engine) is False
    # After quiescence (event recorded + non-terminal cleared) -> ready.
    quiesce(engine)
    assert restore_ready(engine) is True
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM dr_restore_events")).scalar_one() >= 1
