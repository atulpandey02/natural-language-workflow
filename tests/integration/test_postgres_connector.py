"""End-to-end PostgreSQL connector proof (M5).

Uses a SECOND, "external" Postgres container (the tenant's database) with a
dedicated SELECT-only role, separate from the platform ``pg_stack``. Proves the
three independent read-only controls (sqlglot validation, read-only session,
SELECT-only role), the row/byte/timeout bounds, tenant isolation, connector
health transitions, and that the external credential never leaks.
"""

import json
import uuid
from collections.abc import Iterator
from types import SimpleNamespace

import psycopg
import pytest
import structlog
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker
from testcontainers.community.postgres import PostgresContainer

from nlw.connectors.postgres import (
    PostgresAuthError,
    PostgresConnectorConfig,
    PostgresSecret,
    PostgresTimeoutError,
    ResultTooLargeError,
    parse_secret,
    run_read_only_query,
)
from nlw.connectors.postgres import (
    _read_only_connection as read_only_connection,
)
from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.domain.workflow import WorkflowPlan
from nlw.engine.execution import execute_advancement
from nlw.engine.runs import create_run, create_workflow_with_version
from nlw.secrets.store import EnvironmentSecretStore, env_key_for

pytestmark = pytest.mark.integration

READER_USER = "app_reader"
READER_PW = "reader-pw-must-not-leak"
SECRET_REF = "PG_MAIN"


def _libpq(user: str, password: str, host: str, port: str | int, db: str) -> str:
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"


@pytest.fixture(scope="module")
def ext_pg() -> Iterator[SimpleNamespace]:
    """A throwaway 'external' tenant DB with data and a SELECT-only role."""
    with PostgresContainer("postgres:16") as pg:
        host, port, db = pg.get_container_host_ip(), pg.get_exposed_port(5432), pg.dbname
        owner = _libpq(pg.username, pg.password, host, port, db)
        with psycopg.connect(owner, autocommit=True) as c:
            c.execute("CREATE SCHEMA analytics")
            c.execute(
                "CREATE TABLE public.people "
                "(id int PRIMARY KEY, name text, score numeric, created_at timestamptz)"
            )
            c.execute(
                "INSERT INTO public.people "
                "SELECT g, 'user' || g, g * 1.5, now() FROM generate_series(1, 50) g"
            )
            # A table the reader is NOT granted and that is NOT allowlisted.
            c.execute("CREATE TABLE analytics.secret_costs (id int, amount numeric)")
            c.execute(
                f"CREATE ROLE {READER_USER} LOGIN PASSWORD '{READER_PW}' "
                "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"
            )
            c.execute(f"GRANT CONNECT ON DATABASE {db} TO {READER_USER}")
            c.execute(f"GRANT USAGE ON SCHEMA public TO {READER_USER}")
            c.execute(f"GRANT SELECT ON public.people TO {READER_USER}")
        yield SimpleNamespace(
            host=host,
            port=int(port),
            db=db,
            owner_libpq=owner,
            owner_user=pg.username,
            owner_pw=pg.password,
        )


def _config(ext: SimpleNamespace, **over: object) -> PostgresConnectorConfig:
    base: dict[str, object] = {
        "host": ext.host,
        "port": ext.port,
        "database": ext.db,
        "sslmode": "disable",
        "allowed_schemas": ["public"],
        "allowed_tables": ["public.people"],
    }
    base.update(over)
    return PostgresConnectorConfig.model_validate(base)


def _reader_secret() -> PostgresSecret:
    return parse_secret(json.dumps({"username": READER_USER, "password": READER_PW}))


# --- Platform-side helpers (mirror the M4 connector-execution tests) ---


def _seed_pg_connector(
    ext: SimpleNamespace,
    owner_libpq: str,
    tenant_id: uuid.UUID,
    *,
    name: str = "pgdemo",
    status: str = "unchecked",
    config_over: dict[str, object] | None = None,
) -> uuid.UUID:
    cid = uuid.uuid4()
    config: dict[str, object] = {
        "host": ext.host,
        "port": ext.port,
        "database": ext.db,
        "sslmode": "disable",
        "allowed_schemas": ["public"],
        "allowed_tables": ["public.people"],
    }
    if config_over:
        config.update(config_over)
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO connectors (id, tenant_id, type, name, config, secret_ref, status) "
            "VALUES (%s,%s,'postgres',%s,%s::jsonb,%s,%s)",
            (cid, tenant_id, name, json.dumps(config), SECRET_REF, status),
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


def _store(
    tenant_id: uuid.UUID, username: str = READER_USER, password: str = READER_PW
) -> EnvironmentSecretStore:
    return EnvironmentSecretStore(
        {
            env_key_for(tenant_id, SECRET_REF): json.dumps(
                {"username": username, "password": password}
            )
        }
    )


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


def _query_plan(sql: str, connector: str = "pgdemo") -> WorkflowPlan:
    return WorkflowPlan.model_validate(
        {
            "steps": [
                {"id": "q", "tool": "postgres.query", "args": {"sql": sql}, "connector": connector}
            ]
        }
    )


# =========================================================================
# Layer proofs (direct driver path — independent of the engine)
# =========================================================================


def test_layer2_read_only_session_blocks_writes_even_for_a_writer(ext_pg: SimpleNamespace) -> None:
    """The read-only SESSION blocks writes regardless of role privileges."""
    owner_secret = parse_secret(
        json.dumps({"username": ext_pg.owner_user, "password": ext_pg.owner_pw})
    )
    with (
        read_only_connection(_config(ext_pg), owner_secret) as conn,
        conn.cursor() as cur,
        pytest.raises(psycopg.Error),
    ):
        cur.execute("INSERT INTO public.people (id, name) VALUES (999, 'x')")


def test_layer3_select_only_role_blocks_writes(ext_pg: SimpleNamespace) -> None:
    """The reader ROLE cannot write even in an ordinary (writable) session."""
    reader = _libpq(READER_USER, READER_PW, ext_pg.host, ext_pg.port, ext_pg.db)
    with (
        psycopg.connect(reader, autocommit=True) as conn,
        conn.cursor() as cur,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        cur.execute("INSERT INTO public.people (id, name) VALUES (998, 'y')")


def test_statement_timeout_enforced(ext_pg: SimpleNamespace) -> None:
    cfg = _config(ext_pg, statement_timeout_ms=200)
    with pytest.raises(PostgresTimeoutError):
        # Bypasses layer 1 on purpose to exercise the driver timeout directly.
        run_read_only_query(cfg, _reader_secret(), "SELECT pg_sleep(3)")


def test_row_cap_truncates(ext_pg: SimpleNamespace) -> None:
    cfg = _config(ext_pg, max_rows=10)
    result = run_read_only_query(cfg, _reader_secret(), "SELECT id FROM public.people")
    assert len(result.rows) == 10
    assert result.truncated is True


def test_user_limit_cannot_exceed_max_rows(ext_pg: SimpleNamespace) -> None:
    cfg = _config(ext_pg, max_rows=5)
    result = run_read_only_query(cfg, _reader_secret(), "SELECT id FROM public.people LIMIT 999999")
    assert len(result.rows) == 5
    assert result.truncated is True


def test_byte_cap_enforced(ext_pg: SimpleNamespace) -> None:
    cfg = _config(ext_pg, max_result_bytes=50)
    with pytest.raises(ResultTooLargeError):
        run_read_only_query(cfg, _reader_secret(), "SELECT id, name FROM public.people")


def test_auth_failure_raises_typed_error_without_credentials(ext_pg: SimpleNamespace) -> None:
    bad = parse_secret(json.dumps({"username": READER_USER, "password": "wrong-pw"}))
    with pytest.raises(PostgresAuthError) as exc:
        run_read_only_query(_config(ext_pg), bad, "SELECT 1 FROM public.people")
    assert "wrong-pw" not in str(exc.value)


def test_normalized_scalar_types_roundtrip(ext_pg: SimpleNamespace) -> None:
    result = run_read_only_query(
        _config(ext_pg), _reader_secret(), "SELECT id, name, score FROM public.people WHERE id = 2"
    )
    assert result.columns == ["id", "name", "score"]
    assert result.rows[0][0] == 2
    assert result.rows[0][1] == "user2"
    assert result.rows[0][2] == "3.0"  # numeric -> lossless string


# =========================================================================
# Engine end-to-end
# =========================================================================


def test_query_through_engine_and_health_transition(
    pg_stack: SimpleNamespace, ext_pg: SimpleNamespace
) -> None:
    m = pg_stack.seed_member()
    cid = _seed_pg_connector(ext_pg, pg_stack.owner_libpq, m.tenant_id)  # unchecked
    plan = _query_plan("SELECT id, name FROM public.people ORDER BY id LIMIT 3")
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, plan)

    with structlog.testing.capture_logs() as logs:
        assert execute_advancement(_worker_sm(pg_stack), run_id, _store(m.tenant_id)).result == (
            "advanced"
        )

    steps = _steps(pg_stack.owner_libpq, run_id)
    status, output, error = steps["q"]
    assert status == "SUCCESS"
    assert output == {
        "columns": ["id", "name"],
        "rows": [[1, "user1"], [2, "user2"], [3, "user3"]],
        "row_count": 3,
        "truncated": False,
    }
    # unchecked -> health-checked -> active
    assert _connector_status(pg_stack.owner_libpq, cid) == "active"

    # Credential never leaks across any surface the worker touched.
    log_blob = json.dumps(logs, default=str)
    with psycopg.connect(pg_stack.owner_libpq) as c:
        conn_dump = str(c.execute("SELECT config, secret_ref FROM connectors").fetchall())
        io_dump = str(
            c.execute(
                "SELECT input, output, error FROM step_runs WHERE run_id=%s", (run_id,)
            ).fetchall()
        )
    for surface in (json.dumps(steps, default=str), log_blob, conn_dump, io_dump):
        assert READER_PW not in surface


def test_forbidden_sql_fails_step_but_keeps_connector_healthy(
    pg_stack: SimpleNamespace, ext_pg: SimpleNamespace
) -> None:
    m = pg_stack.seed_member()
    cid = _seed_pg_connector(ext_pg, pg_stack.owner_libpq, m.tenant_id)
    # Health check (SELECT 1) succeeds, but the validator rejects the query.
    plan = _query_plan("DELETE FROM public.people")
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, plan)
    assert execute_advancement(_worker_sm(pg_stack), run_id, _store(m.tenant_id)).result == "failed"
    assert _steps(pg_stack.owner_libpq, run_id)["q"][0] == "FAILED"
    assert _connector_status(pg_stack.owner_libpq, cid) == "active"


def test_non_allowlisted_table_fails_step(
    pg_stack: SimpleNamespace, ext_pg: SimpleNamespace
) -> None:
    m = pg_stack.seed_member()
    _seed_pg_connector(ext_pg, pg_stack.owner_libpq, m.tenant_id)
    plan = _query_plan("SELECT * FROM analytics.secret_costs")
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, plan)
    assert execute_advancement(_worker_sm(pg_stack), run_id, _store(m.tenant_id)).result == "failed"


def test_bad_credentials_mark_connector_error(
    pg_stack: SimpleNamespace, ext_pg: SimpleNamespace
) -> None:
    m = pg_stack.seed_member()
    cid = _seed_pg_connector(ext_pg, pg_stack.owner_libpq, m.tenant_id)  # unchecked
    plan = _query_plan("SELECT id FROM public.people")
    run_id = _seed_run(pg_stack, m.user_id, m.tenant_id, plan)
    # Health check fails auth -> connector flips to error, step fails deterministically.
    bad_store = _store(m.tenant_id, password="wrong-pw")
    assert execute_advancement(_worker_sm(pg_stack), run_id, bad_store).result == "failed"
    assert _connector_status(pg_stack.owner_libpq, cid) == "error"
    assert "wrong-pw" not in str(_steps(pg_stack.owner_libpq, run_id))


def test_cross_tenant_cannot_use_connector(
    pg_stack: SimpleNamespace, ext_pg: SimpleNamespace
) -> None:
    a, b = pg_stack.seed_member(), pg_stack.seed_member()
    _seed_pg_connector(ext_pg, pg_stack.owner_libpq, a.tenant_id)  # owned by A only
    plan = _query_plan("SELECT id FROM public.people")
    run_b = _seed_run(pg_stack, b.user_id, b.tenant_id, plan)
    # B references connector name "pgdemo" it does not own -> fails (RLS-scoped lookup).
    assert execute_advancement(_worker_sm(pg_stack), run_b, _store(b.tenant_id)).result == "failed"
