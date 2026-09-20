"""The hardened role bootstrap (docker/postgres/initdb/00-roles.sh) creates the
runtime roles with STRONG, env-supplied passwords on a fresh Postgres volume.

Runs the ACTUAL init script inside postgres:16 (mounted as an initdb hook) and
proves per-role authentication, cross-password rejection, and that the role
security properties are unchanged (PR2 regression tests B–F).
"""

from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

pytestmark = pytest.mark.integration

_INITDB = str(Path(__file__).resolve().parents[2] / "docker" / "postgres" / "initdb")

# Strong, distinct, URL-safe test passwords (NOT the old weak defaults).
_OWNER_PW = "owner_pw_5f4dcc3b5aa765d6"
_APP_PW = "app_pw_2c1743a391305fbf"
_WORKER_PW = "worker_pw_098f6bcd4621d373"
_SCHEDULER_PW = "scheduler_pw_ad0234829205b9033"


@pytest.fixture(scope="module")
def bootstrapped() -> Iterator[SimpleNamespace]:
    container = (
        PostgresContainer("postgres:16", username="nlw", password=_OWNER_PW, dbname="nlw")
        .with_env("NLW_APP_DB_PASSWORD", _APP_PW)
        .with_env("NLW_WORKER_DB_PASSWORD", _WORKER_PW)
        .with_env("NLW_SCHEDULER_DB_PASSWORD", _SCHEDULER_PW)
        .with_volume_mapping(_INITDB, "/docker-entrypoint-initdb.d", "ro")
    )
    with container as pg:
        yield SimpleNamespace(
            host=pg.get_container_host_ip(),
            port=pg.get_exposed_port(5432),
            db=pg.dbname,
        )


def _connect(info: SimpleNamespace, user: str, password: str) -> psycopg.Connection:
    return psycopg.connect(
        f"postgresql://{user}:{password}@{info.host}:{info.port}/{info.db}",
        autocommit=True,
    )


# B: a fresh bootstrap with all required values succeeds (fixture came up) and
#    C: each login role authenticates with its OWN supplied password.
@pytest.mark.parametrize(
    "role,password",
    [("nlw_app", _APP_PW), ("nlw_worker", _WORKER_PW), ("nlw_scheduler", _SCHEDULER_PW)],
)
def test_role_authenticates_with_own_password(
    bootstrapped: SimpleNamespace, role: str, password: str
) -> None:
    with _connect(bootstrapped, role, password) as conn:
        assert conn.execute("SELECT 1").fetchone() == (1,)


# D: cross-password authentication does not succeed.
@pytest.mark.parametrize(
    "role,wrong_password",
    [
        ("nlw_app", _WORKER_PW),
        ("nlw_worker", _SCHEDULER_PW),
        ("nlw_scheduler", _APP_PW),
    ],
)
def test_cross_password_authentication_fails(
    bootstrapped: SimpleNamespace, role: str, wrong_password: str
) -> None:
    with pytest.raises(psycopg.OperationalError):
        _connect(bootstrapped, role, wrong_password)


# E: login roles keep their least-privilege attributes.
def test_login_role_attributes(bootstrapped: SimpleNamespace) -> None:
    with _connect(bootstrapped, "nlw", _OWNER_PW) as conn:
        rows = conn.execute(
            "SELECT rolname, rolcanlogin, rolsuper, rolbypassrls, rolcreatedb, "
            "rolcreaterole, rolinherit FROM pg_roles "
            "WHERE rolname IN ('nlw_app','nlw_worker','nlw_scheduler') ORDER BY rolname"
        ).fetchall()
    assert len(rows) == 3
    for rolname, canlogin, super_, bypassrls, createdb, createrole, inherit in rows:
        assert canlogin is True, rolname
        assert super_ is False, rolname
        assert bypassrls is False, rolname
        assert createdb is False, rolname
        assert createrole is False, rolname
        assert inherit is False, rolname  # NOINHERIT


# F: helper roles remain NOLOGIN (with their documented BYPASSRLS behavior).
def test_helper_roles_are_nologin(bootstrapped: SimpleNamespace) -> None:
    with _connect(bootstrapped, "nlw", _OWNER_PW) as conn:
        rows: dict[str, bool] = dict(
            conn.execute(
                "SELECT rolname, rolcanlogin FROM pg_roles "
                "WHERE rolname IN ('nlw_rls_bypass','nlw_workspace_bootstrap')"
            ).fetchall()
        )
        bypass = conn.execute(
            "SELECT rolbypassrls FROM pg_roles WHERE rolname IN "
            "('nlw_rls_bypass','nlw_workspace_bootstrap')"
        ).fetchall()
    assert rows == {"nlw_rls_bypass": False, "nlw_workspace_bootstrap": False}
    assert all(b == (True,) for b in bypass)
