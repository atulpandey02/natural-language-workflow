"""Shared integration fixtures.

``pg_stack`` starts a throwaway Postgres, bootstraps the restricted ``nlw_app``
role (mirroring the docker init script), applies the real Alembic migrations as
the owner (so grants + RLS policies are exactly what ships), and hands back
settings in which the application connects as ``nlw_app``.
"""

from collections.abc import Iterator
from types import SimpleNamespace

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from testcontainers.community.postgres import PostgresContainer

from nlw.core.config import Settings

APP_ROLE = "nlw_app"
APP_PASSWORD = "nlw_app"


def _libpq(user: str, password: str, host: str, port: str | int, db: str) -> str:
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"


def _sqlalchemy(user: str, password: str, host: str, port: str | int, db: str) -> str:
    return f"postgresql+psycopg://{user}:{password}@{host}:{port}/{db}"


@pytest.fixture
def pg_stack() -> Iterator[SimpleNamespace]:
    with PostgresContainer("postgres:16") as pg:
        host, port = pg.get_container_host_ip(), pg.get_exposed_port(5432)
        owner_user, owner_password, db = pg.username, pg.password, pg.dbname
        owner_libpq = _libpq(owner_user, owner_password, host, port, db)
        owner_sa = _sqlalchemy(owner_user, owner_password, host, port, db)
        app_sa = _sqlalchemy(APP_ROLE, APP_PASSWORD, host, port, db)

        # Bootstrap the restricted role (as owner) — mirrors docker init script.
        with psycopg.connect(owner_libpq, autocommit=True) as conn:
            conn.execute(
                f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{APP_ROLE}') "
                f"THEN CREATE ROLE {APP_ROLE} LOGIN PASSWORD '{APP_PASSWORD}' "
                f"NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT; END IF; END $$;"
            )
            conn.execute(f"GRANT CONNECT ON DATABASE {db} TO {APP_ROLE}")
            conn.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}")

        # Apply the real migrations as owner (tables + grants + RLS policies).
        cfg = Config("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", owner_sa)
        command.upgrade(cfg, "head")

        settings = Settings(  # type: ignore[call-arg]
            _env_file=None,
            database_url=app_sa,
            database_migration_url=owner_sa,
            supabase_url="https://proj.supabase.co",
            supabase_jwt_secret="dev-secret-for-tests-32bytes-min-length",
        )
        yield SimpleNamespace(
            settings=settings,
            owner_libpq=owner_libpq,
            app_libpq=_libpq(APP_ROLE, APP_PASSWORD, host, port, db),
        )
