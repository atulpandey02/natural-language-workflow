"""Shared integration fixtures.

``pg_stack`` starts a throwaway Postgres, bootstraps the runtime roles
(nlw_app, nlw_worker, and the non-login nlw_rls_bypass) exactly as the docker
init script / CI do, applies the real Alembic migrations as the owner, and hands
back settings for both the API role (nlw_app) and the worker role (nlw_worker).
"""

import uuid
from collections.abc import Iterator
from types import SimpleNamespace

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from testcontainers.community.postgres import PostgresContainer

from nlw.core.config import Settings

_SUPABASE_URL = "https://proj.supabase.co"
_SECRET = "dev-secret-for-tests-32bytes-min-length"


def _libpq(user: str, password: str, host: str, port: str | int, db: str) -> str:
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"


def _sqlalchemy(user: str, password: str, host: str, port: str | int, db: str) -> str:
    return f"postgresql+psycopg://{user}:{password}@{host}:{port}/{db}"


def _bootstrap_roles(owner_libpq: str, db: str) -> None:
    with psycopg.connect(owner_libpq, autocommit=True) as conn:
        conn.execute(
            "DO $$ BEGIN "
            "IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='nlw_app') THEN "
            "CREATE ROLE nlw_app LOGIN PASSWORD 'nlw_app' "
            "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT; END IF; "
            "IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='nlw_worker') THEN "
            "CREATE ROLE nlw_worker LOGIN PASSWORD 'nlw_worker' "
            "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT; END IF; "
            "IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='nlw_scheduler') THEN "
            "CREATE ROLE nlw_scheduler LOGIN PASSWORD 'nlw_scheduler' "
            "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT; END IF; "
            "IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='nlw_rls_bypass') THEN "
            "CREATE ROLE nlw_rls_bypass NOLOGIN NOSUPERUSER BYPASSRLS "
            "NOCREATEDB NOCREATEROLE; END IF; "
            "IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='nlw_workspace_bootstrap') THEN "
            "CREATE ROLE nlw_workspace_bootstrap NOLOGIN NOSUPERUSER BYPASSRLS "
            "NOCREATEDB NOCREATEROLE; END IF; END $$;"
        )
        for role in ("nlw_app", "nlw_worker", "nlw_scheduler"):
            conn.execute(f"GRANT CONNECT ON DATABASE {db} TO {role}")
            conn.execute(f"GRANT USAGE ON SCHEMA public TO {role}")
        conn.execute("GRANT nlw_rls_bypass TO CURRENT_USER")
        conn.execute("GRANT nlw_workspace_bootstrap TO CURRENT_USER")


@pytest.fixture
def pg_stack() -> Iterator[SimpleNamespace]:
    with PostgresContainer("postgres:16") as pg:
        host, port = pg.get_container_host_ip(), pg.get_exposed_port(5432)
        owner_user, owner_password, db = pg.username, pg.password, pg.dbname
        owner_libpq = _libpq(owner_user, owner_password, host, port, db)
        owner_sa = _sqlalchemy(owner_user, owner_password, host, port, db)
        app_sa = _sqlalchemy("nlw_app", "nlw_app", host, port, db)
        worker_sa = _sqlalchemy("nlw_worker", "nlw_worker", host, port, db)
        scheduler_sa = _sqlalchemy("nlw_scheduler", "nlw_scheduler", host, port, db)

        _bootstrap_roles(owner_libpq, db)

        cfg = Config("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", owner_sa)
        command.upgrade(cfg, "head")

        def _settings(url: str) -> Settings:
            return Settings(  # type: ignore[call-arg]
                _env_file=None,
                database_url=url,
                database_migration_url=owner_sa,
                supabase_url=_SUPABASE_URL,
                supabase_jwt_secret=_SECRET,
                # Rate limiting needs Redis; the general API fixtures don't run one.
                # Dedicated M9 tests build settings with it enabled + a real Redis.
                rate_limit_enabled=False,
            )

        def seed_user() -> uuid.UUID:
            """Insert a users row (as owner, bypassing RLS). Returns the user id."""
            uid = uuid.uuid4()
            with psycopg.connect(owner_libpq, autocommit=True) as conn:
                conn.execute(
                    "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s)",
                    (uid, f"sub-{uid}", f"{uid}@example.com"),
                )
            return uid

        def seed_member(role: str = "owner") -> SimpleNamespace:
            """Create a user + workspace + one membership with ``role`` (as owner)."""
            uid, tid = seed_user(), uuid.uuid4()
            with psycopg.connect(owner_libpq, autocommit=True) as conn:
                conn.execute(
                    "INSERT INTO workspaces (id, name, slug) VALUES (%s,%s,%s)",
                    (tid, "ws", f"ws-{tid}"),
                )
                conn.execute(
                    "INSERT INTO memberships (id, user_id, workspace_id, role) "
                    "VALUES (%s,%s,%s,%s)",
                    (uuid.uuid4(), uid, tid, role),
                )
            return SimpleNamespace(user_id=uid, tenant_id=tid)

        def add_membership(tenant_id: uuid.UUID, role: str) -> uuid.UUID:
            """Add a fresh user to an existing workspace with ``role`` (as owner).

            Returns the new user id. Lets a test have distinct member/admin/owner
            principals in the same tenant.
            """
            uid = seed_user()
            with psycopg.connect(owner_libpq, autocommit=True) as conn:
                conn.execute(
                    "INSERT INTO memberships (id, user_id, workspace_id, role) "
                    "VALUES (%s,%s,%s,%s)",
                    (uuid.uuid4(), uid, tenant_id, role),
                )
            return uid

        yield SimpleNamespace(
            settings=_settings(app_sa),
            worker_settings=_settings(worker_sa),
            scheduler_settings=_settings(scheduler_sa),
            owner_libpq=owner_libpq,
            owner_sa=owner_sa,
            app_libpq=_libpq("nlw_app", "nlw_app", host, port, db),
            worker_libpq=_libpq("nlw_worker", "nlw_worker", host, port, db),
            scheduler_libpq=_libpq("nlw_scheduler", "nlw_scheduler", host, port, db),
            seed_user=seed_user,
            seed_member=seed_member,
            add_membership=add_membership,
        )
