"""Async database engine and session helpers.

The application layer uses an async engine (psycopg v3). Alembic uses a sync
engine over the same URL — see ``migrations/env.py``.

Engines are pool-sized and timeout-bounded (M9): a bounded pool prevents
connection exhaustion, and server-side ``statement_timeout`` /
``idle_in_transaction_session_timeout`` / ``lock_timeout`` cap runaway queries
and stuck transactions independently of any application-level timeout.
"""

from sqlalchemy import Engine, text
from sqlalchemy import create_engine as _sa_create_engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker

from nlw.core.config import Settings


def _server_settings_options(settings: Settings) -> str:
    """libpq ``options`` string applying per-connection server-side timeouts."""
    return (
        f"-c statement_timeout={settings.db_statement_timeout_ms} "
        f"-c lock_timeout={settings.db_lock_timeout_ms} "
        f"-c idle_in_transaction_session_timeout={settings.db_idle_in_tx_timeout_ms}"
    )


def create_engine(settings: Settings) -> AsyncEngine:
    """Create the async engine with a bounded pool and server-side timeouts."""
    return create_async_engine(
        settings.database_url,
        pool_pre_ping=True,  # avoid handing out dead connections
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout_s,
        pool_recycle=settings.db_pool_recycle_s,
        connect_args={"options": _server_settings_options(settings)},
    )


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create a session factory bound to ``engine``."""
    return async_sessionmaker(engine, expire_on_commit=False)


def create_sync_engine(settings: Settings) -> Engine:
    """Create a synchronous engine for the worker/scheduler (sync actors/loops)."""
    return _sa_create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout_s,
        pool_recycle=settings.db_pool_recycle_s,
        connect_args={"options": _server_settings_options(settings)},
    )


def create_sync_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    """Create a synchronous session factory bound to ``engine``."""
    return sessionmaker(engine, expire_on_commit=False)


async def check_connection(engine: AsyncEngine) -> None:
    """Run a trivial query to verify the database is reachable.

    Raises whatever SQLAlchemy raises on failure; callers translate that into a
    readiness signal.
    """
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
