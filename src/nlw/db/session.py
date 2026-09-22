"""Async database engine and session helpers.

The application layer uses an async engine (psycopg v3). Alembic uses a sync
engine over the same URL — see ``migrations/env.py``.

Engines are pool-sized and timeout-bounded (M9): a bounded pool prevents
connection exhaustion, and server-side ``statement_timeout`` /
``idle_in_transaction_session_timeout`` / ``lock_timeout`` cap runaway queries
and stuck transactions independently of any application-level timeout.
"""

from typing import Any

import structlog
from sqlalchemy import Engine, event, text
from sqlalchemy import create_engine as _sa_create_engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker

from nlw.core.config import Settings

log = structlog.get_logger(__name__)


def _server_settings_options(settings: Settings) -> str:
    """libpq ``options`` string applying per-connection server-side timeouts."""
    return (
        f"-c statement_timeout={settings.db_statement_timeout_ms} "
        f"-c lock_timeout={settings.db_lock_timeout_ms} "
        f"-c idle_in_transaction_session_timeout={settings.db_idle_in_tx_timeout_ms}"
    )


def _install_context_reset(engine: Engine) -> None:
    """Defence in depth for signed context (P3B): on every pool check-in, after the
    default rollback, ``RESET ALL`` so NO session-level setting (``app.*`` or
    otherwise) can survive into the next checkout. Signed context is always
    transaction-local, so this only matters if something ever sets a session-level
    value — in which case a reused connection would otherwise "revert" to the leaked
    value instead of to nothing. A connection that cannot be reset is invalidated
    rather than returned to the pool. Server-side timeouts arrive via libpq
    ``options`` (connection-start defaults) and are unaffected by RESET.
    """

    @event.listens_for(engine.pool, "reset")
    def _reset(dbapi_connection: Any, connection_record: Any, reset_state: Any) -> None:
        # A reset listener REPLACES the pool's default rollback, so: end whatever
        # transaction is open, RESET ALL, and COMMIT that statement — psycopg opens
        # an implicit transaction for the RESET, and an uncommitted RESET would be
        # rolled back later, silently restoring the leaked session value.
        try:
            dbapi_connection.rollback()
            cursor = dbapi_connection.cursor()
            cursor.execute("RESET ALL")
            cursor.close()
            dbapi_connection.commit()
        except Exception as exc:  # pragma: no cover - driver/network failure
            log.warning("db.context_reset_failed", error_class=type(exc).__name__)
            connection_record.invalidate(exc)


def create_engine(settings: Settings) -> AsyncEngine:
    """Create the async engine with a bounded pool and server-side timeouts."""
    engine = create_async_engine(
        settings.database_url,
        pool_pre_ping=True,  # avoid handing out dead connections
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout_s,
        pool_recycle=settings.db_pool_recycle_s,
        connect_args={"options": _server_settings_options(settings)},
    )
    _install_context_reset(engine.sync_engine)
    return engine


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create a session factory bound to ``engine``."""
    return async_sessionmaker(engine, expire_on_commit=False)


def create_sync_engine(settings: Settings) -> Engine:
    """Create a synchronous engine for the worker/scheduler (sync actors/loops)."""
    engine = _sa_create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout_s,
        pool_recycle=settings.db_pool_recycle_s,
        connect_args={"options": _server_settings_options(settings)},
    )
    _install_context_reset(engine)
    return engine


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
