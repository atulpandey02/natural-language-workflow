"""Async database engine and session helpers.

The application layer uses an async engine (psycopg v3). Alembic uses a sync
engine over the same URL — see ``migrations/env.py``.
"""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from nlw.core.config import Settings


def create_engine(settings: Settings) -> AsyncEngine:
    """Create the async engine. ``pool_pre_ping`` avoids handing out dead conns."""
    return create_async_engine(settings.database_url, pool_pre_ping=True)


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create a session factory bound to ``engine``."""
    return async_sessionmaker(engine, expire_on_commit=False)


async def check_connection(engine: AsyncEngine) -> None:
    """Run a trivial query to verify the database is reachable.

    Raises whatever SQLAlchemy raises on failure; callers translate that into a
    readiness signal.
    """
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
