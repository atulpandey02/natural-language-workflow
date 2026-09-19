"""Schema-compatibility check for readiness (M9, req 10).

Readiness must fail if the database schema is not at the migration revision this
code expects — this catches "deployed a new image before running migrations".

The expected Alembic head is read from the migration scripts ONCE and cached in
process (readiness must not rebuild migration metadata on every request). The
actual head is read from the database's ``alembic_version`` table.
"""

from functools import lru_cache

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine


class SchemaMismatchError(Exception):
    """The database schema revision does not match the expected head."""


@lru_cache(maxsize=1)
def expected_head() -> str:
    """The single Alembic head revision this code expects (cached)."""
    script = ScriptDirectory.from_config(Config("alembic.ini"))
    head = script.get_current_head()
    if head is None:  # pragma: no cover - repo always has migrations
        raise SchemaMismatchError("no migration head found in the migration scripts")
    return head


async def check_schema(engine: AsyncEngine) -> None:
    """Verify the DB is migrated to the expected head. Raises on mismatch.

    Callers translate the raise into a readiness signal. A missing
    ``alembic_version`` table (unmigrated DB) surfaces as a not-ready signal.
    """
    want = expected_head()
    async with engine.connect() as conn:
        got = (
            await conn.execute(text("SELECT version_num FROM alembic_version"))
        ).scalar_one_or_none()
    if got != want:
        # Never leak internals beyond the two revision ids (safe, non-secret).
        raise SchemaMismatchError(f"schema at {got!r}, expected {want!r}")
