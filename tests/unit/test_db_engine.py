"""Engine pool sizing + server-side timeout options (M9)."""

from sqlalchemy.pool import QueuePool

from nlw.core.config import Settings
from nlw.db.session import _server_settings_options, create_sync_engine


def _s(**over: object) -> Settings:
    base: dict[str, object] = {"_env_file": None}
    base.update(over)
    return Settings(**base)  # type: ignore[arg-type]


def test_options_string_carries_all_timeouts() -> None:
    opts = _server_settings_options(
        _s(db_statement_timeout_ms=12345, db_lock_timeout_ms=6789, db_idle_in_tx_timeout_ms=4242)
    )
    assert "statement_timeout=12345" in opts
    assert "lock_timeout=6789" in opts
    assert "idle_in_transaction_session_timeout=4242" in opts


def test_sync_engine_is_pool_sized() -> None:
    # Constructing an engine does not connect; the pool reports its configured size.
    engine = create_sync_engine(_s(db_pool_size=7, db_max_overflow=3))
    try:
        assert isinstance(engine.pool, QueuePool)
        assert engine.pool.size() == 7
    finally:
        engine.dispose()
