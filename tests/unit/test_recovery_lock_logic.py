"""Recovery-lock evaluation + fail-closed logic (M11.5 P2 addendum, no DB)."""

from typing import Any

import pytest
from sqlalchemy.exc import SQLAlchemyError

from nlw.backup.recovery_lock import (
    RecoveryLocked,
    RecoveryStateUnknown,
    _evaluate,
    assert_startup_allowed_sync,
    check_recovery_lock,
)


def test_no_event_allows_startup() -> None:
    _evaluate(None)  # never restored -> allowed, no raise


def test_quiesced_not_validated_blocks() -> None:
    with pytest.raises(RecoveryLocked, match="not validated"):
        _evaluate(("gen-1", None, None))  # type: ignore[arg-type]


def test_validated_not_enabled_blocks() -> None:
    with pytest.raises(RecoveryLocked, match="not operator-enabled"):
        _evaluate(("gen-1", "2026-01-01", None))  # type: ignore[arg-type]


def test_validated_and_enabled_allows() -> None:
    _evaluate(("gen-1", "2026-01-01", "2026-01-02"))  # type: ignore[arg-type]


def test_malformed_event_fails_closed() -> None:
    with pytest.raises(RecoveryStateUnknown):
        _evaluate((None, None, None))  # type: ignore[arg-type]


class _RaisingConn:
    def execute(self, *a: Any, **k: Any) -> Any:
        raise SQLAlchemyError("permission denied / missing columns")


def test_query_failure_fails_closed() -> None:
    with pytest.raises(RecoveryStateUnknown):
        check_recovery_lock(_RaisingConn())  # type: ignore[arg-type]


class _RaisingEngine:
    def connect(self) -> Any:
        raise SQLAlchemyError("cannot connect")


def test_connection_failure_fails_closed() -> None:
    with pytest.raises(RecoveryStateUnknown):
        assert_startup_allowed_sync(_RaisingEngine())  # type: ignore[arg-type]
