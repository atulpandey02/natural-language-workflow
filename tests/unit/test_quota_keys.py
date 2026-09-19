"""Advisory-lock keying + count statements for per-tenant caps (M9)."""

import uuid

from nlw.db.quota import (
    QuotaExceededError,
    _lock_key,
    connectors_count_stmt,
    schedules_count_stmt,
    workflows_count_stmt,
)


def test_lock_key_is_stable_and_resource_scoped() -> None:
    t = uuid.uuid4()
    assert _lock_key("connectors", t) == _lock_key("connectors", t)  # deterministic
    assert _lock_key("connectors", t) != _lock_key("schedules", t)  # resource-scoped
    assert _lock_key("connectors", t) != _lock_key("connectors", uuid.uuid4())  # tenant-scoped
    # Must fit a Postgres bigint (signed 64-bit).
    assert -(2**63) <= _lock_key("connectors", t) < 2**63


def test_count_statements_build() -> None:
    t = uuid.uuid4()
    for stmt in (connectors_count_stmt(t), schedules_count_stmt(t), workflows_count_stmt(t)):
        assert "count" in str(stmt).lower()


def test_quota_error_carries_resource_and_cap() -> None:
    err = QuotaExceededError("connectors", 50)
    assert err.resource == "connectors" and err.cap == 50
    assert "50" in str(err)
