"""Live API recovery gate: three-valued state + bounded cache (addendum, no DB)."""

import asyncio
from typing import Any

from nlw.api.recovery_gate import RecoveryGate


class _FakeConn:
    def __init__(self, item: Any) -> None:
        self._item = item

    async def __aenter__(self) -> "_FakeConn":
        return self

    async def __aexit__(self, *a: object) -> bool:
        return False

    async def run_sync(self, fn: Any) -> Any:
        item = self._item
        if isinstance(item, BaseException):
            raise item
        if callable(item):
            return await item()
        return item


class _FakeEngine:
    """Returns the scripted result on each connect(); the last entry repeats."""

    def __init__(self, script: list[Any]) -> None:
        self.script = script
        self.calls = 0

    def connect(self) -> _FakeConn:
        self.calls += 1
        item = self.script[min(self.calls - 1, len(self.script) - 1)]
        return _FakeConn(item)


async def test_initial_state_is_unknown_before_any_check() -> None:
    gate = RecoveryGate(_FakeEngine(["ALLOWED"]), ttl_s=10, query_timeout_s=1)
    assert gate.state == "UNKNOWN"  # never ALLOWED until proven


async def test_reachable_no_event_or_enabled_is_allowed() -> None:
    gate = RecoveryGate(_FakeEngine(["ALLOWED"]), ttl_s=10, query_timeout_s=1)
    assert await gate.check() == "ALLOWED"


async def test_locked_is_locked() -> None:
    gate = RecoveryGate(_FakeEngine(["LOCKED"]), ttl_s=10, query_timeout_s=1)
    assert await gate.check() == "LOCKED"


async def test_connection_failure_is_unknown_fail_closed() -> None:
    gate = RecoveryGate(_FakeEngine([RuntimeError("no db")]), ttl_s=10, query_timeout_s=1)
    assert await gate.check() == "UNKNOWN"


async def test_query_timeout_is_unknown_fail_closed() -> None:
    async def _slow() -> str:
        await asyncio.sleep(0.5)
        return "ALLOWED"

    gate = RecoveryGate(_FakeEngine([_slow]), ttl_s=10, query_timeout_s=0.05)
    assert await gate.check() == "UNKNOWN"


async def test_cache_throttles_queries_within_ttl() -> None:
    engine = _FakeEngine(["ALLOWED", "LOCKED"])
    gate = RecoveryGate(engine, ttl_s=10, query_timeout_s=1)
    assert await gate.check() == "ALLOWED"
    assert await gate.check() == "ALLOWED"  # cached; no second query
    assert engine.calls == 1


async def test_relock_detected_after_ttl_without_restart() -> None:
    engine = _FakeEngine(["ALLOWED", "LOCKED"])
    gate = RecoveryGate(engine, ttl_s=0.05, query_timeout_s=1)
    assert await gate.check() == "ALLOWED"
    await asyncio.sleep(0.08)  # let the cache go stale
    assert await gate.check() == "LOCKED"  # re-read picks up the later generation
    assert engine.calls == 2


async def test_stale_allowed_fails_closed_when_db_lost() -> None:
    # ALLOWED then the DB becomes unreachable -> after the TTL the next check is UNKNOWN.
    engine = _FakeEngine(["ALLOWED", RuntimeError("db gone")])
    gate = RecoveryGate(engine, ttl_s=0.05, query_timeout_s=1)
    assert await gate.check() == "ALLOWED"
    await asyncio.sleep(0.08)
    assert await gate.check() == "UNKNOWN"


async def test_single_flight_refresh_under_concurrency() -> None:
    engine = _FakeEngine(["ALLOWED"])
    gate = RecoveryGate(engine, ttl_s=10, query_timeout_s=1)
    results = await asyncio.gather(*(gate.check() for _ in range(10)))
    assert results == ["ALLOWED"] * 10
    assert engine.calls == 1  # concurrent callers share one refresh
