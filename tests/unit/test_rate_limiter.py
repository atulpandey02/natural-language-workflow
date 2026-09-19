"""RateLimiter contract (M9): over-limit rejection + fail-closed/open backend.

Redis-level atomicity and cross-process concurrency are proven with a real Redis
in the integration suite; here we drive the limiter against a controllable fake.
"""

import pytest

from nlw.ratelimit.limiter import RateLimitBackendError, RateLimiter, RateLimitExceeded


class _FakeScript:
    def __init__(self, store: dict[str, int]) -> None:
        self.store = store

    async def __call__(self, keys: list[str], args: list[int]) -> list[int]:
        key, window = keys[0], int(args[0])
        self.store[key] = self.store.get(key, 0) + 1
        return [self.store[key], window]


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, int] = {}

    def register_script(self, lua: str) -> _FakeScript:
        return _FakeScript(self.store)


class _BoomScript:
    async def __call__(self, keys: list[str], args: list[int]) -> list[int]:
        raise ConnectionError("redis down")


class _BoomRedis:
    def register_script(self, lua: str) -> _BoomScript:
        return _BoomScript()


async def test_allows_up_to_limit_then_rejects() -> None:
    limiter = RateLimiter(_FakeRedis(), window_s=60, fail_open=False)  # type: ignore[arg-type]
    await limiter.check("k", limit=2)
    await limiter.check("k", limit=2)
    with pytest.raises(RateLimitExceeded) as exc:
        await limiter.check("k", limit=2)
    assert exc.value.retry_after == 60


async def test_distinct_keys_are_independent() -> None:
    limiter = RateLimiter(_FakeRedis(), window_s=60, fail_open=False)  # type: ignore[arg-type]
    await limiter.check("tenant", limit=1)
    await limiter.check("user", limit=1)  # different key => still allowed


async def test_fail_closed_on_backend_error() -> None:
    limiter = RateLimiter(_BoomRedis(), window_s=60, fail_open=False)  # type: ignore[arg-type]
    with pytest.raises(RateLimitBackendError):
        await limiter.check("k", limit=100)


async def test_fail_open_swallows_backend_error() -> None:
    limiter = RateLimiter(_BoomRedis(), window_s=60, fail_open=True)  # type: ignore[arg-type]
    await limiter.check("k", limit=100)  # must not raise
