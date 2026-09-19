"""Atomic Redis fixed-window rate limiter (M9, ADR-017, req 2).

Increment, first-use expiry, and TTL read happen in ONE atomic server-side Lua
script — there is no INCR-then-EXPIRE crash window that could leak an
unexpiring counter. Counters are non-durable control state: losing them on a
Redis reset only resets the current window, which is acceptable.

Cost-bearing / mutating endpoints fail CLOSED when the backend is unavailable
(``fail_open=False``): a Redis outage must not open an abuse window.
"""

import redis.asyncio as aioredis
from redis.commands.core import AsyncScript

# Returns {current_count, ttl_seconds}. Single atomic evaluation.
_LUA = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return {current, ttl}
"""


class RateLimitExceeded(Exception):
    """The caller exceeded the window limit."""

    def __init__(self, retry_after: int) -> None:
        super().__init__("rate limit exceeded")
        self.retry_after = retry_after


class RateLimitBackendError(Exception):
    """The rate-limit backend (Redis) is unavailable."""


class RateLimiter:
    def __init__(self, redis_client: aioredis.Redis, *, window_s: int, fail_open: bool) -> None:
        self._redis = redis_client
        self._window_s = window_s
        self._fail_open = fail_open
        self._script: AsyncScript = redis_client.register_script(_LUA)

    async def check(self, key: str, limit: int) -> None:
        """Count one hit against ``key``; raise if over ``limit``.

        Raises ``RateLimitExceeded`` (with retry-after) when over the limit, or
        ``RateLimitBackendError`` when the backend is down and ``fail_open`` is
        False. When ``fail_open`` is True a backend error is swallowed (allow).
        """
        try:
            current, ttl = await self._script(keys=[key], args=[self._window_s])
        except Exception as exc:  # backend unavailable
            if self._fail_open:
                return
            raise RateLimitBackendError() from exc
        if int(current) > limit:
            # A first-hit race could momentarily leave ttl == -1; clamp to window.
            retry_after = int(ttl) if int(ttl) > 0 else self._window_s
            raise RateLimitExceeded(retry_after=retry_after)
