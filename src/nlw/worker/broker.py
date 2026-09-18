"""Dramatiq broker construction and Redis health check.

Redis is transport only (ADR-002); durable workflow state lives in Postgres.
This module is intentionally side-effect free: it builds a broker on request
and probes Redis for readiness. The global broker is set in ``nlw.worker.actors``
(imported by the worker entrypoint), so the API can import ``check_redis`` here
without pulling in that global configuration.
"""

import redis.asyncio as aioredis
from dramatiq.brokers.redis import RedisBroker

from nlw.core.config import Settings


def make_broker(settings: Settings) -> RedisBroker:
    """Build a Redis-backed Dramatiq broker for ``settings.redis_url``."""
    # dramatiq ships py.typed but leaves RedisBroker.__init__ unannotated.
    return RedisBroker(url=settings.redis_url)  # type: ignore[no-untyped-call]


async def check_redis(settings: Settings) -> None:
    """Ping Redis to verify reachability. Raises on failure (readiness signal).

    Short timeouts keep the readiness endpoint from hanging when Redis is down.
    """
    client = aioredis.from_url(
        settings.redis_url,
        socket_connect_timeout=2,
        socket_timeout=2,
    )
    try:
        await client.ping()
    finally:
        await client.aclose()
