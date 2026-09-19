"""Container healthcheck for the worker/scheduler roles (M9, req 7).

Beyond "is the process alive", this proves the process can actually do its job:
PostgreSQL is reachable, Redis is reachable, and the process's own metrics port
is accepting connections (which only happens after the role has booted). Exit 0
when all checks pass, 1 otherwise. Reasons print to stderr (never a secret).

Usage: ``python -m nlw.ops.healthcheck``
"""

import socket
import sys

import psycopg
import redis

from nlw.core.config import Settings, get_settings


def _libpq_url(database_url: str) -> str:
    """SQLAlchemy URL -> libpq URL (drop the +driver suffix)."""
    return database_url.replace("+psycopg", "", 1)


def _check_postgres(settings: Settings) -> None:
    with psycopg.connect(_libpq_url(settings.database_url), connect_timeout=3) as conn:
        conn.execute("SELECT 1")


def _check_redis(settings: Settings) -> None:
    client = redis.from_url(settings.redis_url, socket_connect_timeout=3, socket_timeout=3)
    try:
        client.ping()
    finally:
        client.close()


def _check_metrics_port(settings: Settings) -> None:
    if not settings.metrics_enabled:
        return
    with socket.create_connection(("127.0.0.1", settings.metrics_port), timeout=3):
        pass


def main() -> int:
    settings = get_settings()
    checks = (
        ("postgres", _check_postgres),
        ("redis", _check_redis),
        ("metrics", _check_metrics_port),
    )
    for name, check in checks:
        try:
            check(settings)
        except Exception as exc:  # noqa: BLE001 - report class only, never secrets
            print(f"healthcheck {name} failed: {type(exc).__name__}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
