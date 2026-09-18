"""Readiness reflects the real state of Postgres and Redis.

Readiness is 200 only when both dependencies are reachable, and 503 otherwise,
with a per-dependency breakdown.
"""

import pytest
from fastapi.testclient import TestClient
from testcontainers.community.postgres import PostgresContainer
from testcontainers.community.redis import RedisContainer

from nlw.api.app import create_app
from nlw.core.config import Settings

pytestmark = pytest.mark.integration


def _pg_url(postgres: PostgresContainer) -> str:
    return (
        f"postgresql+psycopg://{postgres.username}:{postgres.password}"
        f"@{postgres.get_container_host_ip()}:{postgres.get_exposed_port(5432)}"
        f"/{postgres.dbname}"
    )


def test_ready_when_both_dependencies_reachable() -> None:
    with PostgresContainer("postgres:16") as postgres, RedisContainer("redis:7") as redis_c:
        redis_url = f"redis://{redis_c.get_container_host_ip()}:{redis_c.get_exposed_port(6379)}/0"
        settings = Settings(  # type: ignore[call-arg]
            _env_file=None,
            database_url=_pg_url(postgres),
            redis_url=redis_url,
        )
        with TestClient(create_app(settings)) as client:
            resp = client.get("/health/ready")

    assert resp.status_code == 200
    assert resp.json()["checks"] == {"postgres": "ok", "redis": "ok"}


def test_not_ready_when_redis_down() -> None:
    with PostgresContainer("postgres:16") as postgres:
        settings = Settings(  # type: ignore[call-arg]
            _env_file=None,
            database_url=_pg_url(postgres),
            redis_url="redis://127.0.0.1:1/0",  # unreachable port
        )
        with TestClient(create_app(settings)) as client:
            resp = client.get("/health/ready")

    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["postgres"] == "ok"
    assert body["checks"]["redis"] == "down"
