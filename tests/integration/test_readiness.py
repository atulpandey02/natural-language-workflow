"""Readiness reflects Postgres + Redis + schema compatibility (M9, req 10).

Readiness is 200 only when all three checks pass. It uses the migrated pg_stack
(so the schema is at the expected Alembic head) plus a real Redis, and a
per-dependency breakdown is always returned.
"""

from collections.abc import Iterator
from types import SimpleNamespace

import psycopg
import pytest
from fastapi.testclient import TestClient
from testcontainers.community.redis import RedisContainer

from nlw.api.app import create_app
from nlw.core.config import Settings

pytestmark = pytest.mark.integration


@pytest.fixture
def redis_url() -> Iterator[str]:
    with RedisContainer("redis:7") as c:
        yield f"redis://{c.get_container_host_ip()}:{c.get_exposed_port(6379)}/0"


def _settings(pg_stack: SimpleNamespace, **over: object) -> Settings:
    settings: Settings = pg_stack.settings.model_copy(update=over)
    return settings


def test_ready_when_all_dependencies_and_schema_ok(
    pg_stack: SimpleNamespace, redis_url: str
) -> None:
    with TestClient(create_app(_settings(pg_stack, redis_url=redis_url))) as client:
        resp = client.get("/health/ready")
    assert resp.status_code == 200
    assert resp.json()["checks"] == {
        "recovery": "ok",
        "postgres": "ok",
        "redis": "ok",
        "schema": "ok",
        # P3B: the API's signer and the database's key registry agree.
        "signed_context": "ok",
    }


def test_not_ready_when_redis_down(pg_stack: SimpleNamespace) -> None:
    with TestClient(create_app(_settings(pg_stack, redis_url="redis://127.0.0.1:1/0"))) as client:
        resp = client.get("/health/ready")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["postgres"] == "ok"
    assert body["checks"]["redis"] == "down"
    assert body["checks"]["schema"] == "ok"


def test_not_ready_when_schema_mismatch(pg_stack: SimpleNamespace, redis_url: str) -> None:
    # Simulate "deployed new image before running migrations": corrupt the
    # recorded revision so it no longer matches the expected head.
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as conn:
        conn.execute("UPDATE alembic_version SET version_num = 'not_the_head'")
    with TestClient(create_app(_settings(pg_stack, redis_url=redis_url))) as client:
        resp = client.get("/health/ready")
    assert resp.status_code == 503
    body = resp.json()
    assert body["checks"]["postgres"] == "ok"
    assert body["checks"]["redis"] == "ok"
    assert body["checks"]["schema"] == "down"
