"""Readiness reports the real state of Postgres.

Spins a throwaway Postgres via testcontainers and asserts that ``/health/ready``
returns 200 when the database is reachable.
"""

import pytest
from fastapi.testclient import TestClient
from testcontainers.community.postgres import PostgresContainer

from nlw.api.app import create_app
from nlw.core.config import Settings

pytestmark = pytest.mark.integration


def test_ready_when_postgres_reachable() -> None:
    with PostgresContainer("postgres:16") as postgres:
        url = (
            f"postgresql+psycopg://{postgres.username}:{postgres.password}"
            f"@{postgres.get_container_host_ip()}:{postgres.get_exposed_port(5432)}"
            f"/{postgres.dbname}"
        )
        settings = Settings(_env_file=None, database_url=url)  # type: ignore[call-arg]
        with TestClient(create_app(settings)) as client:
            resp = client.get("/health/ready")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["checks"]["postgres"] == "ok"
