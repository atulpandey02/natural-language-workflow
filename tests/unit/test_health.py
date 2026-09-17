"""Liveness and version endpoints work without any external dependency.

These use the app's lifespan (which creates the async engine but does not
connect), so no database is required. Readiness is covered in the integration
suite because it actually queries Postgres.
"""

from fastapi.testclient import TestClient

from nlw import __version__
from nlw.api.app import create_app
from nlw.core.config import Settings


def _client() -> TestClient:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    return TestClient(create_app(settings))


def test_health_liveness() -> None:
    with _client() as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_version() -> None:
    with _client() as client:
        resp = client.get("/version")
    assert resp.status_code == 200
    assert resp.json() == {"version": __version__}
