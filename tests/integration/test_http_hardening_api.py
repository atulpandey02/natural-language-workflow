"""End-to-end HTTP hardening on the real control-plane app (M9).

Confirms create_app actually wires the body cap, security headers, and safe
error shape (unit tests cover the components; this proves the assembly).
"""

import time
from collections.abc import Iterator
from types import SimpleNamespace

import jwt
import pytest
from fastapi.testclient import TestClient

from nlw.api.app import create_app
from nlw.core.config import Settings

pytestmark = pytest.mark.integration

ISSUER = "https://proj.supabase.co/auth/v1"
AUD = "authenticated"
SECRET = "dev-secret-for-tests-32bytes-min-length"


def _auth(sub: str) -> dict[str, str]:
    token = jwt.encode(
        {"iss": ISSUER, "aud": AUD, "exp": int(time.time()) + 300, "sub": sub, "email": "e@e.com"},
        SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    settings: Settings = pg_stack.settings.model_copy(update={"max_request_body_bytes": 1000})
    with TestClient(create_app(settings)) as c:
        yield c


def test_security_headers_on_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert len(r.headers["X-Request-Id"]) == 32


def test_oversized_body_rejected_before_auth(client: TestClient) -> None:
    # The body cap runs outermost, so an oversized body is 413 even unauthenticated.
    r = client.post(
        "/connectors", content=b"x" * 5000, headers={"content-type": "application/json"}
    )
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "payload_too_large"


def test_unknown_route_safe_404_shape(client: TestClient) -> None:
    r = client.get("/no-such-route")
    assert r.status_code == 404
    assert set(r.json()["error"].keys()) == {"code", "message"}


def test_docs_served_outside_production(client: TestClient) -> None:
    assert client.get("/openapi.json").status_code == 200


def test_docs_disabled_in_production(pg_stack: SimpleNamespace) -> None:
    settings = pg_stack.settings.model_copy(update={"app_env": "production"})
    with TestClient(create_app(settings)) as c:
        assert c.get("/openapi.json").status_code == 404
        assert c.get("/docs").status_code == 404
