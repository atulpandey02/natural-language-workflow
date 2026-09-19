"""Rate limiting against a real Redis (M9, req 2).

Proves the atomic fixed-window limiter over the real Lua path: over-limit
requests get 429 (+Retry-After), the cap holds under concurrent requests (no
overshoot), and the endpoint fails CLOSED (503) when the limiter backend is
unavailable.
"""

import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import jwt
import pytest
from fastapi.testclient import TestClient
from testcontainers.community.redis import RedisContainer

from nlw.api.app import create_app
from nlw.core.config import Settings

pytestmark = pytest.mark.integration

ISSUER = "https://proj.supabase.co/auth/v1"
AUD = "authenticated"
SECRET = "dev-secret-for-tests-32bytes-min-length"


def _auth(sub: str, email: str) -> dict[str, str]:
    token = jwt.encode(
        {"iss": ISSUER, "aud": AUD, "exp": int(time.time()) + 300, "sub": sub, "email": email},
        SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def _connector_body(name: str) -> dict[str, object]:
    return {"type": "static", "name": name, "config": {"label": "x"}, "secret_ref": "STATIC_DEMO"}


@pytest.fixture
def redis_url() -> Iterator[str]:
    with RedisContainer("redis:7") as c:
        yield f"redis://{c.get_container_host_ip()}:{c.get_exposed_port(6379)}/0"


def _client(pg_stack: SimpleNamespace, **over: object) -> TestClient:
    settings: Settings = pg_stack.settings.model_copy(update={"rate_limit_enabled": True, **over})
    return TestClient(create_app(settings))


def _workspace(client: TestClient, headers: dict[str, str]) -> str:
    return str(client.post("/workspaces", json={"name": "W"}, headers=headers).json()["id"])


def test_over_limit_returns_429_with_retry_after(pg_stack: SimpleNamespace, redis_url: str) -> None:
    with _client(pg_stack, redis_url=redis_url, rate_limit_writes_per_min=3) as client:
        h = _auth("rl-a", "a@example.com")
        h = {**h, "X-Workspace-Id": _workspace(client, h)}
        codes = [
            client.post("/connectors", json=_connector_body(f"c{i}"), headers=h).status_code
            for i in range(5)
        ]
        # First 3 within the window succeed; the rest are limited.
        assert codes[:3] == [201, 201, 201]
        assert codes[3] == 429
        last = client.post("/connectors", json=_connector_body("c-extra"), headers=h)
        assert last.status_code == 429
        assert int(last.headers["Retry-After"]) > 0


def test_cap_holds_under_concurrency(pg_stack: SimpleNamespace, redis_url: str) -> None:
    with _client(pg_stack, redis_url=redis_url, rate_limit_writes_per_min=3) as client:
        h = _auth("rl-b", "b@example.com")
        h = {**h, "X-Workspace-Id": _workspace(client, h)}

        def _fire(i: int) -> int:
            return client.post("/connectors", json=_connector_body(f"cc{i}"), headers=h).status_code

        with ThreadPoolExecutor(max_workers=8) as pool:
            codes = list(pool.map(_fire, range(12)))
        # The atomic counter must never allow more than the limit through.
        assert codes.count(201) == 3
        assert codes.count(429) == 9


def test_fails_closed_when_backend_unavailable(pg_stack: SimpleNamespace) -> None:
    # Point the limiter at an unreachable Redis; cost/mutating endpoints must 503.
    with _client(pg_stack, redis_url="redis://127.0.0.1:1/0", rate_limit_fail_open=False) as client:
        h = _auth("rl-c", "c@example.com")
        h = {**h, "X-Workspace-Id": _workspace(client, h)}
        resp = client.post("/connectors", json=_connector_body("c"), headers=h)
        assert resp.status_code == 503
