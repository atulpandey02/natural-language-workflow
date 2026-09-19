"""Per-tenant durable-resource caps are concurrency-safe (M9, req 3).

The advisory-lock + count + insert path must not overshoot the cap even under a
burst of concurrent creates. Rate limiting is disabled here to isolate the quota.
"""

import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
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


def _auth(sub: str, email: str) -> dict[str, str]:
    token = jwt.encode(
        {"iss": ISSUER, "aud": AUD, "exp": int(time.time()) + 300, "sub": sub, "email": email},
        SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def _body(name: str) -> dict[str, object]:
    return {"type": "static", "name": name, "config": {"label": "x"}, "secret_ref": "STATIC_DEMO"}


@pytest.fixture
def client(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    settings: Settings = pg_stack.settings.model_copy(update={"max_connectors_per_tenant": 3})
    with TestClient(create_app(settings)) as c:
        yield c


def _workspace(client: TestClient, headers: dict[str, str]) -> str:
    return str(client.post("/workspaces", json={"name": "W"}, headers=headers).json()["id"])


def test_connector_cap_enforced_sequentially(client: TestClient) -> None:
    h = _auth("cap-a", "a@example.com")
    h = {**h, "X-Workspace-Id": _workspace(client, h)}
    codes = [
        client.post("/connectors", json=_body(f"c{i}"), headers=h).status_code for i in range(5)
    ]
    assert codes == [201, 201, 201, 409, 409]


def test_connector_cap_not_overshot_under_concurrency(client: TestClient) -> None:
    h = _auth("cap-b", "b@example.com")
    h = {**h, "X-Workspace-Id": _workspace(client, h)}

    def _fire(i: int) -> int:
        return client.post("/connectors", json=_body(f"cc{i}"), headers=h).status_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(_fire, range(12)))
    # Exactly the cap is created; the advisory lock prevents a count-then-insert race.
    assert codes.count(201) == 3
    assert codes.count(409) == 9
