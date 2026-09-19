"""Connector + tools API: tenant-scoped, validated, secret-safe (M4)."""

import time
from collections.abc import Iterator
from types import SimpleNamespace

import jwt
import pytest
from fastapi.testclient import TestClient

from nlw.api.app import create_app

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


@pytest.fixture
def client(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    with TestClient(create_app(pg_stack.settings)) as c:
        yield c


def _new_workspace(client: TestClient, headers: dict[str, str]) -> str:
    return str(client.post("/workspaces", json={"name": "W"}, headers=headers).json()["id"])


def test_create_list_connectors_and_tools(client: TestClient) -> None:
    a = _auth("conn-a", "a@example.com")
    ws = _new_workspace(client, a)
    h = {**a, "X-Workspace-Id": ws}

    # Before a connector: static.* not available; fake.* always available.
    tools0 = {t["name"] for t in client.get("/tools", headers=h).json()}
    assert "fake.echo" in tools0 and "static.echo" not in tools0

    created = client.post(
        "/connectors",
        json={
            "type": "static",
            "name": "demo",
            "config": {"label": "x"},
            "secret_ref": "STATIC_DEMO",
        },
        headers=h,
    )
    assert created.status_code == 201
    body = created.json()
    assert body["has_secret"] is True and body["status"] == "unchecked"
    assert "secret_ref" not in body and "secret" not in body  # never exposed

    listed = client.get("/connectors", headers=h).json()
    assert [c["name"] for c in listed] == ["demo"]
    assert all("secret_ref" not in c for c in listed)

    tools1 = {t["name"] for t in client.get("/tools", headers=h).json()}
    assert {"static.echo", "static.secret_check"} <= tools1  # now available


def test_static_requires_secret_ref(client: TestClient) -> None:
    h = {**_auth("conn-b", "b@example.com")}
    ws = _new_workspace(client, h)
    h = {**h, "X-Workspace-Id": ws}
    resp = client.post(
        "/connectors",
        json={"type": "static", "name": "n", "config": {}, "secret_ref": None},
        headers=h,
    )
    assert resp.status_code == 422


def test_rejects_unknown_type_field_and_bad_ref(client: TestClient) -> None:
    h = {**_auth("conn-c", "c@example.com")}
    ws = _new_workspace(client, h)
    h = {**h, "X-Workspace-Id": ws}
    assert (
        client.post(
            "/connectors", json={"type": "nope", "name": "n", "config": {}}, headers=h
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/connectors",
            json={
                "type": "static",
                "name": "n",
                "config": {"bogus": 1},
                "secret_ref": "STATIC_DEMO",
            },
            headers=h,
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/connectors",
            json={"type": "static", "name": "n", "config": {}, "secret_ref": "bad-ref"},
            headers=h,
        ).status_code
        == 422
    )


def test_connectors_are_tenant_isolated(client: TestClient) -> None:
    a = _auth("conn-owner", "o@example.com")
    ws_a = _new_workspace(client, a)
    client.post(
        "/connectors",
        json={"type": "static", "name": "demo", "config": {}, "secret_ref": "STATIC_DEMO"},
        headers={**a, "X-Workspace-Id": ws_a},
    )
    b = _auth("conn-other", "x@example.com")
    ws_b = _new_workspace(client, b)
    hb = {**b, "X-Workspace-Id": ws_b}
    assert client.get("/connectors", headers=hb).json() == []
    tools_b = {t["name"] for t in client.get("/tools", headers=hb).json()}
    assert "static.echo" not in tools_b  # B owns no static connector
