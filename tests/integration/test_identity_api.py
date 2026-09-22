"""Identity, tenancy, and authorization over the real HTTP + DB stack.

The app connects as the restricted ``nlw_app`` role with RLS active (schema
applied by real migrations via the ``pg_stack`` fixture). Most cases use HS256
dev tokens; ``test_me_via_rs256_jwks_end_to_end`` exercises the production-target
RS256/JWKS path through the same dependency chain.
"""

import asyncio
import time
import uuid
from collections.abc import Iterator
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import select

from nlw.api.app import create_app
from nlw.api.deps import get_auth_provider
from nlw.auth.supabase import SupabaseAuthProvider
from nlw.db.models import User
from nlw.db.repositories import UserRepository
from nlw.db.session import create_engine, create_sessionmaker
from nlw.tenancy.session import set_identity_context
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

ISSUER = "https://proj.supabase.co/auth/v1"
AUD = "authenticated"
SECRET = "dev-secret-for-tests-32bytes-min-length"


def _token(sub: str, email: str) -> str:
    payload = {"iss": ISSUER, "aud": AUD, "exp": int(time.time()) + 300, "sub": sub, "email": email}
    return jwt.encode(payload, SECRET, algorithm="HS256")


def _auth(sub: str, email: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(sub, email)}"}


@pytest.fixture
def client(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    with TestClient(create_app(pg_stack.settings)) as c:
        yield c


def test_me_requires_auth(client: TestClient) -> None:
    assert client.get("/me").status_code == 401
    assert client.get("/me", headers={"Authorization": "Bearer not-a-jwt"}).status_code == 401


def test_me_provisions_idempotently(client: TestClient) -> None:
    headers = _auth("sub-1", "one@example.com")
    first = client.get("/me", headers=headers)
    second = client.get("/me", headers=headers)
    assert first.status_code == 200
    assert first.json()["email"] == "one@example.com"
    assert first.json()["id"] == second.json()["id"]


def test_create_and_list_workspaces(client: TestClient) -> None:
    headers = _auth("sub-owner", "owner@example.com")
    created = client.post("/workspaces", json={"name": "Acme"}, headers=headers)
    assert created.status_code == 201
    assert created.json()["role"] == "owner"

    listed = client.get("/workspaces", headers=headers)
    assert listed.status_code == 200
    ids = [w["id"] for w in listed.json()]
    assert created.json()["id"] in ids


def test_tenant_context_and_cross_tenant_isolation(client: TestClient) -> None:
    a = _auth("sub-a", "a@example.com")
    b = _auth("sub-b", "b@example.com")
    ws_a = client.post("/workspaces", json={"name": "A"}, headers=a).json()["id"]

    ok = client.get("/workspaces/current", headers={**a, "X-Workspace-Id": ws_a})
    assert ok.status_code == 200
    assert ok.json() == {"tenant_id": ws_a, "role": "owner"}

    forbidden = client.get("/workspaces/current", headers={**b, "X-Workspace-Id": ws_a})
    assert forbidden.status_code == 403
    assert client.get("/workspaces", headers=b).json() == []


def test_workspace_header_validation(client: TestClient) -> None:
    a = _auth("sub-h", "h@example.com")
    assert client.get("/workspaces/current", headers=a).status_code == 400  # missing header
    assert (
        client.get("/workspaces/current", headers={**a, "X-Workspace-Id": "nope"}).status_code
        == 400  # not a uuid
    )
    assert (
        client.get(
            "/workspaces/current", headers={**a, "X-Workspace-Id": str(uuid.uuid4())}
        ).status_code
        == 403  # valid uuid, not a member / nonexistent
    )


def test_me_via_rs256_jwks_end_to_end(pg_stack: SimpleNamespace) -> None:
    """Production-target path: HTTP -> FastAPI -> AuthProvider -> RS256 verify
    -> user provisioning -> endpoint, with an injected JWKS resolver (no network).
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    resolver = SimpleNamespace(
        get_signing_key_from_jwt=lambda _token: SimpleNamespace(key=key.public_key())
    )
    provider = SupabaseAuthProvider(issuer=ISSUER, audience=AUD, signing_key_resolver=resolver)
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUD,
            "exp": int(time.time()) + 300,
            "sub": "rs256-sub",
            "email": "rs@example.com",
        },
        key,
        algorithm="RS256",
        headers={"kid": "test"},
    )

    app = create_app(pg_stack.settings)
    app.dependency_overrides[get_auth_provider] = lambda: provider
    try:
        with TestClient(app) as client:
            resp = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    assert resp.json()["email"] == "rs@example.com"


def test_user_provisioning_is_race_safe(pg_stack: SimpleNamespace) -> None:
    async def run() -> tuple[uuid.UUID, uuid.UUID, int]:
        engine = create_engine(pg_stack.settings)
        sessionmaker = create_sessionmaker(engine)

        identity_signer = pg_stack.signers[Purpose.API_IDENTITY]

        async def once() -> User:
            async with sessionmaker() as session, session.begin():
                return await UserRepository(session).get_or_create(
                    "race-sub", "race@example.com", identity_signer
                )

        first, second = await asyncio.gather(once(), once())
        # users enforces RLS (P1A): a read needs a SIGNED identity context (P3B).
        # Both concurrent callers converge on the same id, so a self-scoped read
        # for that id returns exactly the one row that must exist.
        async with sessionmaker() as session, session.begin():
            await set_identity_context(session, identity_signer, first.id)
            rows = (
                (await session.execute(select(User).where(User.auth_provider_id == "race-sub")))
                .scalars()
                .all()
            )
        await engine.dispose()
        return first.id, second.id, len(rows)

    id1, id2, count = asyncio.run(run())
    assert id1 == id2
    assert count == 1  # concurrent first-login converged on a single row
