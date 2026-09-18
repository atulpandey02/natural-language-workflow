"""Identity, tenancy, and authorization over the real HTTP + DB stack.

Most cases use HS256 dev tokens to drive the full request flow against a
throwaway Postgres; ``test_me_via_rs256_jwks_end_to_end`` exercises the
production-target RS256/JWKS path through the same dependency chain.
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
from testcontainers.community.postgres import PostgresContainer

from nlw.api.app import create_app
from nlw.api.deps import get_auth_provider
from nlw.auth.supabase import SupabaseAuthProvider
from nlw.core.config import Settings
from nlw.db.base import Base
from nlw.db.models import User
from nlw.db.repositories import UserRepository
from nlw.db.session import create_engine, create_sessionmaker

pytestmark = pytest.mark.integration

ISSUER = "https://proj.supabase.co/auth/v1"
AUD = "authenticated"
SECRET = "dev-secret-for-tests-32bytes-min-length"


def _token(sub: str, email: str) -> str:
    payload = {"iss": ISSUER, "aud": AUD, "exp": int(time.time()) + 300, "sub": sub, "email": email}
    return jwt.encode(payload, SECRET, algorithm="HS256")


def _auth(sub: str, email: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(sub, email)}"}


async def _create_schema(settings: Settings) -> None:
    engine = create_engine(settings)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()


@pytest.fixture
def pg_settings() -> Iterator[Settings]:
    with PostgresContainer("postgres:16") as pg:
        url = (
            f"postgresql+psycopg://{pg.username}:{pg.password}"
            f"@{pg.get_container_host_ip()}:{pg.get_exposed_port(5432)}/{pg.dbname}"
        )
        settings = Settings(  # type: ignore[call-arg]
            _env_file=None,
            database_url=url,
            supabase_url="https://proj.supabase.co",
            supabase_jwt_secret=SECRET,
        )
        asyncio.run(_create_schema(settings))
        yield settings


@pytest.fixture
def client(pg_settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(pg_settings)) as c:
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

    # Owner of A resolves tenant context for A.
    ok = client.get("/workspaces/current", headers={**a, "X-Workspace-Id": ws_a})
    assert ok.status_code == 200
    assert ok.json() == {"tenant_id": ws_a, "role": "owner"}

    # B is not a member of A -> 403, and cannot see A in their own list.
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


def test_me_via_rs256_jwks_end_to_end(pg_settings: Settings) -> None:
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

    app = create_app(pg_settings)
    app.dependency_overrides[get_auth_provider] = lambda: provider
    try:
        with TestClient(app) as client:
            resp = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    assert resp.json()["email"] == "rs@example.com"


def test_user_provisioning_is_race_safe(pg_settings: Settings) -> None:
    async def run() -> tuple[uuid.UUID, uuid.UUID, int]:
        engine = create_engine(pg_settings)
        sessionmaker = create_sessionmaker(engine)

        async def once() -> User:
            async with sessionmaker() as session:
                return await UserRepository(session).get_or_create("race-sub", "race@example.com")

        first, second = await asyncio.gather(once(), once())
        async with sessionmaker() as session:
            rows = (
                (await session.execute(select(User).where(User.auth_provider_id == "race-sub")))
                .scalars()
                .all()
            )
        await engine.dispose()
        return first.id, second.id, len(rows)

    id1, id2, count = asyncio.run(run())
    assert id1 == id2
    assert count == 1
