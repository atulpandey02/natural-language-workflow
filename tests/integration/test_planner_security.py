"""Planner security (M6): secret non-exposure at the LLM boundary, the honest
user-prompt boundary, and adversarial model output that stays non-executable.
"""

import time
from collections.abc import Iterator
from types import SimpleNamespace

import jwt
import pytest
from fastapi.testclient import TestClient

from nlw.api.app import create_app
from nlw.api.deps import get_llm_provider
from nlw.planner.provider import LLMRequest, LLMResult
from nlw.planner.schema import PlannerOutput

pytestmark = pytest.mark.integration

ISSUER = "https://proj.supabase.co/auth/v1"
AUD = "authenticated"
SECRET = "dev-secret-for-tests-32bytes-min-length"

PG_CONFIG = {
    "host": "internal-db-host.example",
    "database": "app",
    "sslmode": "require",
    "allowed_schemas": ["public"],
    "allowed_tables": ["public.people"],
}


def _auth(sub: str, email: str) -> dict[str, str]:
    token = jwt.encode(
        {"iss": ISSUER, "aud": AUD, "exp": int(time.time()) + 300, "sub": sub, "email": email},
        SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


class SpyProvider:
    """Records the exact LLMRequest and returns a canned output."""

    model = "spy"

    def __init__(self, output: PlannerOutput) -> None:
        self._raw = output.model_dump_json()
        self.last: LLMRequest | None = None

    async def generate_plan(self, req: LLMRequest) -> LLMResult:
        self.last = req
        return LLMResult(raw_json=self._raw, model=self.model)


def _client(pg_stack: SimpleNamespace, provider: object) -> TestClient:
    app = create_app(pg_stack.settings)
    app.dependency_overrides[get_llm_provider] = lambda: provider
    client = TestClient(app)
    client.__enter__()  # run lifespan startup (populates app.state)
    return client


def _workspace(client: TestClient, headers: dict[str, str]) -> str:
    return str(client.post("/workspaces", json={"name": "W"}, headers=headers).json()["id"])


@pytest.fixture
def owner(pg_stack: SimpleNamespace) -> Iterator[SimpleNamespace]:
    yield pg_stack


def test_llm_input_excludes_secrets_and_infra_fields(pg_stack: SimpleNamespace) -> None:
    spy = SpyProvider(
        PlannerOutput.model_validate(
            {"workflow_name": "x", "clarification_needed": True, "steps": []}
        )
    )
    client = _client(pg_stack, spy)
    h = {**_auth("sec-a", "a@x.com")}
    ws = _workspace(client, h)
    h = {**h, "X-Workspace-Id": ws}
    client.post(
        "/connectors",
        json={
            "type": "postgres",
            "name": "pg",
            "config": PG_CONFIG,
            "secret_ref": "PG_TOP_SECRET_REF",
        },
        headers=h,
    )

    client.post("/plans", json={"prompt": "list the people"}, headers=h)

    assert spy.last is not None
    blob = spy.last.system + spy.last.user
    # Platform-managed secret material must never reach the model.
    assert "PG_TOP_SECRET_REF" not in blob
    assert "secret_ref" not in blob
    # Connector infra fields are not needed by the planner and are excluded.
    assert "internal-db-host.example" not in blob
    assert "sslmode" not in blob
    # But the allowlist context IS present (intended, non-secret).
    assert "public.people" in blob


def test_user_typed_content_is_not_falsely_protected(pg_stack: SimpleNamespace) -> None:
    # The model may legitimately copy user-authored text into args. The platform
    # guarantee covers platform-managed secrets, NOT user-typed content.
    user_text = "my-own-typed-password-123"
    spy = SpyProvider(
        PlannerOutput.model_validate(
            {
                "workflow_name": "echo",
                "steps": [{"id": "a", "tool": "fake.echo", "args": {"note": user_text}}],
            }
        )
    )
    client = _client(pg_stack, spy)
    h = {**_auth("sec-b", "b@x.com")}
    ws = _workspace(client, h)
    h = {**h, "X-Workspace-Id": ws}

    body = client.post("/plans", json={"prompt": f"echo {user_text}"}, headers=h).json()
    # User content can appear in the proposed plan args; it is NOT a platform
    # secret and the platform does not claim to strip it.
    assert user_text in str(body["proposed_plan"])


def test_adversarial_write_sql_rejected(pg_stack: SimpleNamespace) -> None:
    spy = SpyProvider(
        PlannerOutput.model_validate(
            {
                "workflow_name": "evil",
                "steps": [
                    {
                        "id": "a",
                        "tool": "postgres.query",
                        "args": {"sql": "DELETE FROM public.people"},
                        "connector": "pg",
                    }
                ],
            }
        )
    )
    client = _client(pg_stack, spy)
    h = {**_auth("sec-c", "c@x.com")}
    ws = _workspace(client, h)
    h = {**h, "X-Workspace-Id": ws}
    client.post(
        "/connectors",
        json={"type": "postgres", "name": "pg", "config": PG_CONFIG, "secret_ref": "PG_REF"},
        headers=h,
    )
    resp = client.post("/plans", json={"prompt": "delete everything"}, headers=h)
    assert resp.json()["status"] == "REJECT"


def test_adversarial_non_allowlisted_table_rejected(pg_stack: SimpleNamespace) -> None:
    spy = SpyProvider(
        PlannerOutput.model_validate(
            {
                "workflow_name": "peek",
                "steps": [
                    {
                        "id": "a",
                        "tool": "postgres.query",
                        "args": {"sql": "SELECT * FROM pg_catalog.pg_user"},
                        "connector": "pg",
                    }
                ],
            }
        )
    )
    client = _client(pg_stack, spy)
    h = {**_auth("sec-d", "d@x.com")}
    ws = _workspace(client, h)
    h = {**h, "X-Workspace-Id": ws}
    client.post(
        "/connectors",
        json={"type": "postgres", "name": "pg", "config": PG_CONFIG, "secret_ref": "PG_REF"},
        headers=h,
    )
    resp = client.post("/plans", json={"prompt": "read catalog"}, headers=h)
    assert resp.json()["status"] == "REJECT"
