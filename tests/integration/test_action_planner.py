"""M6 planner integration for M7 action tools: webhook.send surfaces with
requires_approval -> NEEDS_APPROVAL, and such a plan is materializable.
"""

import time
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
SECRET = "dev-secret-for-tests-32bytes-min-length"


def _auth(sub: str) -> dict[str, str]:
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": "authenticated",
            "exp": int(time.time()) + 300,
            "sub": sub,
            "email": f"{sub}@x.com",
        },
        SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


class ScriptedProvider:
    model = "scripted"

    def __init__(self, output: PlannerOutput) -> None:
        self._raw = output.model_dump_json()

    async def generate_plan(self, req: LLMRequest) -> LLMResult:
        return LLMResult(raw_json=self._raw, model=self.model)


def _client(pg_stack: SimpleNamespace, provider: object) -> TestClient:
    app = create_app(pg_stack.settings)
    app.dependency_overrides[get_llm_provider] = lambda: provider
    c = TestClient(app)
    c.__enter__()
    return c


def test_action_plan_needs_approval_and_materializes(pg_stack: SimpleNamespace) -> None:
    output = PlannerOutput.model_validate(
        {
            "workflow_name": "notify",
            "steps": [
                {
                    "id": "notify",
                    "tool": "webhook.send",
                    "args": {"payload": {"hello": "world"}},
                    "connector": "hook",
                }
            ],
        }
    )
    client = _client(pg_stack, ScriptedProvider(output))
    h = {**_auth("plan-adm"), "X-Workspace-Id": ""}
    ws = str(client.post("/workspaces", json={"name": "W"}, headers=_auth("plan-adm")).json()["id"])
    h = {**_auth("plan-adm"), "X-Workspace-Id": ws}

    # Create a webhook connector so the tool is available to the tenant.
    assert (
        client.post(
            "/connectors",
            json={
                "type": "webhook",
                "name": "hook",
                "config": {"url": "https://sink.example/hook"},
                "secret_ref": None,
            },
            headers=h,
        ).status_code
        == 201
    )

    resp = client.post("/plans", json={"prompt": "notify the webhook"}, headers=h)
    body = resp.json()
    # requires_approval=True -> deterministic NEEDS_APPROVAL (not PASS).
    assert body["status"] == "NEEDS_APPROVAL"
    assert body["normalized_plan"] is not None
    proposal_id = body["id"]

    # NEEDS_APPROVAL is structurally executable -> materialization succeeds.
    mat = client.post(f"/plans/{proposal_id}/materialize", headers=h)
    assert mat.status_code == 200, mat.text
    assert mat.json()["workflow_version_id"]


def test_action_tool_hidden_without_connector(pg_stack: SimpleNamespace) -> None:
    output = PlannerOutput.model_validate(
        {
            "workflow_name": "x",
            "steps": [
                {"id": "a", "tool": "webhook.send", "args": {"payload": {}}, "connector": "hook"}
            ],
        }
    )
    client = _client(pg_stack, ScriptedProvider(output))
    ws = str(client.post("/workspaces", json={"name": "W"}, headers=_auth("plan-b")).json()["id"])
    h = {**_auth("plan-b"), "X-Workspace-Id": ws}
    # No webhook connector -> webhook.send unavailable -> REJECT.
    resp = client.post("/plans", json={"prompt": "notify"}, headers=h)
    assert resp.json()["status"] == "REJECT"
