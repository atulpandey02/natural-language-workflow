"""Planner API end-to-end (M6): propose, persist, revalidate, materialize.

Uses scripted/failing async providers (no network, no key). Planning and
materialization never connect to an external DB, so no second container is
needed. Proves persistence privacy, materialize-time revalidation, idempotency,
and provider-failure behavior.
"""

import hashlib
import time
import uuid
from collections.abc import Iterator
from types import SimpleNamespace

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

from nlw.api.app import create_app
from nlw.api.deps import get_llm_provider
from nlw.planner.provider import LLMRequest, LLMResult, LLMTimeoutError
from nlw.planner.schema import PlannerOutput

pytestmark = pytest.mark.integration

ISSUER = "https://proj.supabase.co/auth/v1"
AUD = "authenticated"
SECRET = "dev-secret-for-tests-32bytes-min-length"

PG_CONFIG = {
    "host": "db.internal",
    "database": "app",
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


class ScriptedProvider:
    model = "scripted"

    def __init__(self, output: PlannerOutput) -> None:
        self._raw = output.model_dump_json()
        self.last_request: LLMRequest | None = None

    async def generate_plan(self, req: LLMRequest) -> LLMResult:
        self.last_request = req
        return LLMResult(raw_json=self._raw, model=self.model)


class FailingProvider:
    model = "failing"

    async def generate_plan(self, req: LLMRequest) -> LLMResult:
        raise LLMTimeoutError("boom")


def _client(pg_stack: SimpleNamespace, provider: object) -> TestClient:
    app = create_app(pg_stack.settings)
    app.dependency_overrides[get_llm_provider] = lambda: provider
    client = TestClient(app)
    client.__enter__()  # run lifespan startup (populates app.state)
    return client


def _workspace(client: TestClient, headers: dict[str, str]) -> str:
    return str(client.post("/workspaces", json={"name": "W"}, headers=headers).json()["id"])


def _make_pg_connector(client: TestClient, headers: dict[str, str], name: str = "pg") -> None:
    resp = client.post(
        "/connectors",
        json={"type": "postgres", "name": name, "config": PG_CONFIG, "secret_ref": "PG_SECRET"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text


def _pg_query_plan(sql: str, connector: str = "pg") -> PlannerOutput:
    return PlannerOutput.model_validate(
        {
            "workflow_name": "read people",
            "steps": [
                {"id": "q", "tool": "postgres.query", "args": {"sql": sql}, "connector": connector}
            ],
        }
    )


@pytest.fixture
def member(pg_stack: SimpleNamespace) -> Iterator[SimpleNamespace]:
    yield pg_stack


def test_plan_pass_and_materialize_idempotent(pg_stack: SimpleNamespace) -> None:
    provider = ScriptedProvider(_pg_query_plan("SELECT id FROM public.people"))
    client = _client(pg_stack, provider)
    h = {**_auth("m6-a", "a@x.com")}
    ws = _workspace(client, h)
    h = {**h, "X-Workspace-Id": ws}
    _make_pg_connector(client, h)

    resp = client.post("/plans", json={"prompt": "list people"}, headers=h)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "PASS"
    assert body["normalized_plan"] is not None
    assert "prompt" not in body  # raw prompt never returned
    proposal_id = body["id"]

    # GET the proposal back.
    got = client.get(f"/plans/{proposal_id}", headers=h)
    assert got.status_code == 200 and got.json()["status"] == "PASS"

    # Materialize -> creates a workflow_version.
    mat = client.post(f"/plans/{proposal_id}/materialize", headers=h)
    assert mat.status_code == 200, mat.text
    first = mat.json()
    assert first["idempotent_hit"] is False
    version_id = first["workflow_version_id"]

    # Materialize again -> idempotent, same version, no new workflow.
    mat2 = client.post(f"/plans/{proposal_id}/materialize", headers=h).json()
    assert mat2["idempotent_hit"] is True
    assert mat2["workflow_version_id"] == version_id


def test_plan_reject_unknown_tool_cannot_materialize(pg_stack: SimpleNamespace) -> None:
    provider = ScriptedProvider(
        PlannerOutput.model_validate(
            {"workflow_name": "x", "steps": [{"id": "a", "tool": "made.up.tool"}]}
        )
    )
    client = _client(pg_stack, provider)
    h = {**_auth("m6-b", "b@x.com")}
    ws = _workspace(client, h)
    h = {**h, "X-Workspace-Id": ws}

    resp = client.post("/plans", json={"prompt": "do X"}, headers=h)
    assert resp.json()["status"] == "REJECT"
    pid = resp.json()["id"]
    mat = client.post(f"/plans/{pid}/materialize", headers=h)
    assert mat.status_code == 409


def test_materialize_blocked_when_connector_disabled(pg_stack: SimpleNamespace) -> None:
    provider = ScriptedProvider(_pg_query_plan("SELECT id FROM public.people"))
    client = _client(pg_stack, provider)
    h = {**_auth("m6-c", "c@x.com")}
    ws = _workspace(client, h)
    h = {**h, "X-Workspace-Id": ws}
    _make_pg_connector(client, h)

    pid = client.post("/plans", json={"prompt": "list"}, headers=h).json()["id"]

    # Disable the connector out-of-band (operator action) BEFORE materialize.
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute("UPDATE connectors SET status='disabled' WHERE tenant_id=%s AND name='pg'", (ws,))

    mat = client.post(f"/plans/{pid}/materialize", headers=h)
    assert mat.status_code == 409  # revalidation blocks a stale PASS


def test_request_provenance_persisted_bounded_and_not_listed(pg_stack: SimpleNamespace) -> None:
    # M12B-A: the request is now DURABLY bound to its proposal (request_text +
    # sha256 + contract version), but only under the `request_text` field, only
    # on the detail view, never on the list, and only for the owning tenant.
    request = "list people please"
    provider = ScriptedProvider(_pg_query_plan("SELECT id FROM public.people"))
    client = _client(pg_stack, provider)
    h = {**_auth("m6-d", "d@x.com")}
    ws = _workspace(client, h)
    h = {**h, "X-Workspace-Id": ws}
    _make_pg_connector(client, h)

    body = client.post("/plans", json={"prompt": request}, headers=h).json()
    assert body["status"] == "PASS"
    assert "prompt" not in body  # the wire field is request_text, not prompt
    assert body["request_text"] == request
    assert body["request_sha256"] == hashlib.sha256(request.encode()).hexdigest()
    assert body["planner_contract_version"]

    # Persisted row carries the request + digest + contract version.
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT request_text, request_sha256, planner_contract_version, prompt_len "
            "FROM plan_proposals WHERE id=%s",
            (body["id"],),
        ).fetchone()
    assert row is not None
    assert row[0] == request
    assert row[1] == hashlib.sha256(request.encode()).hexdigest()
    assert row[2] and row[3] == len(request)

    # The LIST endpoint must NOT expose the request text.
    listed = client.get("/plans", headers=h).json()
    assert listed and all("request_text" not in item for item in listed)


def test_provider_timeout_yields_503_and_no_proposal_row(pg_stack: SimpleNamespace) -> None:
    client = _client(pg_stack, FailingProvider())
    h = {**_auth("m6-e", "e@x.com")}
    ws = _workspace(client, h)
    h = {**h, "X-Workspace-Id": ws}

    resp = client.post("/plans", json={"prompt": "anything"}, headers=h)
    assert resp.status_code == 503
    # No feasibility REJECT row is fabricated for an infrastructure fault.
    assert client.get("/plans", headers=h).json() == []


def test_prompt_length_cap_rejected(pg_stack: SimpleNamespace) -> None:
    provider = ScriptedProvider(_pg_query_plan("SELECT id FROM public.people"))
    client = _client(pg_stack, provider)
    h = {**_auth("m6-f", "f@x.com")}
    ws = _workspace(client, h)
    h = {**h, "X-Workspace-Id": ws}
    huge = "x" * (pg_stack.settings.llm_max_prompt_chars + 1)
    resp = client.post("/plans", json={"prompt": huge}, headers=h)
    assert resp.status_code == 422


def test_proposals_are_tenant_isolated(pg_stack: SimpleNamespace) -> None:
    provider = ScriptedProvider(
        PlannerOutput.model_validate(
            {"workflow_name": "x", "clarification_needed": True, "steps": []}
        )
    )
    client = _client(pg_stack, provider)
    a = {**_auth("m6-owner", "o@x.com")}
    ws_a = _workspace(client, a)
    ha = {**a, "X-Workspace-Id": ws_a}
    pid = client.post("/plans", json={"prompt": "hi"}, headers=ha).json()["id"]

    b = {**_auth("m6-other", "z@x.com")}
    ws_b = _workspace(client, b)
    hb = {**b, "X-Workspace-Id": ws_b}
    # B cannot read A's proposal, and B's own list is empty.
    assert client.get(f"/plans/{pid}", headers=hb).status_code == 404
    assert client.get("/plans", headers=hb).json() == []
    _ = uuid.UUID(pid)  # sanity


def test_cross_tenant_connector_not_usable_in_plan(pg_stack: SimpleNamespace) -> None:
    provider = ScriptedProvider(_pg_query_plan("SELECT id FROM public.people"))
    client = _client(pg_stack, provider)
    # A owns the connector.
    a = {**_auth("m6-a2", "a2@x.com")}
    ws_a = _workspace(client, a)
    ha = {**a, "X-Workspace-Id": ws_a}
    _make_pg_connector(client, ha)
    # B does NOT own it; the same plan references "pg" -> REJECT for B.
    b = {**_auth("m6-b2", "b2@x.com")}
    ws_b = _workspace(client, b)
    hb = {**b, "X-Workspace-Id": ws_b}
    resp = client.post("/plans", json={"prompt": "list"}, headers=hb)
    assert resp.json()["status"] == "REJECT"


def test_run_creation_blocked_stale_plan_after_connector_removed(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    # M12B-A Part 2: a materialized PASS plan whose connector is later removed is
    # blocked at run creation with a STALE_PLAN outcome — fail closed BEFORE any
    # tool is invoked. Non-retryable: the customer must re-plan.
    import nlw.api.routers.workflows as wf_router

    # no Redis in this stack: patch the enqueue seam so a FRESH run creation succeeds.
    monkeypatch.setattr(wf_router, "_enqueue_advance", lambda _run_id: None)
    provider = ScriptedProvider(_pg_query_plan("SELECT id FROM public.people"))
    client = _client(pg_stack, provider)
    h = {**_auth("stale-a", "s@x.com")}
    ws = _workspace(client, h)
    h = {**h, "X-Workspace-Id": ws}
    _make_pg_connector(client, h)

    pid = client.post("/plans", json={"prompt": "list"}, headers=h).json()["id"]
    mat = client.post(f"/plans/{pid}/materialize", headers=h).json()
    wf_id = mat["workflow_id"]

    # A fresh workflow runs (sanity): the plan is still executable.
    ok = client.post(f"/workflows/{wf_id}/runs", headers={**h, "Idempotency-Key": "run-fresh-1"})
    assert ok.status_code == 201, ok.text

    # Operator removes the connector out-of-band.
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute("DELETE FROM connectors WHERE tenant_id=%s AND name='pg'", (ws,))

    blocked = client.post(
        f"/workflows/{wf_id}/runs", headers={**h, "Idempotency-Key": "run-stale-1"}
    )
    assert blocked.status_code == 409
    err = blocked.json()["error"]
    assert err["code"] == "STALE_PLAN"
    assert "re-plan" in err["message"].lower()
