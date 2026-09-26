"""Demo-tool visibility through the real API (final audit, Package 6).

Production settings (DEMO_TOOLS_ENABLED unset): new planning and ``GET /tools``
never see ``fake.*`` / ``static.*``; a tenant cannot switch them on from a
request; an ALREADY-materialized workflow version that references a demo tool
still runs (registry compatibility). Test/development settings (explicit true)
expose them.
"""

import json
import time
import uuid
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

import nlw.api.routers.plans as plans_mod
import nlw.api.routers.workflows as workflows_mod
from nlw.api.app import create_app
from nlw.api.deps import get_llm_provider
from nlw.core.config import Settings
from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.engine.execution import process_advance
from nlw.planner.provider import LLMRequest, LLMResult
from nlw.planner.schema import PlannerOutput

pytestmark = pytest.mark.integration

DEMO = {"fake.echo", "fake.fail", "static.echo", "static.secret_check"}
_ISSUER = "https://proj.supabase.co/auth/v1"
_SECRET = "dev-secret-for-tests-32bytes-min-length"


def _auth(sub: str, email: str) -> dict[str, str]:
    token = jwt.encode(
        {
            "iss": _ISSUER,
            "aud": "authenticated",
            "exp": int(time.time()) + 300,
            "sub": sub,
            "email": email,
        },
        _SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def _prod(pg_stack: SimpleNamespace) -> Settings:
    """Production-shaped settings with the demo-tool setting MISSING."""
    settings: Settings = pg_stack.settings.model_copy(
        update={"app_env": "production", "demo_tools_enabled": None}
    )
    return settings


@pytest.fixture
def prod_client(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    with TestClient(create_app(_prod(pg_stack))) as c:
        yield c


@pytest.fixture
def dev_client(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    with TestClient(create_app(pg_stack.settings)) as c:  # demo_tools_enabled=True (explicit)
        yield c


def _owner(client: TestClient, sub: str) -> tuple[dict[str, str], uuid.UUID]:
    h = _auth(sub, f"{sub}@x.com")
    r = client.post("/workspaces", headers=h, json={"name": f"ws-{sub}"})
    assert r.status_code == 201, r.text
    tid = uuid.UUID(r.json()["id"])
    return {**h, "X-Workspace-Id": str(tid)}, tid


def _static_connector(client: TestClient, h: dict[str, str]) -> None:
    r = client.post(
        "/connectors",
        headers=h,
        json={"type": "static", "name": "s", "config": {}, "secret_ref": "STATIC_DEMO"},
    )
    assert r.status_code == 201, r.text


def _tools(
    client: TestClient,
    h: dict[str, str],
    *,
    params: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> set[str]:
    r = client.get("/tools", headers={**h, **(extra_headers or {})}, params=params)
    assert r.status_code == 200, r.text
    return {t["name"] for t in r.json()}


def test_production_hides_demo_tools_from_tools_listing_and_planning(
    prod_client: TestClient, pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    h, tid = _owner(prod_client, "prod1")
    _static_connector(prod_client, h)
    assert _tools(prod_client, h).isdisjoint(DEMO)

    # A tenant cannot switch them on from the request (query/header/body ignored).
    assert _tools(
        prod_client,
        h,
        params={"demo_tools_enabled": "true", "include_demo": "true"},
        extra_headers={"X-Demo-Tools": "true"},
    ).isdisjoint(DEMO)

    # The view handed to the planner for a NEW plan carries no demo tool, while the
    # registry name set (UNKNOWN_TOOL vs TOOL_NOT_AVAILABLE) still knows them.
    captured: dict[str, Any] = {}
    real = plans_mod.build_tenant_view  # type: ignore[attr-defined]

    async def spy(session: Any, tenant_id: Any, settings: Any, *, purpose: str) -> Any:
        view, names = await real(session, tenant_id, settings, purpose=purpose)  # type: ignore[arg-type]
        captured["purpose"] = purpose
        captured["view_names"] = {t.name for t in view.tools}
        captured["registry_names"] = set(names)
        return view, names

    monkeypatch.setattr(plans_mod, "build_tenant_view", spy)
    r = prod_client.post(
        "/plans",
        headers=h,
        json={"prompt": "Echo hello world.", "demo_tools_enabled": True, "include_demo": True},
    )
    assert r.status_code in (200, 201, 422), r.text
    assert captured["purpose"] == "planning"
    assert captured["view_names"].isdisjoint(DEMO)
    assert captured["registry_names"] >= DEMO


def test_development_configuration_exposes_demo_tools(dev_client: TestClient) -> None:
    h, _tid = _owner(dev_client, "dev1")
    assert {"fake.echo", "fake.fail"} <= _tools(dev_client, h)
    assert "static.echo" not in _tools(dev_client, h)  # still connector-gated
    _static_connector(dev_client, h)
    assert _tools(dev_client, h) >= DEMO


def test_existing_materialized_demo_workflow_remains_executable_in_production(
    prod_client: TestClient, pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Registry compatibility: an already-materialized fake.echo version is not
    STALE merely because new planning no longer sees the tool, and the worker
    still executes it to completion."""
    monkeypatch.setattr(workflows_mod, "_enqueue_advance", lambda _rid: None)  # no Redis here
    h, tid = _owner(prod_client, "prod2")
    wf, ver = uuid.uuid4(), uuid.uuid4()
    plan = {"steps": [{"id": "a", "tool": "fake.echo", "args": {"x": 1}}]}
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'legacy')", (wf, tid))
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,%s::jsonb)",
            (ver, tid, wf, json.dumps(plan)),
        )
        c.execute("UPDATE workflows SET current_version_id=%s WHERE id=%s", (ver, wf))

    r = prod_client.post(
        f"/workflows/{wf}/runs", headers={**h, "Idempotency-Key": uuid.uuid4().hex}
    )
    assert r.status_code in (200, 201, 202), r.text  # NOT 409 STALE_PLAN
    run_id = uuid.UUID(r.json()["run_id"])

    sm = create_sync_sessionmaker(create_sync_engine(pg_stack.worker_settings))
    last = "noop"
    for _ in range(6):
        last = process_advance(sm, run_id, lambda *_a: None, None, lambda _t: None).result  # type: ignore[arg-type, return-value]
        if last in ("completed", "failed"):
            break
    assert last == "completed"
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute("SELECT status FROM workflow_runs WHERE id=%s", (run_id,)).fetchone()
    assert row is not None and row[0] == "COMPLETED"


# --- materialization after demo tools are disabled (real /plans -> /materialize path) ---


class _ScriptedProvider:
    """Deterministic planner: returns a fixed, valid plan (no live model)."""

    model = "scripted"

    def __init__(self, output: PlannerOutput) -> None:
        self._raw = output.model_dump_json()

    async def generate_plan(self, req: LLMRequest) -> LLMResult:
        return LLMResult(raw_json=self._raw, model=self.model)


def _client_with(settings: Settings, provider: object) -> TestClient:
    app = create_app(settings)
    app.dependency_overrides[get_llm_provider] = lambda: provider
    client = TestClient(app, raise_server_exceptions=False)
    client.__enter__()
    return client


def _tenant_counts(owner_libpq: str, tid: uuid.UUID) -> dict[str, int]:
    with psycopg.connect(owner_libpq) as c:
        out: dict[str, int] = {}
        for table in (
            "workflows",
            "workflow_versions",
            "workflow_runs",
            "step_runs",
            "external_actions",
        ):
            row = c.execute(f"SELECT count(*) FROM {table} WHERE tenant_id=%s", (tid,)).fetchone()
            assert row is not None
            out[table] = int(row[0])
    return out


def test_proposal_with_demo_tool_cannot_materialize_after_demo_tools_are_disabled(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Lifecycle: demo tools enabled -> a valid fake.echo proposal is ACCEPTED ->
    demo tools disabled for planning -> materialization is refused as STALE
    (TOOL_NOT_AVAILABLE) BEFORE any workflow version exists; nothing runnable is
    created and nothing is enqueued. An already-materialized demo version keeps
    running through execution_compat."""
    plan = PlannerOutput.model_validate(
        {"workflow_name": "echo", "steps": [{"id": "a", "tool": "fake.echo", "args": {"x": 1}}]}
    )
    enqueued: list[object] = []
    monkeypatch.setattr(workflows_mod, "_enqueue_advance", enqueued.append)

    # 1-2. Demo tools explicitly enabled (fixture settings): the proposal is accepted.
    dev = _client_with(pg_stack.settings, _ScriptedProvider(plan))
    h, tid = _owner(dev, "mat1")
    r = dev.post("/plans", headers=h, json={"prompt": "echo x"})
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "PASS"
    proposal_id = r.json()["id"]
    baseline = _tenant_counts(pg_stack.owner_libpq, tid)

    # 3-6. Demo tools disabled for planning/materialization: refused, nothing created.
    prod = _client_with(_prod(pg_stack), _ScriptedProvider(plan))
    m = prod.post(f"/plans/{proposal_id}/materialize", headers=h)
    assert m.status_code == 409, m.text
    err = m.json()["error"]
    assert err["code"] == "STALE_PLAN", err
    assert "fake.echo" not in m.text  # sanitized member-safe reason only
    assert _tenant_counts(pg_stack.owner_libpq, tid) == baseline
    assert enqueued == []
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT workflow_version_id FROM plan_proposals WHERE id=%s", (proposal_id,)
        ).fetchone()
    assert row is not None and row[0] is None  # proposal not bound to any version

    # A NEW plan under the disabled policy cannot even be accepted with a demo tool.
    r2 = prod.post("/plans", headers=h, json={"prompt": "echo again"})
    assert r2.status_code == 201, r2.text
    assert r2.json()["status"] == "REJECT"

    # 7. Materialized while enabled -> still runnable when disabled (execution_compat).
    ok = dev.post(f"/plans/{proposal_id}/materialize", headers=h)
    assert ok.status_code == 200, ok.text
    wf_id = ok.json()["workflow_id"]
    run = prod.post(f"/workflows/{wf_id}/runs", headers={**h, "Idempotency-Key": uuid.uuid4().hex})
    assert run.status_code in (200, 201, 202), run.text  # NOT 409 STALE_PLAN
    assert len(enqueued) == 1
