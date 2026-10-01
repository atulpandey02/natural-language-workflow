"""B02: every planning attempt appends one redacted outcome event.

Same transaction as the proposal (PASS / REJECT / CLARIFY), a separate signed
transaction for provider failures (no proposal), tenant-scoped reads, and an
append-only table with no free text.
"""

import time
import uuid
from types import SimpleNamespace

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

from nlw.api.app import create_app
from nlw.api.deps import get_llm_provider
from nlw.planner.provider import LLMAuthError, LLMRequest, LLMResult, LLMUnavailableError
from nlw.planner.schema import PlannerOutput
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

SECRET = "dev-secret-for-tests-32bytes-min-length"
SENSITIVE = "Why did Dr. Jane Roe at Mercy West miss 7 shifts last month?"


def _auth(sub: str) -> dict[str, str]:
    token = jwt.encode(
        {
            "iss": "https://proj.supabase.co/auth/v1",
            "aud": "authenticated",
            "exp": int(time.time()) + 300,
            "sub": sub,
            "email": f"{sub}@x.com",
        },
        SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


class Scripted:
    model = "scripted-1"

    def __init__(self, output: PlannerOutput) -> None:
        self.raw = output.model_dump_json()

    async def generate_plan(self, req: LLMRequest) -> LLMResult:
        return LLMResult(raw_json=self.raw, model=self.model)


class Down:
    model = "down"

    async def generate_plan(self, req: LLMRequest) -> LLMResult:
        raise LLMUnavailableError("provider down")


def _setup(
    pg_stack: SimpleNamespace, provider: object, sub: str
) -> tuple[TestClient, dict[str, str], str]:
    app = create_app(pg_stack.settings)
    app.dependency_overrides[get_llm_provider] = lambda: provider
    client = TestClient(app)
    client.__enter__()
    h = _auth(sub)
    ws = client.post("/workspaces", json={"name": "W"}, headers=h).json()["id"]
    return client, {**h, "X-Workspace-Id": ws}, ws


def _events(pg_stack: SimpleNamespace, ws: str) -> list[tuple[object, ...]]:
    with psycopg.connect(pg_stack.owner_libpq) as conn:
        return conn.execute(
            "SELECT outcome, category, finding_codes, proposal_id, request_len_bucket, "
            "request_shape, provider, model, contract_version, step_count "
            "FROM plan_outcome_events WHERE tenant_id=%s ORDER BY created_at",
            (ws,),
        ).fetchall()


def test_reject_writes_one_redacted_event_linked_to_the_proposal(pg_stack: SimpleNamespace) -> None:
    out = PlannerOutput.model_validate(
        {"workflow_name": "x", "steps": [{"id": "a", "tool": "made.up.tool"}]}
    )
    client, h, ws = _setup(pg_stack, Scripted(out), "po-reject")
    r = client.post("/plans", json={"prompt": SENSITIVE}, headers=h)
    assert r.status_code == 201 and r.json()["status"] == "REJECT"
    rows = _events(pg_stack, ws)
    assert len(rows) == 1
    outcome, category, codes, proposal_id, bucket, shape, provider, model, contract, steps = rows[0]
    assert (outcome, category, codes) == ("REJECT", "MISSING_CAPABILITY", ["UNKNOWN_TOOL"])
    assert str(proposal_id) == r.json()["id"]
    assert bucket == "50_199"
    assert isinstance(shape, list) and {"asks_why", "has_time_window"} <= set(shape)
    assert (provider, model, contract, steps) == ("stub", "scripted-1", "planner-1", 1)
    blob = repr(rows)
    for fragment in ("Jane", "Mercy", "made.up.tool"):
        assert fragment not in blob


def test_clarification_via_the_stub_provider_is_recorded(pg_stack: SimpleNamespace) -> None:
    app = create_app(pg_stack.settings)  # default provider: keyless stub -> clarify
    client = TestClient(app)
    client.__enter__()
    h = _auth("po-stub")
    ws = client.post("/workspaces", json={"name": "W"}, headers=h).json()["id"]
    r = client.post("/plans", json={"prompt": "show sales"}, headers={**h, "X-Workspace-Id": ws})
    assert r.status_code == 201 and r.json()["status"] == "NEEDS_CLARIFICATION"
    [(outcome, category, *_rest)] = _events(pg_stack, ws)
    assert (outcome, category) == ("CLARIFY", "UNDERSPECIFIED_REQUEST")


def test_provider_failure_records_infra_fail_without_a_proposal(pg_stack: SimpleNamespace) -> None:
    client, h, ws = _setup(pg_stack, Down(), "po-down")
    r = client.post("/plans", json={"prompt": "show sales"}, headers=h)
    assert r.status_code == 503
    with psycopg.connect(pg_stack.owner_libpq) as conn:
        proposals = conn.execute(
            "SELECT count(*) FROM plan_proposals WHERE tenant_id=%s", (ws,)
        ).fetchone()
    assert proposals == (0,)
    [(outcome, category, codes, proposal_id, *_rest)] = _events(pg_stack, ws)
    assert (outcome, category, codes, proposal_id) == ("INFRA_FAIL", "INFRA_FAILURE", [], None)


def test_events_are_tenant_scoped_append_only_and_admin_readable(pg_stack: SimpleNamespace) -> None:
    out = PlannerOutput.model_validate(
        {"workflow_name": "x", "steps": [{"id": "a", "tool": "made.up.tool"}]}
    )
    client, h, ws = _setup(pg_stack, Scripted(out), "po-rls")
    client.post("/plans", json={"prompt": "hello"}, headers=h)
    owner_id = uuid.UUID(client.get("/me", headers=h).json()["id"])
    tenant = uuid.UUID(ws)
    other = pg_stack.seed_member("owner")
    member = pg_stack.add_membership(tenant, "member")

    def rows_for(user: uuid.UUID, tid: uuid.UUID) -> int:
        got = pg_stack.run_as(
            pg_stack.app_libpq,
            Purpose.API_REQUEST,
            "SELECT count(*) FROM plan_outcome_events",
            user_id=user,
            tenant_id=tid,
        )
        return int(str(got[0][0]))

    assert rows_for(owner_id, tenant) == 1
    assert rows_for(member, tenant) == 0  # members cannot read aggregates source rows
    assert rows_for(other.user_id, other.tenant_id) == 0  # other tenant sees nothing
    for stmt in (
        "UPDATE plan_outcome_events SET outcome='PASS'",
        "DELETE FROM plan_outcome_events",
    ):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            pg_stack.run_as(
                pg_stack.app_libpq, Purpose.API_REQUEST, stmt, user_id=owner_id, tenant_id=tenant
            )
    # A member of another tenant cannot forge an event for this tenant.
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        pg_stack.run_as(
            pg_stack.app_libpq,
            Purpose.API_REQUEST,
            "INSERT INTO plan_outcome_events (id, tenant_id, proposal_id, outcome, "
            "request_len_bucket, provider, model) VALUES (gen_random_uuid(), %s, "
            "gen_random_uuid(), 'PASS', 'lt50', 'stub', 'stub')",
            (tenant,),
            user_id=other.user_id,
            tenant_id=other.tenant_id,
        )


def test_schema_refuses_free_text(pg_stack: SimpleNamespace) -> None:
    member = pg_stack.seed_member("owner")
    base = (
        "INSERT INTO plan_outcome_events (id, tenant_id, proposal_id, outcome, "
        "request_len_bucket, provider, model, finding_codes, request_shape) VALUES "
        "(gen_random_uuid(), %s, gen_random_uuid(), 'REJECT', 'lt50', 'stub', %s, %s, %s)"
    )
    bad = [
        ("stub", ["UNKNOWN_TOOL: tool 'payroll.dump' missing"], []),
        ("stub", [], ["mentions Jane Roe"]),
        ("model with a sentence in it", [], []),
    ]
    for model, codes, shape in bad:
        with pytest.raises(psycopg.errors.CheckViolation):
            pg_stack.run_as(
                pg_stack.app_libpq,
                Purpose.API_REQUEST,
                base,
                (member.tenant_id, model, codes, shape),
                user_id=member.user_id,
                tenant_id=member.tenant_id,
            )
    columns = pg_stack.run_as(
        pg_stack.owner_libpq,
        Purpose.API_REQUEST,
        "SELECT column_name, data_type FROM information_schema.columns "
        "WHERE table_name='plan_outcome_events'",
        user_id=member.user_id,
        tenant_id=member.tenant_id,
    )
    names = {str(c[0]) for c in columns}
    assert not names & {"request_text", "message", "detail", "prompt", "user_id", "created_by"}


class Unauthorized:
    model = "unauthorized"

    async def generate_plan(self, req: LLMRequest) -> LLMResult:
        raise LLMAuthError("provider rejected the platform key")


def _proposals(pg_stack: SimpleNamespace, ws: str) -> int:
    with psycopg.connect(pg_stack.owner_libpq) as conn:
        row = conn.execute("SELECT count(*) FROM plan_proposals WHERE tenant_id=%s", (ws,))
        return int(row.fetchone()[0])  # type: ignore[index]


def test_provider_auth_failure_records_infra_fail_and_keeps_the_502(
    pg_stack: SimpleNamespace,
) -> None:
    client, h, ws = _setup(pg_stack, Unauthorized(), "po-auth")
    r = client.post("/plans", json={"prompt": "show sales"}, headers=h)
    assert r.status_code == 502
    assert r.json()["error"]["message"] == "planner provider misconfigured"
    assert _proposals(pg_stack, ws) == 0
    [(outcome, category, codes, proposal_id, *_rest)] = _events(pg_stack, ws)
    assert (outcome, category, codes, proposal_id) == ("INFRA_FAIL", "INFRA_FAILURE", [], None)


def test_classification_failure_never_fails_planning(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    from nlw.observability import plan_outcomes

    def _boom(*_a: object, **_k: object) -> None:
        raise KeyError("an unclassified feasibility code")

    monkeypatch.setattr(plan_outcomes, "from_report", _boom)
    out = PlannerOutput.model_validate(
        {"workflow_name": "x", "steps": [{"id": "a", "tool": "made.up.tool"}]}
    )
    client, h, ws = _setup(pg_stack, Scripted(out), "po-classify-fail")
    r = client.post("/plans", json={"prompt": "show sales"}, headers=h)
    assert r.status_code == 201 and r.json()["status"] == "REJECT"
    assert _proposals(pg_stack, ws) == 1
    assert _events(pg_stack, ws) == []


def test_rejected_event_insert_rolls_back_only_its_savepoint(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real database error on the event INSERT (a CHECK violation) aborts
    only the SAVEPOINT: the proposal still commits and the response is 201."""
    import dataclasses

    from nlw.observability import plan_outcomes

    real_insert = plan_outcomes.insert_event

    async def _bad_insert(session: object, tenant_id: uuid.UUID, event: object) -> None:
        bad = dataclasses.replace(event, outcome="NOT_AN_OUTCOME")  # type: ignore[type-var]
        await real_insert(session, tenant_id, bad)  # type: ignore[arg-type]

    monkeypatch.setattr(plan_outcomes, "insert_event", _bad_insert)
    out = PlannerOutput.model_validate(
        {"workflow_name": "x", "steps": [{"id": "a", "tool": "made.up.tool"}]}
    )
    client, h, ws = _setup(pg_stack, Scripted(out), "po-insert-fail")
    r = client.post("/plans", json={"prompt": "show sales"}, headers=h)
    assert r.status_code == 201 and r.json()["status"] == "REJECT"
    assert _proposals(pg_stack, ws) == 1
    assert _events(pg_stack, ws) == []
