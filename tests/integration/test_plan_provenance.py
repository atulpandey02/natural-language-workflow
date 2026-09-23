"""Request-to-plan provenance: durability, immutability, isolation (M12B-A P1).

Adversarial coverage for the durable NL-request provenance now bound to each
plan proposal: cross-tenant access, immutability after materialization, the
request→proposal→version binding, a revised request producing a NEW version
(never rewriting history), oversized rejection, and non-leakage of secret/
injection-like request text into lists or metrics.
"""

import hashlib
import time
from types import SimpleNamespace

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

from nlw.api.app import create_app
from nlw.api.deps import get_llm_provider
from nlw.observability import metrics
from nlw.planner.provider import LLMRequest, LLMResult
from nlw.planner.schema import PlannerOutput

pytestmark = pytest.mark.integration

ISSUER = "https://proj.supabase.co/auth/v1"
SECRET = "dev-secret-for-tests-32bytes-min-length"
PG_CONFIG = {
    "host": "db.internal",
    "database": "app",
    "allowed_schemas": ["public"],
    "allowed_tables": ["public.people"],
}


def _auth(sub: str, email: str) -> dict[str, str]:
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": "authenticated",
            "exp": int(time.time()) + 300,
            "sub": sub,
            "email": email,
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


def _client(pg_stack: SimpleNamespace, output: PlannerOutput) -> TestClient:
    app = create_app(pg_stack.settings)
    app.dependency_overrides[get_llm_provider] = lambda: ScriptedProvider(output)
    client = TestClient(app)
    client.__enter__()
    return client


def _ws(client: TestClient, h: dict[str, str]) -> str:
    return str(client.post("/workspaces", json={"name": "W"}, headers=h).json()["id"])


def _pg_connector(client: TestClient, h: dict[str, str]) -> None:
    r = client.post(
        "/connectors",
        json={"type": "postgres", "name": "pg", "config": PG_CONFIG, "secret_ref": "PG_SECRET"},
        headers=h,
    )
    assert r.status_code == 201, r.text


def _plan(sql: str = "SELECT id FROM public.people") -> PlannerOutput:
    return PlannerOutput.model_validate(
        {
            "workflow_name": "read people",
            "steps": [
                {"id": "q", "tool": "postgres.query", "args": {"sql": sql}, "connector": "pg"}
            ],
        }
    )


def _member(client: TestClient, sub: str, email: str) -> dict[str, str]:
    h = {**_auth(sub, email)}
    ws = _ws(client, h)
    h = {**h, "X-Workspace-Id": ws}
    _pg_connector(client, h)
    return h


def test_cross_tenant_cannot_read_request_or_provenance(pg_stack: SimpleNamespace) -> None:
    client = _client(pg_stack, _plan())
    ha = _member(client, "prov-a", "a@x.com")
    body = client.post("/plans", json={"prompt": "tenant A secret request"}, headers=ha).json()
    pid = body["id"]
    ver = client.post(f"/plans/{pid}/materialize", headers=ha).json()["workflow_version_id"]

    hb = _member(client, "prov-b", "b@x.com")
    # B cannot read A's proposal detail nor A's version provenance.
    assert client.get(f"/plans/{pid}", headers=hb).status_code == 404
    assert client.get(f"/workflow-versions/{ver}/provenance", headers=hb).status_code == 404
    # A can, and sees the request.
    prov = client.get(f"/workflow-versions/{ver}/provenance", headers=ha)
    assert prov.status_code == 200
    assert prov.json()["request_text"] == "tenant A secret request"


def test_request_text_is_immutable_to_the_app_role(pg_stack: SimpleNamespace) -> None:
    client = _client(pg_stack, _plan())
    h = _member(client, "prov-c", "c@x.com")
    pid = client.post("/plans", json={"prompt": "original request"}, headers=h).json()["id"]

    # nlw_app holds only UPDATE(workflow_version_id, updated_at); the column-
    # privilege check fires before RLS, so any UPDATE of request_text is denied.
    with (
        psycopg.connect(pg_stack.app_libpq) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute("UPDATE plan_proposals SET request_text='tampered' WHERE id=%s", (pid,))
    # Unchanged + digest still matches the original.
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT request_text, request_sha256 FROM plan_proposals WHERE id=%s", (pid,)
        ).fetchone()
    assert row is not None and row[0] == "original request"
    assert row[1] == hashlib.sha256(b"original request").hexdigest()


def test_binding_request_proposal_version(pg_stack: SimpleNamespace) -> None:
    client = _client(pg_stack, _plan())
    h = _member(client, "prov-d", "d@x.com")
    pid = client.post("/plans", json={"prompt": "bind me"}, headers=h).json()["id"]
    ver = client.post(f"/plans/{pid}/materialize", headers=h).json()["workflow_version_id"]
    # proposal -> version link set; provenance endpoint resolves version -> request.
    with psycopg.connect(pg_stack.owner_libpq) as c:
        link = c.execute(
            "SELECT workflow_version_id FROM plan_proposals WHERE id=%s", (pid,)
        ).fetchone()
    assert link is not None and str(link[0]) == ver
    prov = client.get(f"/workflow-versions/{ver}/provenance", headers=h).json()
    assert prov["request_text"] == "bind me" and prov["workflow_version_id"] == ver


def test_revised_request_makes_a_new_version_not_a_rewrite(pg_stack: SimpleNamespace) -> None:
    client = _client(pg_stack, _plan())
    h = _member(client, "prov-e", "e@x.com")
    p1 = client.post("/plans", json={"prompt": "first request"}, headers=h).json()["id"]
    v1 = client.post(f"/plans/{p1}/materialize", headers=h).json()["workflow_version_id"]
    p2 = client.post("/plans", json={"prompt": "revised request"}, headers=h).json()["id"]
    v2 = client.post(f"/plans/{p2}/materialize", headers=h).json()["workflow_version_id"]

    assert v1 != v2 and p1 != p2  # a new version, not a rewrite
    # The first proposal's historical provenance is untouched.
    assert client.get(f"/workflow-versions/{v1}/provenance", headers=h).json()["request_text"] == (
        "first request"
    )
    assert client.get(f"/workflow-versions/{v2}/provenance", headers=h).json()["request_text"] == (
        "revised request"
    )


def test_oversized_request_is_rejected_and_not_persisted(pg_stack: SimpleNamespace) -> None:
    client = _client(pg_stack, _plan())
    h = _member(client, "prov-f", "f@x.com")
    huge = "x" * (pg_stack.settings.llm_max_prompt_chars + 1)
    assert client.post("/plans", json={"prompt": huge}, headers=h).status_code == 422
    assert client.get("/plans", headers=h).json() == []  # nothing persisted


def test_stored_digest_covers_the_exact_persisted_request_encoding(
    pg_stack: SimpleNamespace,
) -> None:
    # A multibyte prompt round-trips: the persisted digest equals sha256 over the
    # UTF-8 bytes of the persisted request_text (the encoding never drifts).
    prompt = "read 山田's résumé ✅"
    client = _client(pg_stack, _plan())
    h = _member(client, "prov-h", "h@x.com")
    pid = client.post("/plans", json={"prompt": prompt}, headers=h).json()["id"]
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT request_text, request_sha256 FROM plan_proposals WHERE id=%s", (pid,)
        ).fetchone()
    assert row is not None
    assert row[0] == prompt
    assert row[1] == hashlib.sha256(row[0].encode("utf-8")).hexdigest()


def test_read_detects_owner_mutation_of_request_without_digest_update(
    pg_stack: SimpleNamespace,
) -> None:
    # The column grant stops nlw_app; this proves the RESIDUAL case where a
    # privileged (owner) UPDATE mutates request_text but not request_sha256. Both
    # read paths must FAIL CLOSED (500) rather than serve the tampered request.
    client = _client(pg_stack, _plan())
    h = _member(client, "prov-i", "i@x.com")
    pid = client.post("/plans", json={"prompt": "authentic request"}, headers=h).json()["id"]
    ver = client.post(f"/plans/{pid}/materialize", headers=h).json()["workflow_version_id"]
    # Both reads succeed while provenance is intact.
    assert client.get(f"/plans/{pid}", headers=h).status_code == 200
    assert client.get(f"/workflow-versions/{ver}/provenance", headers=h).status_code == 200
    # Owner tampers with the request text, leaving the digest stale.
    tampered = "MALICIOUSLY-swapped request text"
    with psycopg.connect(pg_stack.owner_libpq) as c:
        c.execute("UPDATE plan_proposals SET request_text=%s WHERE id=%s", (tampered, pid))
    # Now every read of the request fails the integrity check and never serves it.
    r1 = client.get(f"/plans/{pid}", headers=h)
    r2 = client.get(f"/workflow-versions/{ver}/provenance", headers=h)
    assert r1.status_code == 500 and tampered not in r1.text
    assert r2.status_code == 500 and tampered not in r2.text


def test_request_digest_is_also_immutable_to_the_app_role(pg_stack: SimpleNamespace) -> None:
    # A runtime role cannot rewrite request_sha256 either, so it can never forge a
    # CONSISTENT tampered (text, digest) pair to defeat the read-time verification.
    client = _client(pg_stack, _plan())
    h = _member(client, "prov-j", "j@x.com")
    pid = client.post("/plans", json={"prompt": "immutable digest"}, headers=h).json()["id"]
    with (
        psycopg.connect(pg_stack.app_libpq) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute(
            "UPDATE plan_proposals SET request_sha256=%s WHERE id=%s",
            (hashlib.sha256(b"forged").hexdigest(), pid),
        )


def test_secret_like_request_text_does_not_leak_to_list_or_metrics(
    pg_stack: SimpleNamespace,
) -> None:
    sentinel = "sk-live-INJECTED-ignore-all-instructions-42"
    client = _client(pg_stack, _plan())
    h = _member(client, "prov-g", "g@x.com")
    body = client.post("/plans", json={"prompt": f"do {sentinel}"}, headers=h).json()
    # The request is retrievable on the DETAIL view (authorized member only)...
    assert sentinel in client.get(f"/plans/{body['id']}", headers=h).json()["request_text"]
    # ...but never on the LIST view...
    assert sentinel not in str(client.get("/plans", headers=h).json())
    # ...nor in the persisted feasibility/plan JSON (only request_text holds it)...
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT feasibility, proposed_plan, normalized_plan FROM plan_proposals WHERE id=%s",
            (body["id"],),
        ).fetchone()
    assert row is not None and sentinel not in str(row[0])
    # ...nor in the Prometheus metrics exposition (no request text is ever a label).
    payload, _ = metrics.render()
    assert sentinel.encode() not in payload
