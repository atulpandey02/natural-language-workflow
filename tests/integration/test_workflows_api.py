"""Workflow read endpoints + idempotent manual run (M10 support)."""

import json
import time
import uuid
from collections.abc import Iterator
from types import SimpleNamespace

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

import nlw.api.routers.workflows as workflows_mod
from nlw.api.app import create_app

pytestmark = pytest.mark.integration

ISSUER = "https://proj.supabase.co/auth/v1"
AUD = "authenticated"
SECRET = "dev-secret-for-tests-32bytes-min-length"
_PLAN = {"steps": [{"id": "a", "tool": "fake.echo", "args": {}}]}


def _auth_for(user_id: uuid.UUID) -> dict[str, str]:
    # seed_member creates users with auth_provider_id == f"sub-{user_id}".
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUD,
            "exp": int(time.time()) + 300,
            "sub": f"sub-{user_id}",
            "email": f"{user_id}@example.com",
        },
        SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def _seed_workflow(
    owner: str, tenant: uuid.UUID, *, with_version: bool = True
) -> tuple[uuid.UUID, uuid.UUID | None]:
    wf, ver = uuid.uuid4(), uuid.uuid4()
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf, tenant))
        if with_version:
            c.execute(
                "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
                "VALUES (%s,%s,%s,1,%s::jsonb)",
                (ver, tenant, wf, json.dumps(_PLAN)),
            )
            c.execute("UPDATE workflows SET current_version_id=%s WHERE id=%s", (ver, wf))
            return wf, ver
    return wf, None


@pytest.fixture
def client(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    with TestClient(create_app(pg_stack.settings)) as c:
        yield c


@pytest.fixture
def enqueued(monkeypatch: pytest.MonkeyPatch) -> list[uuid.UUID]:
    calls: list[uuid.UUID] = []
    monkeypatch.setattr(workflows_mod, "_enqueue_advance", calls.append)
    return calls


def test_list_and_get_workflow_with_version(client: TestClient, pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    wf, ver = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    h = {**_auth_for(m.user_id), "X-Workspace-Id": str(m.tenant_id)}

    listed = client.get("/workflows", headers=h).json()
    assert [w["id"] for w in listed] == [str(wf)]

    detail = client.get(f"/workflows/{wf}", headers=h).json()
    assert detail["current_version_id"] == str(ver)
    assert detail["current_version"]["plan"] == _PLAN

    version = client.get(f"/workflow-versions/{ver}", headers=h).json()
    assert version["version"] == 1 and version["plan"] == _PLAN


def test_workflows_are_tenant_isolated(client: TestClient, pg_stack: SimpleNamespace) -> None:
    a = pg_stack.seed_member()
    _seed_workflow(pg_stack.owner_libpq, a.tenant_id)
    b = pg_stack.seed_member()
    hb = {**_auth_for(b.user_id), "X-Workspace-Id": str(b.tenant_id)}
    assert client.get("/workflows", headers=hb).json() == []


def test_manual_run_is_idempotent(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    m = pg_stack.seed_member()
    wf, _ = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    h = {**_auth_for(m.user_id), "X-Workspace-Id": str(m.tenant_id), "Idempotency-Key": "run-key-1"}

    first = client.post(f"/workflows/{wf}/runs", headers=h)
    assert first.status_code == 201
    body1 = first.json()
    assert body1["idempotent_hit"] is False and body1["status"] == "PENDING"

    # Same key again (double-click / retry): SAME run, no duplicate.
    second = client.post(f"/workflows/{wf}/runs", headers=h)
    assert second.status_code == 201
    body2 = second.json()
    assert body2["run_id"] == body1["run_id"]
    assert body2["idempotent_hit"] is True

    # Exactly one durable run exists for this workflow.
    with psycopg.connect(pg_stack.owner_libpq) as c:
        count = c.execute(
            "SELECT count(*) FROM workflow_runs WHERE workflow_id=%s", (wf,)
        ).fetchone()
    assert count is not None and count[0] == 1
    assert len(enqueued) == 2  # re-enqueue on idempotent hit (recovery-safe)


def test_manual_run_requires_idempotency_key(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    m = pg_stack.seed_member()
    wf, _ = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    h = {**_auth_for(m.user_id), "X-Workspace-Id": str(m.tenant_id)}
    assert client.post(f"/workflows/{wf}/runs", headers=h).status_code == 422


def test_manual_run_rejects_reserved_scheduler_key_prefix(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    """A client Idempotency-Key must not use the reserved 'sched:' prefix, so the
    manual and scheduler namespaces stay unambiguous (P1D)."""
    m = pg_stack.seed_member()
    wf, _ = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    h = {
        **_auth_for(m.user_id),
        "X-Workspace-Id": str(m.tenant_id),
        "Idempotency-Key": "sched:deadbeef:2026-05-01T09:00:00+00:00",
    }
    assert client.post(f"/workflows/{wf}/runs", headers=h).status_code == 422
    assert len(enqueued) == 0


def test_manual_run_without_version_conflicts(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    m = pg_stack.seed_member()
    wf, _ = _seed_workflow(pg_stack.owner_libpq, m.tenant_id, with_version=False)
    h = {**_auth_for(m.user_id), "X-Workspace-Id": str(m.tenant_id), "Idempotency-Key": "k"}
    assert client.post(f"/workflows/{wf}/runs", headers=h).status_code == 409


def test_manual_run_enqueue_failure_returns_503(
    client: TestClient, pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    m = pg_stack.seed_member()
    wf, _ = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)

    def _boom(_run_id: uuid.UUID) -> None:
        raise RuntimeError("redis down")

    monkeypatch.setattr(workflows_mod, "_enqueue_advance", _boom)
    h = {**_auth_for(m.user_id), "X-Workspace-Id": str(m.tenant_id), "Idempotency-Key": "k2"}
    resp = client.post(f"/workflows/{wf}/runs", headers=h)
    assert resp.status_code == 503
    # The durable run still exists (recoverable by reconciliation).
    with psycopg.connect(pg_stack.owner_libpq) as c:
        count = c.execute(
            "SELECT count(*) FROM workflow_runs WHERE workflow_id=%s", (wf,)
        ).fetchone()
    assert count is not None and count[0] == 1
