"""Approval API (M7): admin/owner gate (RLS + role), CAS semantics, recovery-safe
re-enqueue, enqueue-failure surfacing, secret-free preview, tenant isolation.
"""

import json
import time
import uuid
from collections.abc import Iterator
from types import SimpleNamespace

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

import nlw.api.routers.approvals as approvals_mod
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
def enqueued(monkeypatch: pytest.MonkeyPatch) -> list[uuid.UUID]:
    """Capture enqueue calls instead of hitting Redis."""
    captured: list[uuid.UUID] = []

    def _fake(_request: object, run_id: uuid.UUID) -> None:
        captured.append(run_id)

    monkeypatch.setattr(approvals_mod, "_enqueue_advance", _fake)
    return captured


@pytest.fixture
def client(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    with TestClient(create_app(pg_stack.settings)) as c:
        yield c


def _seed_user_member(owner_libpq: str, tenant_id: uuid.UUID, sub: str, role: str) -> uuid.UUID:
    uid = uuid.uuid4()
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s)",
            (uid, sub, f"{sub}@example.com"),
        )
        c.execute(
            "INSERT INTO memberships (id, user_id, workspace_id, role) VALUES (%s,%s,%s,%s)",
            (uuid.uuid4(), uid, tenant_id, role),
        )
    return uid


def _seed_workspace(owner_libpq: str) -> uuid.UUID:
    tid = uuid.uuid4()
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO workspaces (id, name, slug) VALUES (%s,%s,%s)",
            (tid, "ws", f"ws-{tid}"),
        )
    return tid


def _seed_parked_action(
    owner_libpq: str,
    tenant_id: uuid.UUID,
    *,
    payload: dict[str, object] | None = None,
    connector_url: str = "https://sink.example/h",
) -> uuid.UUID:
    """Seed a webhook connector + a run parked at WAITING_APPROVAL with a pending
    approval (as the worker would leave it)."""
    connector_id = uuid.uuid4()
    wf_id, ver_id, run_id, approval_id = (uuid.uuid4() for _ in range(4))
    plan = {
        "steps": [
            {
                "id": "notify",
                "tool": "webhook.send",
                "args": {"payload": payload if payload is not None else {"msg": "hi"}},
                "connector": "hook",
            }
        ]
    }
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO connectors (id, tenant_id, type, name, config, secret_ref, status) "
            "VALUES (%s,%s,'webhook','hook',%s::jsonb,NULL,'active')",
            (connector_id, tenant_id, json.dumps({"url": connector_url})),
        )
        c.execute(
            "INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf_id, tenant_id)
        )
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,%s::jsonb)",
            (ver_id, tenant_id, wf_id, json.dumps(plan)),
        )
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status) "
            "VALUES (%s,%s,%s,%s,'WAITING_APPROVAL')",
            (run_id, tenant_id, wf_id, ver_id),
        )
        c.execute(
            "INSERT INTO step_runs (id, tenant_id, run_id, step_id, tool, status, attempt) "
            "VALUES (%s,%s,%s,'notify','webhook.send','WAITING_APPROVAL',0)",
            (uuid.uuid4(), tenant_id, run_id),
        )
        c.execute(
            "INSERT INTO approvals (id, tenant_id, run_id, step_id, connector_id, connector_name, "
            "tool, status) VALUES (%s,%s,%s,'notify',%s,'hook','webhook.send','pending')",
            (approval_id, tenant_id, run_id, connector_id),
        )
    return approval_id


def _approval_status(owner_libpq: str, approval_id: uuid.UUID) -> str:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute("SELECT status FROM approvals WHERE id=%s", (approval_id,)).fetchone()
    assert row is not None
    return str(row[0])


def test_admin_can_approve_and_reapprove_is_idempotent(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    tid = _seed_workspace(pg_stack.owner_libpq)
    _seed_user_member(pg_stack.owner_libpq, tid, "adm", "admin")
    approval_id = _seed_parked_action(pg_stack.owner_libpq, tid)
    h = {**_auth("adm", "admin@x.com"), "X-Workspace-Id": str(tid)}

    r1 = client.post(f"/approvals/{approval_id}/approve", headers=h)
    assert r1.status_code == 200 and r1.json()["status"] == "approved"
    assert _approval_status(pg_stack.owner_libpq, approval_id) == "approved"
    assert len(enqueued) == 1

    # Re-approve: idempotent success + re-enqueue (recovery-safe).
    r2 = client.post(f"/approvals/{approval_id}/approve", headers=h)
    assert r2.status_code == 200
    assert len(enqueued) == 2


def test_approve_then_reject_conflicts(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    tid = _seed_workspace(pg_stack.owner_libpq)
    _seed_user_member(pg_stack.owner_libpq, tid, "adm2", "admin")
    approval_id = _seed_parked_action(pg_stack.owner_libpq, tid)
    h = {**_auth("adm2", "a2@x.com"), "X-Workspace-Id": str(tid)}

    assert client.post(f"/approvals/{approval_id}/approve", headers=h).status_code == 200
    assert client.post(f"/approvals/{approval_id}/reject", headers=h).status_code == 409


def test_member_cannot_approve(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    tid = _seed_workspace(pg_stack.owner_libpq)
    _seed_user_member(pg_stack.owner_libpq, tid, "mem", "member")
    approval_id = _seed_parked_action(pg_stack.owner_libpq, tid)
    h = {**_auth("mem", "m@x.com"), "X-Workspace-Id": str(tid)}
    assert client.post(f"/approvals/{approval_id}/approve", headers=h).status_code == 403
    assert _approval_status(pg_stack.owner_libpq, approval_id) == "pending"
    assert len(enqueued) == 0


def test_enqueue_failure_returns_503(
    client: TestClient, pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = _seed_workspace(pg_stack.owner_libpq)
    _seed_user_member(pg_stack.owner_libpq, tid, "adm3", "admin")
    approval_id = _seed_parked_action(pg_stack.owner_libpq, tid)
    h = {**_auth("adm3", "a3@x.com"), "X-Workspace-Id": str(tid)}

    def _boom(_request: object, run_id: uuid.UUID) -> None:
        raise RuntimeError("redis down")

    monkeypatch.setattr(approvals_mod, "_enqueue_advance", _boom)
    r = client.post(f"/approvals/{approval_id}/approve", headers=h)
    assert r.status_code == 503
    # The decision is durable even though resume could not be scheduled.
    assert _approval_status(pg_stack.owner_libpq, approval_id) == "approved"


def test_list_approvals_preview_is_secret_free(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    tid = _seed_workspace(pg_stack.owner_libpq)
    _seed_user_member(pg_stack.owner_libpq, tid, "adm4", "admin")
    _seed_parked_action(pg_stack.owner_libpq, tid)
    h = {**_auth("adm4", "a4@x.com"), "X-Workspace-Id": str(tid)}

    listing = client.get("/approvals", headers=h).json()
    assert len(listing) == 1
    item = listing[0]
    assert item["tool"] == "webhook.send"
    assert item["preview"]["args"] == {"payload": {"msg": "hi"}}
    blob = json.dumps(item)
    for forbidden in ("secret", "token", "Authorization", "url"):
        assert forbidden not in blob


def test_preview_shows_effective_destination_host_only(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    """The approver sees the effective, non-secret destination the side effect
    will reach — the webhook HOST only (never the path/query/credentials)."""
    tid = _seed_workspace(pg_stack.owner_libpq)
    _seed_user_member(pg_stack.owner_libpq, tid, "adm-d", "admin")
    _seed_parked_action(
        pg_stack.owner_libpq, tid, connector_url="https://hooks.example.com/secret-path?token=abc"
    )
    h = {**_auth("adm-d", "d@x.com"), "X-Workspace-Id": str(tid)}

    item = client.get("/approvals", headers=h).json()[0]
    assert item["destination"] == "hooks.example.com"  # host only
    assert item["payload_review_blocked"] is False
    blob = json.dumps(item)
    assert "secret-path" not in blob  # path never exposed
    assert "token=abc" not in blob  # credential query never exposed


def test_oversized_payload_is_review_blocked_and_cannot_be_approved(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    """A payload too large to review safely is NOT shown and CANNOT be approved
    unseen — it can only be rejected (P1C part G, defence-in-depth)."""
    from nlw.tools.action_schemas import MAX_REVIEWABLE_ACTION_PAYLOAD_BYTES

    tid = _seed_workspace(pg_stack.owner_libpq)
    _seed_user_member(pg_stack.owner_libpq, tid, "adm-o", "admin")
    big: dict[str, object] = {"blob": "x" * (MAX_REVIEWABLE_ACTION_PAYLOAD_BYTES + 5000)}
    approval_id = _seed_parked_action(pg_stack.owner_libpq, tid, payload=big)
    h = {**_auth("adm-o", "o@x.com"), "X-Workspace-Id": str(tid)}

    item = client.get("/approvals", headers=h).json()[0]
    assert item["payload_review_blocked"] is True
    assert item["preview"]["args"] is None  # oversized payload is NOT shown

    # Approve is refused (422); the approval stays pending and nothing is enqueued.
    r = client.post(f"/approvals/{approval_id}/approve", headers=h)
    assert r.status_code == 422
    assert _approval_status(pg_stack.owner_libpq, approval_id) == "pending"
    assert len(enqueued) == 0

    # It can still be REJECTED.
    assert client.post(f"/approvals/{approval_id}/reject", headers=h).status_code == 200
    assert _approval_status(pg_stack.owner_libpq, approval_id) == "rejected"


def test_cross_tenant_cannot_see_or_decide(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    tid_a = _seed_workspace(pg_stack.owner_libpq)
    _seed_user_member(pg_stack.owner_libpq, tid_a, "own-a", "admin")
    approval_id = _seed_parked_action(pg_stack.owner_libpq, tid_a)

    tid_b = _seed_workspace(pg_stack.owner_libpq)
    _seed_user_member(pg_stack.owner_libpq, tid_b, "own-b", "admin")
    hb = {**_auth("own-b", "b@x.com"), "X-Workspace-Id": str(tid_b)}

    # B lists nothing, and cannot decide A's approval (RLS-scoped -> 404).
    assert client.get("/approvals", headers=hb).json() == []
    assert client.post(f"/approvals/{approval_id}/approve", headers=hb).status_code == 404
