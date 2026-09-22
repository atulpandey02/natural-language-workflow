"""Approval separation-of-duties adversarial tests (M11.5 P3A).

The requester of an action can never decide it, even as owner/admin — enforced by
the app AND by the RLS four-eyes WITH CHECK (direct-SQL proof). A different eligible
user can decide. Worker/scheduler roles can never become decided_by.
"""

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
    captured: list[uuid.UUID] = []
    monkeypatch.setattr(approvals_mod, "_enqueue_advance", lambda _r, rid: captured.append(rid))
    return captured


@pytest.fixture
def client(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    with TestClient(create_app(pg_stack.settings)) as c:
        yield c


def _seed_user(owner_libpq: str, tid: uuid.UUID, sub: str, role: str) -> uuid.UUID:
    uid = uuid.uuid4()
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s)",
            (uid, sub, f"{sub}@x.com"),
        )
        c.execute(
            "INSERT INTO memberships (id, user_id, workspace_id, role) VALUES (%s,%s,%s,%s)",
            (uuid.uuid4(), uid, tid, role),
        )
    return uid


def _seed_ws(owner_libpq: str) -> uuid.UUID:
    tid = uuid.uuid4()
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute("INSERT INTO workspaces (id, name, slug) VALUES (%s,'ws',%s)", (tid, f"w-{tid}"))
    return tid


def _seed_approval(
    owner_libpq: str,
    tid: uuid.UUID,
    requester: uuid.UUID | None,
    *,
    scheduled_by: uuid.UUID | None = None,
) -> uuid.UUID:
    wf, ver, run, appr, conn_id = (uuid.uuid4() for _ in range(5))
    plan = '{"steps":[{"id":"notify","tool":"webhook.send","args":{},"connector":"hook"}]}'
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO connectors (id, tenant_id, type, name, config, secret_ref, status) "
            "VALUES (%s,%s,'webhook','hook','{\"url\":\"https://s.example/h\"}'::jsonb,NULL,'active')",
            (conn_id, tid),
        )
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf, tid))
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,%s::jsonb)",
            (ver, tid, wf, plan),
        )
        if scheduled_by is not None:
            sid = uuid.uuid4()
            c.execute(
                "INSERT INTO schedules (id, tenant_id, workflow_id, workflow_version_id, timezone, "
                "frequency, minute, hour, enabled, next_run_at, created_by) "
                "VALUES (%s,%s,%s,%s,'UTC','daily',0,9,true,now(),%s)",
                (sid, tid, wf, ver, scheduled_by),
            )
            c.execute(
                "INSERT INTO workflow_runs (id, tenant_id, workflow_id, "
                "workflow_version_id, status, trigger, schedule_id, scheduled_for, "
                "initiated_by_user_id) "
                "VALUES (%s,%s,%s,%s,'WAITING_APPROVAL','schedule',%s,now(),%s)",
                (run, tid, wf, ver, sid, scheduled_by),
            )
        else:
            c.execute(
                "INSERT INTO workflow_runs (id, tenant_id, workflow_id, "
                "workflow_version_id, status, initiated_by_user_id) "
                "VALUES (%s,%s,%s,%s,'WAITING_APPROVAL',%s)",
                (run, tid, wf, ver, requester),
            )
        c.execute(
            "INSERT INTO approvals (id, tenant_id, run_id, step_id, connector_id, connector_name, "
            "tool, status, requested_by_user_id) "
            "VALUES (%s,%s,%s,'notify',%s,'hook','webhook.send','pending',%s)",
            (appr, tid, run, conn_id, requester if scheduled_by is None else scheduled_by),
        )
    return appr


def _status(owner_libpq: str, appr: uuid.UUID) -> str:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute("SELECT status FROM approvals WHERE id=%s", (appr,)).fetchone()
    return str(row[0]) if row else "?"


# --- 13/14: manual-run requester (admin, then owner) cannot self-approve ---
@pytest.mark.parametrize("requester_role", ["admin", "owner"])
def test_manual_requester_cannot_self_approve(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID], requester_role: str
) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    req = _seed_user(pg_stack.owner_libpq, tid, f"req-{requester_role}", requester_role)
    appr = _seed_approval(pg_stack.owner_libpq, tid, req)
    h = {
        **_auth(f"req-{requester_role}", f"req-{requester_role}@x.com"),
        "X-Workspace-Id": str(tid),
    }
    r = client.post(f"/approvals/{appr}/approve", headers=h)
    assert r.status_code == 403 and "cannot decide" in r.json()["error"]["message"]
    assert _status(pg_stack.owner_libpq, appr) == "pending" and enqueued == []


# --- 15: a different eligible admin/owner can approve ---
def test_different_admin_can_approve(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    req = _seed_user(pg_stack.owner_libpq, tid, "req15", "admin")
    _seed_user(pg_stack.owner_libpq, tid, "adm15", "admin")
    appr = _seed_approval(pg_stack.owner_libpq, tid, req)
    h = {**_auth("adm15", "adm15@x.com"), "X-Workspace-Id": str(tid)}
    r = client.post(f"/approvals/{appr}/approve", headers=h)
    assert r.status_code == 200 and _status(pg_stack.owner_libpq, appr) == "approved"


# --- 16: user from another workspace cannot approve ---
def test_cross_workspace_cannot_approve(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    tid_a = _seed_ws(pg_stack.owner_libpq)
    req = _seed_user(pg_stack.owner_libpq, tid_a, "req16", "admin")
    appr = _seed_approval(pg_stack.owner_libpq, tid_a, req)
    tid_b = _seed_ws(pg_stack.owner_libpq)
    _seed_user(pg_stack.owner_libpq, tid_b, "own16b", "owner")
    # Owner of B, presenting A's workspace -> not a member of A.
    hb = {**_auth("own16b", "own16b@x.com"), "X-Workspace-Id": str(tid_a)}
    assert client.post(f"/approvals/{appr}/approve", headers=hb).status_code == 403
    # Presenting their own workspace -> approval not found there.
    hb2 = {**_auth("own16b", "own16b@x.com"), "X-Workspace-Id": str(tid_b)}
    assert client.post(f"/approvals/{appr}/approve", headers=hb2).status_code == 404


# --- 17: ordinary member cannot approve ---
def test_member_cannot_approve(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    req = _seed_user(pg_stack.owner_libpq, tid, "req17", "admin")
    _seed_user(pg_stack.owner_libpq, tid, "mem17", "member")
    appr = _seed_approval(pg_stack.owner_libpq, tid, req)
    h = {**_auth("mem17", "mem17@x.com"), "X-Workspace-Id": str(tid)}
    assert client.post(f"/approvals/{appr}/approve", headers=h).status_code == 403


# --- 18: scheduled-run responsible user cannot approve their own scheduled action ---
def test_scheduled_run_creator_cannot_self_approve(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    creator = _seed_user(pg_stack.owner_libpq, tid, "sched18", "admin")
    appr = _seed_approval(pg_stack.owner_libpq, tid, None, scheduled_by=creator)
    h = {**_auth("sched18", "sched18@x.com"), "X-Workspace-Id": str(tid)}
    r = client.post(f"/approvals/{appr}/approve", headers=h)
    assert r.status_code == 403 and _status(pg_stack.owner_libpq, appr) == "pending"


# --- 19: worker/scheduler DB roles can never write decided_by ---
def test_worker_scheduler_cannot_decide(pg_stack: SimpleNamespace) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    req = _seed_user(pg_stack.owner_libpq, tid, "req19", "admin")
    appr = _seed_approval(pg_stack.owner_libpq, tid, req)
    for libpq in (pg_stack.worker_libpq, pg_stack.scheduler_libpq):
        with (
            psycopg.connect(libpq, autocommit=True) as c,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            c.execute(
                "UPDATE approvals SET status='approved', decided_by=%s WHERE id=%s", (req, appr)
            )


# --- 20: concurrent decisions -> exactly one immutable decision ---
def test_concurrent_decisions_single_immutable(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    req = _seed_user(pg_stack.owner_libpq, tid, "req20", "member")
    a1 = _seed_user(pg_stack.owner_libpq, tid, "adm20a", "admin")
    _seed_user(pg_stack.owner_libpq, tid, "adm20b", "owner")
    appr = _seed_approval(pg_stack.owner_libpq, tid, req)
    h1 = {**_auth("adm20a", "adm20a@x.com"), "X-Workspace-Id": str(tid)}
    h2 = {**_auth("adm20b", "adm20b@x.com"), "X-Workspace-Id": str(tid)}
    r1 = client.post(f"/approvals/{appr}/approve", headers=h1)
    r2 = client.post(f"/approvals/{appr}/reject", headers=h2)
    # One decides; the opposite decision on the decided approval conflicts.
    assert r1.status_code == 200
    assert r2.status_code == 409
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute("SELECT status, decided_by FROM approvals WHERE id=%s", (appr,)).fetchone()
    assert row is not None and row[0] == "approved" and uuid.UUID(str(row[1])) == a1


# --- 21 (DB-level): the RLS four-eyes WITH CHECK blocks a direct self-approval ---
def test_rls_blocks_direct_self_approval(pg_stack: SimpleNamespace) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    req = _seed_user(pg_stack.owner_libpq, tid, "req21", "owner")
    appr = _seed_approval(pg_stack.owner_libpq, tid, req)
    # As nlw_app, with the requester's own context, a direct self-approval UPDATE is
    # rejected by the RLS WITH CHECK (decided_by <> requested_by_user_id): a WITH
    # CHECK violation RAISES (SQLSTATE 42501), it does not silently update 0 rows.
    with psycopg.connect(pg_stack.app_libpq, autocommit=True) as c:
        c.execute("SELECT set_config('app.user_id', %s, false)", (str(req),))
        c.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tid),))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(
                "UPDATE approvals SET status='approved', decided_by=%s, decided_at=now() "
                "WHERE id=%s",
                (req, appr),
            )
    assert _status(pg_stack.owner_libpq, appr) == "pending"  # unchanged (fail closed)


# --- requester_unknown (legacy) fails closed for decision ---
def test_unknown_requester_fails_closed(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    _seed_user(pg_stack.owner_libpq, tid, "adm-u", "owner")
    appr = _seed_approval(pg_stack.owner_libpq, tid, None)  # NULL requester (legacy)
    h = {**_auth("adm-u", "adm-u@x.com"), "X-Workspace-Id": str(tid)}
    r = client.post(f"/approvals/{appr}/approve", headers=h)
    assert r.status_code == 409 and "no recorded requester" in r.json()["error"]["message"]
