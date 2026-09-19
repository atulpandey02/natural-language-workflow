"""Schedule API (M8): admin/owner gate (role + RLS), tenant isolation,
server-owned created_by, immutable version pin, validation, disable-over-delete.
"""

import time
import uuid
from collections.abc import Iterator
from types import SimpleNamespace

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

from nlw.api.app import create_app

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


@pytest.fixture
def client(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    with TestClient(create_app(pg_stack.settings)) as c:
        yield c


def _seed_workflow(owner: str, tenant: uuid.UUID, *, with_version: bool = True) -> uuid.UUID:
    wf = uuid.uuid4()
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf, tenant))
        if with_version:
            ver = uuid.uuid4()
            c.execute(
                "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
                "VALUES (%s,%s,%s,1,'{\"steps\":[]}'::jsonb)",
                (ver, tenant, wf),
            )
            c.execute("UPDATE workflows SET current_version_id=%s WHERE id=%s", (ver, wf))
    return wf


def _seed_member(owner: str, tenant: uuid.UUID, sub: str, role: str) -> uuid.UUID:
    uid = uuid.uuid4()
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute(
            "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s)",
            (uid, sub, f"{sub}@x.com"),
        )
        c.execute(
            "INSERT INTO memberships (id, user_id, workspace_id, role) VALUES (%s,%s,%s,%s)",
            (uuid.uuid4(), uid, tenant, role),
        )
    return uid


def _daily(wf: uuid.UUID) -> dict[str, object]:
    return {
        "workflow_id": str(wf),
        "timezone": "America/New_York",
        "frequency": "daily",
        "minute": 0,
        "hour": 9,
    }


def test_admin_creates_schedule_pins_version_and_created_by(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    h = {**_auth("sch-owner")}
    ws = str(client.post("/workspaces", json={"name": "W"}, headers=h).json()["id"])
    h = {**h, "X-Workspace-Id": ws}
    wf = _seed_workflow(pg_stack.owner_libpq, uuid.UUID(ws))

    resp = client.post("/schedules", json=_daily(wf), headers=h)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["frequency"] == "daily" and body["enabled"] is True
    assert body["next_run_at"]  # computed
    # created_by is server-owned = the authenticated owner (req 6); version pinned.
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT s.created_by, s.workflow_version_id, w.current_version_id "
            "FROM schedules s JOIN workflows w ON w.id=s.workflow_id WHERE s.id=%s",
            (body["id"],),
        ).fetchone()
        me = c.execute("SELECT id FROM users WHERE auth_provider_id='sch-owner'").fetchone()
    assert row is not None and me is not None
    assert row[0] == me[0]  # created_by = authenticated user
    assert row[1] == row[2]  # pinned == current version at creation


def test_member_cannot_create_schedule(client: TestClient, pg_stack: SimpleNamespace) -> None:
    admin = {**_auth("sch-adm")}
    ws = str(client.post("/workspaces", json={"name": "W"}, headers=admin).json()["id"])
    wf = _seed_workflow(pg_stack.owner_libpq, uuid.UUID(ws))
    _seed_member(pg_stack.owner_libpq, uuid.UUID(ws), "sch-mem", "member")
    hm = {**_auth("sch-mem"), "X-Workspace-Id": ws}
    assert client.post("/schedules", json=_daily(wf), headers=hm).status_code == 403


def test_workflow_without_version_rejected(client: TestClient, pg_stack: SimpleNamespace) -> None:
    h = {**_auth("sch-nv")}
    ws = str(client.post("/workspaces", json={"name": "W"}, headers=h).json()["id"])
    h = {**h, "X-Workspace-Id": ws}
    wf = _seed_workflow(pg_stack.owner_libpq, uuid.UUID(ws), with_version=False)
    assert client.post("/schedules", json=_daily(wf), headers=h).status_code == 422


def test_invalid_recurrence_rejected(client: TestClient, pg_stack: SimpleNamespace) -> None:
    h = {**_auth("sch-inv")}
    ws = str(client.post("/workspaces", json={"name": "W"}, headers=h).json()["id"])
    h = {**h, "X-Workspace-Id": ws}
    wf = _seed_workflow(pg_stack.owner_libpq, uuid.UUID(ws))
    bad_tz = {**_daily(wf), "timezone": "Mars/Phobos"}
    assert client.post("/schedules", json=bad_tz, headers=h).status_code == 422
    weekly_no_dow = {
        "workflow_id": str(wf),
        "timezone": "UTC",
        "frequency": "weekly",
        "minute": 0,
        "hour": 9,
    }
    assert client.post("/schedules", json=weekly_no_dow, headers=h).status_code == 422


def test_disable_and_list(client: TestClient, pg_stack: SimpleNamespace) -> None:
    h = {**_auth("sch-dis")}
    ws = str(client.post("/workspaces", json={"name": "W"}, headers=h).json()["id"])
    h = {**h, "X-Workspace-Id": ws}
    wf = _seed_workflow(pg_stack.owner_libpq, uuid.UUID(ws))
    sid = client.post("/schedules", json=_daily(wf), headers=h).json()["id"]

    assert len(client.get("/schedules", headers=h).json()) == 1
    disabled = client.delete(f"/schedules/{sid}", headers=h)
    assert disabled.status_code == 200 and disabled.json()["enabled"] is False


def test_cross_tenant_isolation(client: TestClient, pg_stack: SimpleNamespace) -> None:
    a = {**_auth("sch-a")}
    ws_a = str(client.post("/workspaces", json={"name": "A"}, headers=a).json()["id"])
    ha = {**a, "X-Workspace-Id": ws_a}
    wf = _seed_workflow(pg_stack.owner_libpq, uuid.UUID(ws_a))
    sid = client.post("/schedules", json=_daily(wf), headers=ha).json()["id"]

    b = {**_auth("sch-b")}
    ws_b = str(client.post("/workspaces", json={"name": "B"}, headers=b).json()["id"])
    hb = {**b, "X-Workspace-Id": ws_b}
    assert client.get("/schedules", headers=hb).json() == []
    assert client.get(f"/schedules/{sid}", headers=hb).status_code == 404
    assert client.patch(f"/schedules/{sid}", json={"enabled": False}, headers=hb).status_code == 404
