"""Run read endpoints: detail, steps (bounded output), action audit (M10)."""

import json
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
AUD = "authenticated"
SECRET = "dev-secret-for-tests-32bytes-min-length"
_PLAN = {"steps": [{"id": "a", "tool": "fake.echo", "args": {}}]}


def _auth_for(user_id: uuid.UUID) -> dict[str, str]:
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


def _seed_run_with_step(
    owner: str, tenant: uuid.UUID, *, output: dict[str, object], status: str = "COMPLETED"
) -> tuple[uuid.UUID, uuid.UUID]:
    wf, ver, run = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf, tenant))
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,%s::jsonb)",
            (ver, tenant, wf, json.dumps(_PLAN)),
        )
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status, "
            "trigger) VALUES (%s,%s,%s,%s,%s,'manual')",
            (run, tenant, wf, ver, status),
        )
        c.execute(
            "INSERT INTO step_runs (id, tenant_id, run_id, step_id, tool, status, attempt, output) "
            "VALUES (%s,%s,%s,'a','fake.echo','SUCCESS',1,%s::jsonb)",
            (uuid.uuid4(), tenant, run, json.dumps(output)),
        )
    return wf, run


def _seed_action(owner: str, tenant: uuid.UUID, run: uuid.UUID) -> None:
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute(
            "INSERT INTO external_actions (id, tenant_id, run_id, step_id, connector_id, tool, "
            "external_action_key, destination_summary, status, attempts, http_status) "
            "VALUES (%s,%s,%s,'notify',%s,'webhook.send',%s,'hooks.example.com','success',1,200)",
            (uuid.uuid4(), tenant, run, uuid.uuid4(), uuid.uuid4()),
        )


@pytest.fixture
def client(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    with TestClient(create_app(pg_stack.settings)) as c:
        yield c


def test_list_and_get_run(client: TestClient, pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    wf, run = _seed_run_with_step(pg_stack.owner_libpq, m.tenant_id, output={"ok": True})
    h = {**_auth_for(m.user_id), "X-Workspace-Id": str(m.tenant_id)}

    runs = client.get("/runs", headers=h).json()
    assert [r["id"] for r in runs] == [str(run)]
    assert runs[0]["trigger"] == "manual"

    filtered = client.get(f"/runs?workflow_id={wf}&status=COMPLETED", headers=h).json()
    assert [r["id"] for r in filtered] == [str(run)]

    detail = client.get(f"/runs/{run}", headers=h).json()
    assert detail["status"] == "COMPLETED"


def test_steps_return_bounded_output(client: TestClient, pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _, small = _seed_run_with_step(pg_stack.owner_libpq, m.tenant_id, output={"rows": [1, 2, 3]})
    _, big = _seed_run_with_step(pg_stack.owner_libpq, m.tenant_id, output={"blob": "x" * 8000})
    h = {**_auth_for(m.user_id), "X-Workspace-Id": str(m.tenant_id)}

    small_steps = client.get(f"/runs/{small}/steps", headers=h).json()
    assert small_steps[0]["output_truncated"] is False
    assert small_steps[0]["output_preview"] == {"rows": [1, 2, 3]}

    big_steps = client.get(f"/runs/{big}/steps", headers=h).json()
    assert big_steps[0]["output_truncated"] is True
    assert big_steps[0]["output_preview"] == {"_truncated": True}
    assert "x" * 8000 not in json.dumps(big_steps)  # raw output never leaks


def test_actions_are_secret_free(client: TestClient, pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _, run = _seed_run_with_step(pg_stack.owner_libpq, m.tenant_id, output={})
    _seed_action(pg_stack.owner_libpq, m.tenant_id, run)
    h = {**_auth_for(m.user_id), "X-Workspace-Id": str(m.tenant_id)}

    actions = client.get(f"/runs/{run}/actions", headers=h).json()
    assert actions[0]["destination_summary"] == "hooks.example.com"
    assert actions[0]["http_status"] == 200
    # Audit shape carries no secret/body fields.
    keys = set(actions[0].keys())
    for forbidden in ("secret", "secret_ref", "auth_header", "body", "lease_token", "config"):
        assert forbidden not in keys


def test_runs_tenant_isolated(client: TestClient, pg_stack: SimpleNamespace) -> None:
    a = pg_stack.seed_member()
    _, run = _seed_run_with_step(pg_stack.owner_libpq, a.tenant_id, output={})
    b = pg_stack.seed_member()
    hb = {**_auth_for(b.user_id), "X-Workspace-Id": str(b.tenant_id)}
    assert client.get("/runs", headers=hb).json() == []
    assert client.get(f"/runs/{run}", headers=hb).status_code == 404
