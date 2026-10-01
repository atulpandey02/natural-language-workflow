"""The staging role-check script against the REAL run endpoints.

Regression for PR #42: the script read ``id`` from ``POST /workflows/{id}/runs``
while the API returns ``run_id`` (``RunCreateOut``). Its unit fakes shared the
wrong shape, so only the seeded CI stack exposed it. Here the script's own
``trigger_run`` / ``wait_for_worker`` talk to the real FastAPI app.
"""

import importlib.util
import json
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

import nlw.api.routers.workflows as workflows_mod
from nlw.api.app import create_app

pytestmark = pytest.mark.integration

SECRET = "dev-secret-for-tests-32bytes-min-length"

_spec = importlib.util.spec_from_file_location(
    "staging_role_check_contract",
    Path(__file__).resolve().parents[2] / "scripts" / "ci" / "staging_role_check.py",
)
assert _spec and _spec.loader
rc = importlib.util.module_from_spec(_spec)
sys.modules["staging_role_check_contract"] = rc
_spec.loader.exec_module(rc)


def _auth_for(user_id: uuid.UUID) -> dict[str, str]:
    token = jwt.encode(
        {
            "iss": "https://proj.supabase.co/auth/v1",
            "aud": "authenticated",
            "exp": int(time.time()) + 300,
            "sub": f"sub-{user_id}",
            "email": f"{user_id}@example.com",
        },
        SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def _seed_runnable_workflow(owner: str, tenant: uuid.UUID) -> uuid.UUID:
    wf, ver = uuid.uuid4(), uuid.uuid4()
    plan = {"steps": [{"id": "a", "tool": "fake.echo", "args": {}}]}
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf, tenant))
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,%s::jsonb)",
            (ver, tenant, wf, json.dumps(plan)),
        )
        c.execute("UPDATE workflows SET current_version_id=%s WHERE id=%s", (ver, wf))
    return wf


def test_script_triggers_and_reads_a_run_through_the_real_api(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(workflows_mod, "_enqueue_advance", lambda _run_id: None)  # no worker
    m = pg_stack.seed_member()
    wf = _seed_runnable_workflow(pg_stack.owner_libpq, m.tenant_id)
    headers = {
        **_auth_for(m.user_id),
        "X-Workspace-Id": str(m.tenant_id),
        "Idempotency-Key": "role-check-contract",
    }

    with TestClient(create_app(pg_stack.settings)) as client:

        def http(method: str, url: str, hdrs: dict[str, str]) -> tuple[int, bytes]:
            path = url.removeprefix("http://api")
            if method == "POST":
                resp = client.post(path, headers=hdrs)
            else:
                resp = client.get(path, headers=hdrs)
            return resp.status_code, resp.content

        run_id = rc.trigger_run(http, "http://api", headers, str(wf))
        assert str(uuid.UUID(run_id)) == run_id
        # No worker runs here, so the bounded poll must read the real RunOut
        # status (PENDING) and then fail at its deadline, never pass.
        with pytest.raises(rc.CheckFailed, match=r"within 0s \(status PENDING\)"):
            rc.wait_for_worker(http, "http://api", headers, run_id, deadline_s=0)
