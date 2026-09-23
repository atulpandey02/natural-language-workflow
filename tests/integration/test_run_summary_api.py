"""Summary endpoint confidentiality (M12B-A addendum, Part 5).

The grounded summary applies tenant authorization (another tenant gets 404),
consumes only bounded persisted state, and NEVER surfaces raw tool output — it
reports a per-step outcome + a bounded detail + a has-output boolean only.
UNKNOWN/FAILED/SKIPPED are reported exactly (test_ai_core_smoke.py); malicious
text inside tool output cannot change the classification (test_run_summary.py).
"""

import time
import uuid
from types import SimpleNamespace

import jwt
import pytest
from fastapi.testclient import TestClient

from nlw.api.app import create_app
from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.domain.workflow import WorkflowPlan
from nlw.engine.execution import execute_advancement
from nlw.engine.runs import create_run, create_workflow_with_version
from nlw.tenancy.keys import process_signer
from nlw.tenancy.session import apply_signed_context_sync
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

ISSUER = "https://proj.supabase.co/auth/v1"
SECRET = "dev-secret-for-tests-32bytes-min-length"
SENTINEL = "OUTPUT-SECRET-must-not-surface-99"


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


@pytest.fixture
def sms(pg_stack: SimpleNamespace) -> object:
    app_engine = create_sync_engine(pg_stack.settings)
    worker_engine = create_sync_engine(pg_stack.worker_settings)
    try:
        yield SimpleNamespace(
            app=create_sync_sessionmaker(app_engine),
            worker=create_sync_sessionmaker(worker_engine),
        )
    finally:
        app_engine.dispose()
        worker_engine.dispose()


def _seed_completed_run(
    sms: SimpleNamespace, user_id: uuid.UUID, tenant_id: uuid.UUID
) -> uuid.UUID:
    # fake.echo echoes its args into the step output, so SENTINEL lands in the
    # durable step_runs.output — the summary must never surface it.
    plan = WorkflowPlan.model_validate(
        {"steps": [{"id": "a", "tool": "fake.echo", "args": {"note": SENTINEL}}]}
    )
    with sms.app() as s, s.begin():
        apply_signed_context_sync(
            s, process_signer(Purpose.API_REQUEST).sign(user_id=user_id, tenant_id=tenant_id)
        )
        wf, ver = create_workflow_with_version(s, tenant_id, "wf", plan)
        run = create_run(s, tenant_id, wf.id, ver.id)
        run_id = run.id
    for _ in range(4):
        if execute_advancement(sms.worker, run_id).result in ("completed", "failed", "noop"):
            break
    return run_id


def test_summary_endpoint_isolation_and_no_raw_output(
    pg_stack: SimpleNamespace, sms: SimpleNamespace
) -> None:
    app = create_app(pg_stack.settings)
    client = TestClient(app)
    client.__enter__()

    owner = {**_auth("sum-owner", "owner@x.com")}
    ws = client.post("/workspaces", json={"name": "W"}, headers=owner).json()["id"]
    owner = {**owner, "X-Workspace-Id": ws}
    user_id = uuid.UUID(client.get("/me", headers=owner).json()["id"])
    run_id = _seed_completed_run(sms, user_id, uuid.UUID(ws))

    # Owner sees a grounded summary; it never contains the raw output sentinel.
    resp = client.get(f"/runs/{run_id}/summary", headers=owner)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["outcome"] == "COMPLETED" and body["succeeded"] == 1
    assert SENTINEL not in resp.text  # raw tool output is never surfaced
    step = body["steps"][0]
    assert step["outcome"] == "SUCCESS" and len(step["detail"]) <= 240
    assert "note" not in step["detail"]  # arg keys/values are not echoed

    # The sentinel IS in the durable output (sanity: the summary is what hides it).
    import psycopg

    with psycopg.connect(pg_stack.owner_libpq) as c:
        out = c.execute("SELECT output::text FROM step_runs WHERE run_id=%s", (run_id,)).fetchone()
    assert out is not None and SENTINEL in out[0]

    # A different tenant cannot read the summary at all.
    other = {**_auth("sum-other", "other@x.com")}
    ws2 = client.post("/workspaces", json={"name": "W2"}, headers=other).json()["id"]
    other = {**other, "X-Workspace-Id": ws2}
    assert client.get(f"/runs/{run_id}/summary", headers=other).status_code == 404
