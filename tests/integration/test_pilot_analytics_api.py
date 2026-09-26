"""Real planner/feasibility/materialization/Redis/worker/Postgres golden paths."""

import json
import os
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jwt
import psycopg
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from testcontainers.community.redis import RedisContainer

from nlw.api.app import create_app
from nlw.api.deps import get_llm_provider
from nlw.api.routers import approvals, workflows
from nlw.core.config import Settings
from nlw.planner.provider import LLMRequest, LLMResult
from nlw.planner.schema import PlannerOutput
from nlw.secrets.store import env_key_for
from nlw.tenancy.signing import Purpose
from nlw.worker.actors import advance_run
from nlw.worker.broker import make_broker

pytestmark = pytest.mark.integration
SECRET = "dev-secret-for-tests-32bytes-min-length"


def auth(sub: str) -> dict[str, str]:
    return {
        "Authorization": "Bearer "
        + jwt.encode(
            {
                "iss": "https://proj.supabase.co/auth/v1",
                "aud": "authenticated",
                "exp": int(time.time()) + 600,
                "sub": sub,
                "email": f"{sub}@example.test",
            },
            SECRET,
            algorithm="HS256",
        )
    }


class GoldenProvider:
    """Deterministic provider fixture; real planner parsing and feasibility follow."""

    async def generate_plan(self, req: LLMRequest) -> LLMResult:
        context = json.loads(req.user.split("\n\n", 1)[1])
        prompt = context["user_request"].lower()
        dataset = "support" if "support-v1" in prompt else "sales"
        tool = f"pilot.{dataset}_analysis"
        assert any(t["name"] == tool for t in context["capabilities"]["tools"])
        output = PlannerOutput.model_validate(
            {
                "workflow_name": f"Pilot {dataset} analysis",
                "steps": [
                    {"id": "analyze", "tool": tool, "args": {"dataset_version": "v1", "months": 6}}
                ],
            }
        )
        return LLMResult(raw_json=output.model_dump_json(), model="test-golden-1")


@pytest.fixture
def pilot(
    pg_stack: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> Iterator[SimpleNamespace]:
    with RedisContainer("redis:7") as redis_c:
        redis_url = f"redis://{redis_c.get_container_host_ip()}:{redis_c.get_exposed_port(6379)}/0"
        broker = make_broker(Settings(_env_file=None, redis_url=redis_url))  # type: ignore[call-arg]
        broker.declare_queue("default")

        def enqueue(rid: uuid.UUID) -> None:
            broker.enqueue(advance_run.message(str(rid)))

        monkeypatch.setattr(workflows, "_enqueue_advance", enqueue)
        monkeypatch.setattr(approvals, "_enqueue_advance", lambda request, rid: enqueue(rid))
        app = create_app(pg_stack.settings)
        app.dependency_overrides[get_llm_provider] = GoldenProvider
        with TestClient(app) as client:
            owner = auth("pilot-owner")
            ws = client.post("/workspaces", json={"name": "Pilot"}, headers=owner).json()["id"]
            owner["X-Workspace-Id"] = ws
            other = auth("pilot-other")
            other["X-Workspace-Id"] = client.post(
                "/workspaces", json={"name": "Other"}, headers=other
            ).json()["id"]
            approver = auth("pilot-approver")
            approver_id = client.get("/me", headers=approver).json()["id"]
            member = auth("pilot-member")
            member_id = client.get("/me", headers=member).json()["id"]
            with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as conn:
                for uid, role in ((approver_id, "admin"), (member_id, "member")):
                    conn.execute(
                        "INSERT INTO memberships (id,user_id,workspace_id,role) "
                        "VALUES (%s,%s,%s,%s)",
                        (uuid.uuid4(), uid, ws, role),
                    )
            approver["X-Workspace-Id"] = ws
            member["X-Workspace-Id"] = ws
            connector = client.post(
                "/connectors",
                json={
                    "name": "pilot-slack",
                    "type": "slack",
                    "config": {
                        "workspace_label": "Synthetic",
                        "default_channel": "CPILOT",
                        "allowed_channels": ["CPILOT", "CSECOND"],
                    },
                    "secret_ref": "PILOT_TEST",
                },
                headers=owner,
            )
            assert connector.status_code == 201, connector.text
            worker_log = (tmp_path / "worker.log").open("w")
            worker = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "dramatiq",
                    "pilot_worker",
                    "--processes",
                    "1",
                    "--threads",
                    "1",
                ],
                env={
                    **os.environ,
                    "PYTHONPATH": "tests/integration:src",
                    "APP_ENV": "local",
                    "REDIS_URL": redis_url,
                    "DATABASE_URL": pg_stack.worker_settings.database_url,
                    "NLW_CTX_KEY_ID": str(pg_stack.worker_settings.ctx_key_id),
                    "NLW_CTX_KEY_FILE": str(pg_stack.worker_settings.ctx_key_file),
                    "METRICS_ENABLED": "false",
                    "PILOT_DELIVERY_EVIDENCE": str(tmp_path / "delivery.jsonl"),
                    "PILOT_DELIVERY_OUTCOME": getattr(request, "param", "success"),
                    env_key_for(uuid.UUID(ws), "PILOT_TEST"): "synthetic-test-only",
                },
                stdout=worker_log,
                stderr=subprocess.STDOUT,
            )
            try:
                yield SimpleNamespace(
                    client=client,
                    owner=owner,
                    other=other,
                    member=member,
                    approver=approver,
                    connector=connector.json(),
                    enqueue=enqueue,
                    pg=pg_stack,
                    evidence=tmp_path / "delivery.jsonl",
                    worker=worker,
                    broker=broker,
                )
            finally:
                worker.terminate()
                worker.wait(timeout=15)
                worker_log.close()
                broker.close()


def wait_status(pilot: SimpleNamespace, rid: str, desired: str) -> dict[str, Any]:
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        response = pilot.client.get(f"/runs/{rid}", headers=pilot.owner)
        assert response.status_code == 200, response.text
        state = response.json()
        if state["status"] == desired:
            return dict(state)
        if state["status"] == "FAILED":
            raise AssertionError(
                pilot.client.get(f"/runs/{rid}/summary", headers=pilot.owner).json()
            )
        time.sleep(0.1)
    raise AssertionError(f"Run did not reach {desired}")


def start_proposal(pilot: SimpleNamespace, pid: str) -> str:
    mat = pilot.client.post(f"/plans/{pid}/materialize", headers=pilot.owner)
    assert mat.status_code == 200, mat.text
    response = pilot.client.post(
        f"/workflows/{mat.json()['workflow_id']}/runs",
        headers={**pilot.owner, "Idempotency-Key": uuid.uuid4().hex},
    )
    assert response.status_code in (200, 201, 202), response.text
    return str(response.json()["run_id"])


def analysis(pilot: SimpleNamespace, dataset: str = "sales-v1") -> str:
    response = pilot.client.post(
        "/plans", json={"prompt": f"Analyze the last six months of {dataset}."}, headers=pilot.owner
    )
    assert response.status_code == 201 and response.json()["status"] == "PASS", response.text
    rid = start_proposal(pilot, response.json()["id"])
    pilot.enqueue(uuid.UUID(rid))  # deliberate duplicate wake-up
    wait_status(pilot, rid, "COMPLETED")
    return rid


def handoff(pilot: SimpleNamespace, rid: str) -> dict[str, Any]:
    response = pilot.client.post(
        f"/runs/{rid}/slack-proposal",
        json={"connector_id": pilot.connector["id"], "channel": "CPILOT"},
        headers=pilot.owner,
    )
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "NEEDS_APPROVAL"
    return dict(response.json())


def test_three_golden_journeys_and_authorization(pilot: SimpleNamespace) -> None:
    for dataset in ("sales-v1", "support-v1"):
        rid = analysis(pilot, dataset)
        response = pilot.client.get(f"/runs/{rid}/analytics", headers=pilot.member)
        assert response.status_code == 200, response.text
        result = response.json()
        assert result["status"] == "READY" and len(result["metrics"]) == 4
        assert len(result["visualizations"]) >= 4 and result["findings"]
        assert result["freshness"][0]["dataset"] == dataset
        assert result["source_step_ids"] == ["analyze"]
        assert pilot.client.get(f"/runs/{rid}/analytics", headers=pilot.other).status_code == 404
        assert pilot.client.get(f"/runs/{rid}/analytics").status_code == 401
        with psycopg.connect(pilot.pg.owner_libpq) as conn:
            rows = conn.execute(
                "SELECT status,attempt FROM step_runs WHERE run_id=%s", (rid,)
            ).fetchall()
            assert rows == [("SUCCESS", 1)]
        pilot.enqueue(uuid.UUID(rid))
    proposal = handoff(pilot, rid)
    binding = proposal["analytics_source"]
    assert binding["source_run_id"] == rid and binding["contract_version"] == "analytics-1"
    assert binding["connector_id"] == pilot.connector["id"] and binding["channel"] == "CPILOT"
    message = proposal["proposed_plan"]["steps"][0]["args"]["text"]
    assert message not in pilot.client.get("/plans", headers=pilot.owner).text
    assert "Synthetic pilot analysis" not in pilot.client.get("/plans", headers=pilot.owner).text
    shared_run = start_proposal(pilot, proposal["id"])
    wait_status(pilot, shared_run, "WAITING_APPROVAL")
    approval = pilot.client.get("/approvals", headers=pilot.owner).json()[0]
    assert approval["preview"]["args"]["text"] == message
    assert approval["destination"] == "CPILOT" and not approval["viewer_can_decide"]
    assert (
        pilot.client.post(f"/approvals/{approval['id']}/approve", headers=pilot.owner).status_code
        == 403
    )
    assert not pilot.evidence.exists()
    assert (
        pilot.client.post(
            f"/approvals/{approval['id']}/approve", headers=pilot.approver
        ).status_code
        == 200
    )
    wait_status(pilot, shared_run, "COMPLETED")
    sent = [json.loads(line) for line in pilot.evidence.read_text().splitlines()]
    assert sent == [{"text": message, "channel": "CPILOT"}]
    assert (
        "synthetic-test-only"
        not in pilot.client.get(f"/runs/{shared_run}/analytics", headers=pilot.owner).text
    )
    assert (
        pilot.client.get(f"/runs/{shared_run}/analytics", headers=pilot.owner).json()["status"]
        == "EMPTY"
    )


@pytest.mark.parametrize("drift", ["output", "connector", "missing", "status"])
def test_handoff_drift_fails_closed(pilot: SimpleNamespace, drift: str) -> None:
    rid = analysis(pilot)
    proposal = handoff(pilot, rid)
    with psycopg.connect(pilot.pg.owner_libpq, autocommit=True) as conn:
        if drift == "output":
            conn.execute(
                "UPDATE step_runs SET output=jsonb_set(output,'{totals,0}','999') WHERE run_id=%s",
                (rid,),
            )
        elif drift == "connector":
            conn.execute(
                "UPDATE connectors SET config=jsonb_set(config,'{default_channel}','\"CSECOND\"') "
                "WHERE id=%s",
                (pilot.connector["id"],),
            )
        elif drift == "missing":
            conn.execute("UPDATE step_runs SET output=NULL WHERE run_id=%s", (rid,))
        else:
            conn.execute("UPDATE workflow_runs SET status='FAILED' WHERE id=%s", (rid,))
    response = pilot.client.post(f"/plans/{proposal['id']}/materialize", headers=pilot.owner)
    assert response.status_code == 409 and "STALE_ANALYTICS_SOURCE" in response.text
    assert not pilot.evidence.exists()


def test_handoff_rejects_browser_text_cross_tenant_and_disallowed_destination(
    pilot: SimpleNamespace,
) -> None:
    rid = analysis(pilot)
    endpoint = f"/runs/{rid}/slack-proposal"
    body = {"connector_id": pilot.connector["id"], "channel": "CPILOT"}
    assert (
        pilot.client.post(
            endpoint, json={**body, "text": "arbitrary browser text"}, headers=pilot.owner
        ).status_code
        == 422
    )
    assert pilot.client.post(endpoint, json=body, headers=pilot.other).status_code == 404
    assert (
        pilot.client.post(
            endpoint, json={**body, "channel": "CFOREIGN"}, headers=pilot.owner
        ).status_code
        == 422
    )
    assert (
        pilot.client.post(
            endpoint, json={**body, "connector_id": str(uuid.uuid4())}, headers=pilot.owner
        ).status_code
        == 404
    )


def test_migration_roundtrip_and_handoff_immutability(pg_stack: SimpleNamespace) -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", pg_stack.owner_sa)
    command.downgrade(cfg, "0020_schedule_authorization")
    command.upgrade(cfg, "head")
    with psycopg.connect(pg_stack.owner_libpq) as conn:
        row = conn.execute(
            "SELECT has_column_privilege('nlw_app','plan_proposals','analytics_source','UPDATE'), "
            "has_column_privilege('nlw_app','plan_proposals','analytics_source','INSERT'), "
            "relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname='plan_proposals'"
        ).fetchone()
    assert row == (False, True, True, True)
    member = pg_stack.seed_member()
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        pg_stack.run_as(
            pg_stack.app_libpq,
            Purpose.API_REQUEST,
            "UPDATE plan_proposals SET analytics_source=NULL",
            user_id=member.user_id,
            tenant_id=member.tenant_id,
        )


@pytest.mark.parametrize("pilot", ["unknown"], indirect=True)
def test_golden_slack_ambiguity_is_terminal_unknown(pilot: SimpleNamespace) -> None:
    source = analysis(pilot, "support-v1")
    proposal = handoff(pilot, source)
    rid = start_proposal(pilot, proposal["id"])
    wait_status(pilot, rid, "WAITING_APPROVAL")
    approval = pilot.client.get("/approvals", headers=pilot.approver).json()[0]
    assert (
        pilot.client.post(
            f"/approvals/{approval['id']}/approve", headers=pilot.approver
        ).status_code
        == 200
    )
    wait_status(pilot, rid, "FAILED")
    pilot.enqueue(uuid.UUID(rid))
    pilot.enqueue(uuid.UUID(rid))
    pilot.broker.join("default", timeout=10000)
    summary = pilot.client.get(f"/runs/{rid}/summary", headers=pilot.owner).json()
    assert summary["outcome"] == "FAILED_WITH_UNKNOWN"
    assert summary["steps"][0]["outcome"] == "UNKNOWN"
    assert len(pilot.evidence.read_text().splitlines()) == 1
    assert (
        pilot.client.get(f"/runs/{source}/analytics", headers=pilot.owner).json()["status"]
        == "READY"
    )


def test_stale_connector_after_approval_blocks_before_io(
    pilot: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = analysis(pilot)
    rid = start_proposal(pilot, handoff(pilot, source)["id"])
    wait_status(pilot, rid, "WAITING_APPROVAL")
    approval = pilot.client.get("/approvals", headers=pilot.approver).json()[0]
    # Hold the wake-up (not the decision) to model connector drift before resume.
    monkeypatch.setattr(approvals, "_enqueue_advance", lambda request, run_id: None)
    assert (
        pilot.client.post(
            f"/approvals/{approval['id']}/approve", headers=pilot.approver
        ).status_code
        == 200
    )
    with psycopg.connect(pilot.pg.owner_libpq, autocommit=True) as conn:
        conn.execute(
            "UPDATE connectors SET status='disabled' WHERE id=%s", (pilot.connector["id"],)
        )
    pilot.enqueue(uuid.UUID(rid))
    wait_status(pilot, rid, "FAILED")
    assert not pilot.evidence.exists()
    assert "STALE_PLAN" in pilot.client.get(f"/runs/{rid}/summary", headers=pilot.owner).text


def test_raw_output_and_missing_source_provenance_fail_closed(pilot: SimpleNamespace) -> None:
    rid = analysis(pilot)
    proposal = handoff(pilot, rid)
    with psycopg.connect(pilot.pg.owner_libpq, autocommit=True) as conn:
        conn.execute(
            'UPDATE step_runs SET output=output || \'{"raw_secret":"DO-NOT-RETURN"}\'::jsonb '
            "WHERE run_id=%s",
            (rid,),
        )
        conn.execute(
            "UPDATE plan_proposals SET analytics_source=NULL WHERE id=%s", (proposal["id"],)
        )
    response = pilot.client.get(f"/runs/{rid}/analytics", headers=pilot.owner)
    assert response.json()["status"] == "INVALID"
    assert "DO-NOT-RETURN" not in response.text and response.json()["metrics"] == []
    assert (
        pilot.client.post(f"/plans/{proposal['id']}/materialize", headers=pilot.owner).status_code
        == 409
    )
    assert (
        pilot.client.post(
            f"/runs/{rid}/slack-proposal",
            json={"connector_id": pilot.connector["id"]},
            headers=pilot.owner,
        ).status_code
        == 409
    )
