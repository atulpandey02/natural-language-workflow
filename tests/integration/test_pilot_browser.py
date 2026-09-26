"""Opt-in real-browser harness. Local Supabase only; no cloud/provider traffic.

PILOT_AUTH_CONFIG points to `supabase status -o json` for a disposable LOCAL
project. Ordinary pytest skips this expensive browser check; the release task
runs it explicitly after building the frontend.
"""

import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse

import httpx
import psycopg
import pytest
import uvicorn
from test_pilot_analytics_api import GoldenProvider
from testcontainers.community.redis import RedisContainer

from nlw.api.app import create_app
from nlw.api.deps import get_llm_provider
from nlw.api.routers import approvals, workflows
from nlw.core.config import Settings
from nlw.secrets.store import env_key_for
from nlw.worker.actors import advance_run
from nlw.worker.broker import make_broker

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("PILOT_AUTH_CONFIG"), reason="local browser harness is opt-in"
    ),
]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_pilot_browser(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    auth = json.loads(Path(os.environ["PILOT_AUTH_CONFIG"]).read_text())
    auth_url = auth["API_URL"]
    assert urlparse(auth_url).hostname in {"127.0.0.1", "localhost"}, (
        "Only local synthetic auth is allowed"
    )
    api_port, web_port = free_port(), free_port()
    api_url = f"http://127.0.0.1:{api_port}"
    web_url = f"http://127.0.0.1:{web_port}"
    settings = pg_stack.settings.model_copy(
        update={
            "supabase_url": auth_url,
            "supabase_jwt_secret": auth.get("JWT_SECRET"),
            "supabase_jwks_url": f"{auth_url}/auth/v1/.well-known/jwks.json",
            "supabase_jwt_issuer": f"{auth_url}/auth/v1",
        }
    )
    identities = {}
    with httpx.Client(timeout=15) as client:
        for role in ("owner", "approver", "other"):
            email = f"pilot-{role}-{uuid.uuid4().hex[:8]}@example.test"
            password = uuid.uuid4().hex + "Aa1!"
            response = client.post(
                f"{auth_url}/auth/v1/admin/users",
                headers={
                    "apikey": auth["SERVICE_ROLE_KEY"],
                    "Authorization": f"Bearer {auth['SERVICE_ROLE_KEY']}",
                },
                json={"email": email, "password": password, "email_confirm": True},
            )
            assert response.status_code in (200, 201)
            login = client.post(
                f"{auth_url}/auth/v1/token?grant_type=password",
                headers={"apikey": auth["ANON_KEY"]},
                json={"email": email, "password": password},
            )
            assert login.status_code == 200
            identities[role] = {
                "email": email,
                "password": password,
                "token": login.json()["access_token"],
            }
    with RedisContainer("redis:7") as redis_c:
        redis_url = f"redis://{redis_c.get_container_host_ip()}:{redis_c.get_exposed_port(6379)}/0"
        broker = make_broker(Settings(_env_file=None, redis_url=redis_url))  # type: ignore[call-arg]
        broker.declare_queue("default")

        def enqueue(rid: uuid.UUID) -> None:
            broker.enqueue(advance_run.message(str(rid)))

        monkeypatch.setattr(workflows, "_enqueue_advance", enqueue)
        monkeypatch.setattr(approvals, "_enqueue_advance", lambda request, rid: enqueue(rid))
        app = create_app(settings)
        app.dependency_overrides[get_llm_provider] = GoldenProvider
        server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=api_port, log_level="warning")
        )
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.monotonic() + 20
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.1)
        assert server.started
        with httpx.Client(base_url=api_url, timeout=15) as client:
            owner = {"Authorization": f"Bearer {identities['owner']['token']}"}
            ws = client.post("/workspaces", headers=owner, json={"name": "Pilot Analytics"}).json()[
                "id"
            ]
            owner["X-Workspace-Id"] = ws
            other = {"Authorization": f"Bearer {identities['other']['token']}"}
            assert (
                client.post("/workspaces", headers=other, json={"name": "Other Tenant"}).status_code
                == 201
            )
            approver = {"Authorization": f"Bearer {identities['approver']['token']}"}
            approver_id = client.get("/me", headers=approver).json()["id"]
            with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as conn:
                conn.execute(
                    "INSERT INTO memberships (id,user_id,workspace_id,role) "
                    "VALUES (%s,%s,%s,'admin')",
                    (uuid.uuid4(), approver_id, ws),
                )
            assert (
                client.post(
                    "/connectors",
                    headers=owner,
                    json={
                        "name": "pilot-slack",
                        "type": "slack",
                        "config": {
                            "workspace_label": "Synthetic local fixture",
                            "default_channel": "CPILOT",
                        },
                        "secret_ref": "PILOT_TEST",
                    },
                ).status_code
                == 201
            )
        worker_log = (tmp_path / "worker.log").open("w")
        web_log = (tmp_path / "web.log").open("w")
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
                "PILOT_DELIVERY_EVIDENCE": str(tmp_path / "deliveries.jsonl"),
                env_key_for(uuid.UUID(ws), "PILOT_TEST"): "synthetic-test-only",
            },
            stdout=worker_log,
            stderr=subprocess.STDOUT,
        )
        web_env = {
            **os.environ,
            "SUPABASE_URL": auth_url,
            "SUPABASE_ANON_KEY": auth["ANON_KEY"],
            "NLW_API_URL": api_url,
            "WORKSPACE_COOKIE_SECRET": uuid.uuid4().hex + uuid.uuid4().hex,
            "COOKIE_SECURE": "false",
            "NEXT_TELEMETRY_DISABLED": "1",
        }
        web = subprocess.Popen(
            [
                "node",
                "node_modules/next/dist/bin/next",
                "start",
                "--hostname",
                "127.0.0.1",
                "--port",
                str(web_port),
            ],
            cwd="web",
            env=web_env,
            stdout=web_log,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                try:
                    if httpx.get(f"{web_url}/login").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.2)
            browser_env = {
                **os.environ,
                "E2E_REQUIRED": "1",
                "E2E_PILOT": "1",
                "E2E_BASE_URL": web_url,
                "E2E_ADMIN_EMAIL": identities["owner"]["email"],
                "E2E_ADMIN_PASSWORD": identities["owner"]["password"],
                "E2E_MEMBER_EMAIL": identities["approver"]["email"],
                "E2E_MEMBER_PASSWORD": identities["approver"]["password"],
                "E2E_APPROVER_EMAIL": identities["approver"]["email"],
                "E2E_APPROVER_PASSWORD": identities["approver"]["password"],
                "E2E_OTHER_EMAIL": identities["other"]["email"],
                "E2E_OTHER_PASSWORD": identities["other"]["password"],
            }
            completed = subprocess.run(
                [
                    "node",
                    "node_modules/@playwright/test/cli.js",
                    "test",
                    "e2e/pilot-analytics.spec.ts",
                    "--workers=1",
                ],
                cwd="web",
                env=browser_env,
                timeout=240,
                capture_output=True,
                text=True,
            )
            assert completed.returncode == 0, completed.stdout + completed.stderr
            deliveries = (tmp_path / "deliveries.jsonl").read_text().splitlines()
            assert len(deliveries) == 1 and json.loads(deliveries[0])["channel"] == "CPILOT"
        finally:
            web.terminate()
            worker.terminate()
            web.wait(timeout=15)
            worker.wait(timeout=15)
            server.should_exit = True
            thread.join(timeout=15)
            web_log.close()
            worker_log.close()
            broker.close()
