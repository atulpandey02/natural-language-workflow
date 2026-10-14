"""Opt-in real-browser dataset journey. Local Supabase and local storage only.

The production build of the web app (``next start``) drives the real API, a real
Redis queue and the real ingest runtime (``dramatiq nlw.ingest_service.actors``
as ``nlw_ingest``): create -> upload -> ingest -> profile -> confirm semantics
-> activate -> deletion request, plus a malformed CSV, an oversized file, a lost
queue message and a broker outage (both recovered with the supported
"request processing again" action) and cross-tenant refusal.

Two controlled faults are injected at the API's enqueue boundary, chosen by the
synthetic file NAME: ``lost-queue.csv``'s first message is silently dropped
after commit (a lost message); ``broker-down.csv``'s first enqueue raises (the
API answers 503 PROCESSING_NOT_QUEUED). Every later enqueue is delivered. No
cloud, staging or S3 is contacted; uploads stay refused there by Settings.
"""

import json
import os
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
from test_pilot_browser import free_port
from testcontainers.community.redis import RedisContainer

from nlw.api.app import create_app
from nlw.api.routers import dataset_uploads
from nlw.core.config import Settings
from nlw.datasets.envelope import QUEUE_NAME, WorkEnvelope, enqueue_envelope
from nlw.worker.broker import make_broker

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("PILOT_AUTH_CONFIG"), reason="local browser harness is opt-in"
    ),
]

# Small, so the oversized case is cheap; API and web enforce the same value.
MAX_UPLOAD_BYTES = 4096


def _identity(client: httpx.Client, auth: dict[str, str], label: str) -> dict[str, str]:
    email = f"pilot-ds-{label}-{uuid.uuid4().hex[:8]}@example.test"
    password = uuid.uuid4().hex + "Aa1!"
    created = client.post(
        f"{auth['API_URL']}/auth/v1/admin/users",
        headers={
            "apikey": auth["SERVICE_ROLE_KEY"],
            "Authorization": f"Bearer {auth['SERVICE_ROLE_KEY']}",
        },
        json={"email": email, "password": password, "email_confirm": True},
    )
    assert created.status_code in (200, 201)
    login = client.post(
        f"{auth['API_URL']}/auth/v1/token?grant_type=password",
        headers={"apikey": auth["ANON_KEY"]},
        json={"email": email, "password": password},
    )
    assert login.status_code == 200
    return {"email": email, "password": password, "token": login.json()["access_token"]}


def test_pilot_dataset_browser(
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
    storage_root = tmp_path / "datasets"
    dataset_settings = {
        "app_env": "local",
        "datasets_api_enabled": True,
        "dataset_storage_backend": "local",
        "dataset_storage_root": str(storage_root),
        "dataset_max_upload_bytes": MAX_UPLOAD_BYTES,
    }
    settings = pg_stack.settings.model_copy(
        update={
            **dataset_settings,
            "supabase_url": auth_url,
            "supabase_jwt_secret": auth.get("JWT_SECRET"),
            "supabase_jwks_url": f"{auth_url}/auth/v1/.well-known/jwks.json",
            "supabase_jwt_issuer": f"{auth_url}/auth/v1",
        }
    )
    pg_stack.enable_ingest()
    with httpx.Client(timeout=15) as client:
        identities = {
            label: _identity(client, auth, label) for label in ("owner", "member", "other")
        }

    with RedisContainer("redis:7") as redis_c:
        redis_url = f"redis://{redis_c.get_container_host_ip()}:{redis_c.get_exposed_port(6379)}/0"
        broker = make_broker(Settings(_env_file=None, redis_url=redis_url))  # type: ignore[call-arg]
        broker.declare_queue(QUEUE_NAME)
        faults: dict[str, set[uuid.UUID]] = {"lost-queue.csv": set(), "broker-down.csv": set()}
        injected: list[str] = []

        def filename(version_id: uuid.UUID) -> str:
            with psycopg.connect(pg_stack.owner_libpq) as conn:
                row = conn.execute(
                    "SELECT original_filename FROM dataset_versions WHERE id = %s", (version_id,)
                ).fetchone()
            return str(row[0]) if row else ""

        def enqueue(envelope: WorkEnvelope) -> None:
            name = filename(envelope.version_id)
            seen = faults.get(name)
            if seen is not None and envelope.version_id not in seen:
                seen.add(envelope.version_id)
                injected.append(name)
                if name == "lost-queue.csv":
                    return  # committed, then the message is lost in transit
                raise ConnectionError("synthetic broker outage")
            enqueue_envelope(broker, envelope)

        monkeypatch.setattr(dataset_uploads, "_enqueue", enqueue)
        app = create_app(settings)
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
            ws = client.post("/workspaces", headers=owner, json={"name": "Dataset Pilot"}).json()[
                "id"
            ]
            other = {"Authorization": f"Bearer {identities['other']['token']}"}
            assert (
                client.post("/workspaces", headers=other, json={"name": "Other"}).status_code == 201
            )
            member = {"Authorization": f"Bearer {identities['member']['token']}"}
            member_id = client.get("/me", headers=member).json()["id"]
        with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as conn:
            conn.execute(
                "INSERT INTO memberships (id,user_id,workspace_id,role) VALUES (%s,%s,%s,'member')",
                (uuid.uuid4(), member_id, ws),
            )

        ingest_log = (tmp_path / "ingest.log").open("w")
        web_log = (tmp_path / "web.log").open("w")
        ingest_settings = pg_stack.ingest_settings
        ingest = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "dramatiq",
                "nlw.ingest_service.actors",
                "--queues",
                QUEUE_NAME,
                "--processes",
                "1",
                "--threads",
                "1",
            ],
            env={
                **os.environ,
                "PYTHONPATH": "src",
                "APP_ENV": "local",
                "REDIS_URL": redis_url,
                "DATABASE_URL": ingest_settings.database_url,
                "NLW_CTX_KEY_ID": str(ingest_settings.ctx_key_id),
                "NLW_CTX_KEY_FILE": str(ingest_settings.ctx_key_file),
                "METRICS_ENABLED": "false",
                "DATASETS_API_ENABLED": "false",
                "DATASET_STORAGE_BACKEND": "local",
                "DATASET_STORAGE_ROOT": str(storage_root),
                "DATASET_MAX_UPLOAD_BYTES": str(MAX_UPLOAD_BYTES),
            },
            stdout=ingest_log,
            stderr=subprocess.STDOUT,
        )
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
            env={
                **os.environ,
                "SUPABASE_URL": auth_url,
                "SUPABASE_ANON_KEY": auth["ANON_KEY"],
                "NLW_API_URL": api_url,
                "NLW_DATASET_MAX_UPLOAD_BYTES": str(MAX_UPLOAD_BYTES),
                "WORKSPACE_COOKIE_SECRET": uuid.uuid4().hex + uuid.uuid4().hex,
                "COOKIE_SECURE": "false",
                "NEXT_TELEMETRY_DISABLED": "1",
            },
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
            completed = subprocess.run(
                [
                    "node",
                    "node_modules/@playwright/test/cli.js",
                    "test",
                    "e2e/pilot-datasets.spec.ts",
                    "--workers=1",
                ],
                cwd="web",
                env={
                    **os.environ,
                    "E2E_REQUIRED": "1",
                    "E2E_PILOT": "1",
                    "E2E_BASE_URL": web_url,
                    "E2E_ADMIN_EMAIL": identities["owner"]["email"],
                    "E2E_ADMIN_PASSWORD": identities["owner"]["password"],
                    "E2E_MEMBER_EMAIL": identities["member"]["email"],
                    "E2E_MEMBER_PASSWORD": identities["member"]["password"],
                    "E2E_OTHER_EMAIL": identities["other"]["email"],
                    "E2E_OTHER_PASSWORD": identities["other"]["password"],
                    "E2E_DATASET_MAX_BYTES": str(MAX_UPLOAD_BYTES),
                },
                timeout=300,
                capture_output=True,
                text=True,
            )
            assert completed.returncode == 0, completed.stdout + completed.stderr
            # Both faults really happened (and were recovered in the browser).
            assert sorted(injected) == ["broker-down.csv", "lost-queue.csv"]
            with psycopg.connect(pg_stack.owner_libpq) as conn:
                rows = conn.execute(
                    "SELECT v.original_filename, v.status, count(*) OVER "
                    "(PARTITION BY v.original_filename) FROM dataset_versions v "
                    "WHERE v.tenant_id = %s",
                    (uuid.UUID(ws),),
                ).fetchall()
            by_name = {name: (status, count) for name, status, count in rows}
            # Recovery re-dispatched the SAME version: never a second one.
            assert by_name["lost-queue.csv"][1] == 1
            assert by_name["broker-down.csv"][1] == 1
            assert by_name["malformed.csv"][0] == "REJECTED"
            # The oversized file was refused before any version was initiated.
            assert "oversized.csv" not in by_name
            # Logical deletion only: the browser never purges.
            assert by_name["orders.csv"][0] == "DELETING"
        finally:
            web.terminate()
            ingest.terminate()
            web.wait(timeout=15)
            ingest.wait(timeout=15)
            server.should_exit = True
            thread.join(timeout=15)
            web_log.close()
            ingest_log.close()
            broker.close()
