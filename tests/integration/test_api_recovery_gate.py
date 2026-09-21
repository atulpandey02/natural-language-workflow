"""Live API recovery-gate transitions against a real database (M11.5 P2 addendum).

Proves a RUNNING API process: keeps liveness up while gating readiness + business
routes; opens when the newest restore generation is enabled; and re-locks when a
later generation appears or the DB is lost — all without a restart.
"""

import time
import uuid
from types import SimpleNamespace
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine

from nlw.api.app import create_app
from nlw.backup.quiescence import quiesce
from nlw.backup.recovery_lock import enable_runtime, mark_validated
from nlw.core.config import Settings

pytestmark = pytest.mark.integration

_TTL = 0.2
_SETTLE = 0.35  # > TTL, so the gate's cache is stale and re-reads
_PROJECT = "nlw-dr-project"
_BIZ = "/workflows"  # a representative DB-backed business route (401 when allowed+unauth)


def _short_ttl(settings: Any) -> Settings:
    result: Settings = settings.model_copy(update={"recovery_gate_ttl_s": _TTL})
    return result


def _new_locked_generation(pg_stack: SimpleNamespace, owner: Any) -> str:
    """Insert non-terminal work + quiesce -> a fresh LOCKED generation; return its id."""
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        m = pg_stack.seed_member()
        wf, ver, run = (uuid.uuid4() for _ in range(3))
        c.execute(
            "INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'w')", (wf, m.tenant_id)
        )
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,'{\"steps\":[]}'::jsonb)",
            (ver, m.tenant_id, wf),
        )
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status) "
            "VALUES (%s,%s,%s,%s,'RUNNING')",
            (run, m.tenant_id, wf, ver),
        )
    qr = quiesce(owner)
    assert qr.event_id is not None
    return qr.event_id


def test_api_boot_with_db_unavailable_is_alive_but_gated(pg_stack: SimpleNamespace) -> None:
    bad = pg_stack.settings.model_copy(
        update={
            "database_url": "postgresql+psycopg://x:x@127.0.0.1:59999/nope",
            "recovery_gate_ttl_s": _TTL,
        }
    )
    with TestClient(create_app(bad)) as client:
        # Process is ALIVE: liveness works without a database.
        assert client.get("/health").status_code == 200
        assert client.get("/version").status_code == 200
        # Readiness + business routes fail closed (recovery UNKNOWN).
        assert client.get("/health/ready").status_code == 503
        assert client.get("/health/ready").json()["checks"]["recovery"] == "unknown"
        assert client.get(_BIZ).status_code == 503


def test_api_live_lock_enable_relock_transitions(pg_stack: SimpleNamespace) -> None:
    owner = create_engine(pg_stack.owner_sa)
    with TestClient(create_app(_short_ttl(pg_stack.settings))) as client:
        # (2) reachable, no restore event -> ALLOWED: business permitted (401 unauth,
        # NOT a 503 gate), readiness recovery ok.
        assert client.get("/health").status_code == 200
        assert client.get(_BIZ).status_code != 503
        assert client.get("/health/ready").json()["checks"]["recovery"] == "ok"

        # (3) a LOCKED generation appears -> same process re-locks after the TTL.
        _new_locked_generation(pg_stack, owner)
        time.sleep(_SETTLE)
        assert client.get(_BIZ).status_code == 503
        assert client.get("/health/ready").json()["checks"]["recovery"] == "locked"
        assert client.get("/health").status_code == 200  # liveness still up

        # (4) operator enables the exact newest generation -> same process opens.
        event_id = _newest_event_id(pg_stack.owner_libpq)
        mark_validated(owner, event_id, target_project=_PROJECT)
        enable_runtime(owner, event_id=event_id, confirm_project=_PROJECT, operator="op")
        time.sleep(_SETTLE)
        assert client.get(_BIZ).status_code != 503
        assert client.get("/health/ready").json()["checks"]["recovery"] == "ok"

        # (5) a LATER locked generation re-locks the SAME running process.
        _new_locked_generation(pg_stack, owner)
        time.sleep(_SETTLE)
        assert client.get(_BIZ).status_code == 503
        assert client.get("/health/ready").json()["checks"]["recovery"] == "locked"


def test_api_stale_allowed_fails_closed_when_db_lost(pg_stack: SimpleNamespace) -> None:
    with TestClient(create_app(_short_ttl(pg_stack.settings))) as client:
        assert client.get(_BIZ).status_code != 503  # ALLOWED (no event)
        # (6) DB connectivity lost after ALLOWED -> after the TTL, fail closed.
        gate = client.app.state.recovery_gate  # type: ignore[attr-defined]
        gate._engine = create_async_engine("postgresql+psycopg://x:x@127.0.0.1:59999/nope")
        time.sleep(_SETTLE)
        assert client.get(_BIZ).status_code == 503
        assert client.get("/health/ready").json()["checks"]["recovery"] == "unknown"
        assert client.get("/health").status_code == 200  # liveness unaffected


def _newest_event_id(owner_libpq: str) -> str:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute(
            "SELECT id FROM dr_restore_events ORDER BY restored_at DESC LIMIT 1"
        ).fetchone()
    assert row is not None
    return str(row[0])
