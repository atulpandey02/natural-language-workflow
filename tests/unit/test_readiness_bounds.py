"""Readiness probes are bounded during dependency outages (M11).

A black-holed dependency (e.g. a paused Postgres holding an open socket) cannot
be bounded by server-side statement timeouts, so ``/health/ready`` wraps every
dependency check in an application-level timeout and reports the dependency
"down" (503) instead of hanging. These are pure unit tests: the real dependency
checks are replaced with fakes, so no containers/network are needed.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Iterator

import pytest
from fastapi.testclient import TestClient

import nlw.api.app as app_module
from nlw.api.app import create_app
from nlw.core.config import Settings
from nlw.db.schema import SchemaMismatchError
from nlw.tenancy.keys import signer_from_material
from nlw.tenancy.signing import Purpose

TIMEOUT_S = 0.2  # small, so a "hanging" probe is bounded well within the test

Probe = Callable[..., Awaitable[None]]


async def _ok(*_a: object, **_k: object) -> None:
    return None


async def _hang(*_a: object, **_k: object) -> None:
    # Never completes on its own; the readiness timeout must cancel it.
    await asyncio.sleep(3600)


def _raise(exc: Exception) -> Probe:
    async def _fn(*_a: object, **_k: object) -> None:
        raise exc

    return _fn


class _StubGate:
    """Stand-in recovery gate with a fixed state (these tests exercise the DB probes,
    not the recovery lock — that has its own suite)."""

    def __init__(self, state: str = "ALLOWED") -> None:
        self._state = state

    async def check(self) -> str:
        return self._state


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    settings = Settings(readiness_probe_timeout_s=TIMEOUT_S)
    # Signed context (P3B): give the app in-memory test signers and a fake
    # verification probe — this file bounds probe TIMING, it does not need a DB.
    monkeypatch.setattr(app_module, "check_signed_context", _ok)
    with TestClient(create_app(settings)) as c:
        c.app.state.recovery_gate = _StubGate("ALLOWED")  # type: ignore[attr-defined]
        c.app.state.ctx_signers = {  # type: ignore[attr-defined]
            p: signer_from_material(p, "unit", "22" * 32)
            for p in (Purpose.API_IDENTITY, Purpose.API_REQUEST)
        }
        yield c


def _patch(
    monkeypatch: pytest.MonkeyPatch,
    *,
    postgres: Probe,
    redis: Probe = _ok,
    schema: Probe = _ok,
) -> list[str]:
    """Replace the three dependency checks; record which ones are actually called."""
    called: list[str] = []

    def wrap(name: str, fn: Probe) -> Probe:
        async def _inner(*a: object, **k: object) -> None:
            called.append(name)
            await fn(*a, **k)

        return _inner

    monkeypatch.setattr(app_module, "check_connection", wrap("postgres", postgres))
    monkeypatch.setattr(app_module, "check_redis", wrap("redis", redis))
    monkeypatch.setattr(app_module, "check_schema", wrap("schema", schema))
    return called


def test_a_hanging_postgres_probe_is_bounded(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch(monkeypatch, postgres=_hang)
    start = time.monotonic()
    resp = client.get("/health/ready")
    elapsed = time.monotonic() - start
    assert resp.status_code == 503
    assert resp.json()["checks"]["postgres"] == "down"
    # Bounded: comfortably under the 3600s sleep, near the configured timeout.
    assert elapsed < 5.0


def test_b_all_healthy_is_200(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, postgres=_ok)
    resp = client.get("/health/ready")
    assert resp.status_code == 200
    assert resp.json()["checks"] == {
        "recovery": "ok",
        "postgres": "ok",
        "redis": "ok",
        "schema": "ok",
        "signed_context": "ok",
    }


def test_c_redis_down_is_503(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, postgres=_ok, redis=_raise(ConnectionError("no redis")))
    resp = client.get("/health/ready")
    assert resp.status_code == 503
    checks = resp.json()["checks"]
    assert checks == {
        "recovery": "ok",
        "postgres": "ok",
        "redis": "down",
        "schema": "ok",
        "signed_context": "ok",
    }


def test_f_recovery_locked_is_not_ready(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Even with every dependency healthy, a locked recovery generation is NOT ready.
    client.app.state.recovery_gate = _StubGate("LOCKED")  # type: ignore[attr-defined]
    _patch(monkeypatch, postgres=_ok)
    resp = client.get("/health/ready")
    assert resp.status_code == 503
    assert resp.json()["checks"]["recovery"] == "locked"


def test_d_schema_mismatch_is_503(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, postgres=_ok, schema=_raise(SchemaMismatchError("stale")))
    resp = client.get("/health/ready")
    assert resp.status_code == 503
    assert resp.json()["checks"]["schema"] == "down"


def test_e_schema_not_probed_when_postgres_down(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A hanging Postgres must NOT trigger a second blocking DB round-trip via the
    # schema probe (that would incur a second full timeout).
    called = _patch(monkeypatch, postgres=_hang)
    resp = client.get("/health/ready")
    assert resp.status_code == 503
    checks = resp.json()["checks"]
    assert checks["postgres"] == "down"
    assert checks["schema"] == "down"
    assert "schema" not in called  # never invoked when postgres is down
    assert "postgres" in called


def test_e_schema_not_probed_when_postgres_errors(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = _patch(monkeypatch, postgres=_raise(ConnectionError("refused")))
    resp = client.get("/health/ready")
    assert resp.status_code == 503
    assert resp.json()["checks"]["schema"] == "down"
    assert "schema" not in called
