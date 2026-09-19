"""Reconciler recovery-horizon behavior (M9, req 4), driven without a DB."""

import uuid
from datetime import UTC, datetime

import pytest

import nlw.observability.metrics as metrics_mod
import nlw.scheduler.service as service
from nlw.core.config import Settings
from nlw.scheduler.reconcile import StuckRun


class _Ctx:
    def __enter__(self) -> "_Ctx":
        return self

    def __exit__(self, *a: object) -> None:
        return None


class _Session(_Ctx):
    def begin(self) -> _Ctx:
        return _Ctx()


def _factory() -> _Session:
    return _Session()


def _settings() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


def test_beyond_horizon_runs_are_not_reenqueued_but_gauged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live, poisoned = uuid.uuid4(), uuid.uuid4()
    monkeypatch.setattr(
        service,
        "find_stuck_runs",
        lambda *a, **k: [
            StuckRun(run_id=live, beyond_horizon=False),
            StuckRun(run_id=poisoned, beyond_horizon=True),
        ],
    )
    gauge: list[int] = []
    reenq: list[int] = []
    monkeypatch.setattr(metrics_mod, "set_runs_beyond_horizon", gauge.append)
    monkeypatch.setattr(metrics_mod, "record_reconcile", reenq.append)

    enqueued: list[uuid.UUID] = []
    result = service.reconcile_once(
        _factory,  # type: ignore[arg-type]
        _settings(),
        enqueued.append,
        now=datetime(2026, 5, 1, tzinfo=UTC),
    )

    assert enqueued == [live]  # poisoned run is NOT re-enqueued
    assert result == [live]
    assert gauge == [1]  # current count past horizon (a gauge, not a counter)
    assert reenq == [1]


def test_no_beyond_runs_sets_gauge_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    ok = uuid.uuid4()
    monkeypatch.setattr(
        service, "find_stuck_runs", lambda *a, **k: [StuckRun(run_id=ok, beyond_horizon=False)]
    )
    gauge: list[int] = []
    monkeypatch.setattr(metrics_mod, "set_runs_beyond_horizon", gauge.append)

    enqueued: list[uuid.UUID] = []
    service.reconcile_once(
        _factory,  # type: ignore[arg-type]
        _settings(),
        enqueued.append,
        now=datetime(2026, 5, 1, tzinfo=UTC),
    )
    assert enqueued == [ok]
    assert gauge == [0]
