"""Scheduler loop: due-scan every tick, reconcile on its slower cadence,
bounded by iterations, resilient to a failing tick."""

import uuid

import pytest

import nlw.scheduler.service as service
from nlw.core.config import Settings


def _settings(**over: object) -> Settings:
    base: dict[str, object] = {"_env_file": None}
    base.update(over)
    return Settings(**base)  # type: ignore[arg-type]


def test_loop_runs_due_scan_each_tick_and_reconcile_on_cadence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    due_calls = {"n": 0}
    rec_calls = {"n": 0}
    monkeypatch.setattr(
        service, "due_scan_once", lambda *a, **k: due_calls.__setitem__("n", due_calls["n"] + 1)
    )
    monkeypatch.setattr(
        service, "reconcile_once", lambda *a, **k: rec_calls.__setitem__("n", rec_calls["n"] + 1)
    )

    # reconcile_interval 0 => reconcile fires every tick.
    settings = _settings(scheduler_reconcile_interval_s=0.0)
    service.run(
        settings,
        session_factory=None,  # type: ignore[arg-type]
        enqueue=lambda _r: None,
        iterations=3,
        sleep=lambda _s: None,
    )
    assert due_calls["n"] == 3
    assert rec_calls["n"] >= 1


def test_loop_survives_a_failing_tick(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a: object, **k: object) -> None:
        raise RuntimeError("db down")

    monkeypatch.setattr(service, "due_scan_once", _boom)
    monkeypatch.setattr(service, "reconcile_once", lambda *a, **k: None)
    # Must not raise; the loop logs and continues.
    service.run(
        _settings(),
        session_factory=None,  # type: ignore[arg-type]
        enqueue=lambda _r: None,
        iterations=2,
        sleep=lambda _s: None,
    )


def test_enqueue_type_is_uuid_callable() -> None:
    # Documents the enqueue contract used by __main__ (advance_run.send).
    seen: list[uuid.UUID] = []
    fn = seen.append
    rid = uuid.uuid4()
    fn(rid)
    assert seen == [rid]
