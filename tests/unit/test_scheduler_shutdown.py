"""Scheduler graceful shutdown (rollout `drain` killed it with exit 137).

Root cause: the SIGTERM handler only set a flag while the loop slept in
``time.sleep(scheduler_scan_interval_s)``; PEP 475 resumes that sleep after the
handler returns, so shutdown waited up to a full 30 s scan interval and Docker
SIGKILLed it after its 10 s grace period. These tests drive the real ``main()``
wiring with real signals delivered to this process (handlers are restored after
every test). Timing bounds are deliberately loose (the fixed path takes
milliseconds; the old path took the whole scan interval).
"""

import os
import signal
import sys
import threading
import time
import types
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest

import nlw.scheduler.__main__ as sched_main
import nlw.scheduler.service as service
from nlw.core.config import Settings

SCAN_INTERVAL_S = 30.0  # the production default; a regression would block this long
BOUND_S = 5.0  # conservative upper bound for a prompt exit


@pytest.fixture(autouse=True)
def _restore_signal_handlers() -> Iterator[None]:
    saved = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
    yield
    for s, handler in saved.items():
        signal.signal(s, handler)


def _settings() -> Settings:
    return Settings(  # type: ignore[call-arg]
        _env_file=None,
        scheduler_scan_interval_s=SCAN_INTERVAL_S,
        scheduler_reconcile_interval_s=SCAN_INTERVAL_S,
    )


def _sigterm_self_after(delay_s: float) -> threading.Timer:
    timer = threading.Timer(delay_s, os.kill, (os.getpid(), signal.SIGTERM))
    timer.daemon = True
    timer.start()
    return timer


class _Harness:
    """Fakes every external dependency of ``main()``; records what happened."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, during_init: Callable[[], None]) -> None:
        self.events: list[str] = []
        self.enqueued: list[uuid.UUID] = []
        h = self

        class _Engine:
            def dispose(self) -> None:
                h.events.append("engine.dispose")

        class _Broker:
            def close(self) -> None:
                h.events.append("broker.close")

        class _Actor:
            broker = _Broker()

            def send(self, run_id: str) -> None:
                h.events.append("enqueue")
                h.enqueued.append(uuid.UUID(run_id))

        actors = types.ModuleType("nlw.worker.actors")
        actors.advance_run = _Actor()  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "nlw.worker.actors", actors)

        def _init_step(*_a: Any, **_k: Any) -> None:
            during_init()

        import nlw.backup.recovery_lock as recovery_lock

        monkeypatch.setattr(recovery_lock, "assert_startup_allowed_sync", _init_step)
        monkeypatch.setattr(sched_main, "get_settings", _settings)
        monkeypatch.setattr(sched_main, "configure_logging", lambda _s: None)
        monkeypatch.setattr(sched_main, "start_metrics_server", lambda *_a, **_k: None)
        monkeypatch.setattr(sched_main, "create_sync_engine", lambda _s: _Engine())
        monkeypatch.setattr(sched_main, "create_sync_sessionmaker", lambda _e: _Session)
        monkeypatch.setattr(sched_main, "build_signer", lambda *_a: object())
        monkeypatch.setattr(sched_main, "set_process_signer", lambda _s: None)
        monkeypatch.setattr(sched_main, "set_ctx_signer_configured", lambda *_a: None)
        monkeypatch.setattr(sched_main, "check_signed_context_sync", lambda *_a: None)


class _Session:
    def __enter__(self) -> "_Session":
        return self

    def __exit__(self, *_a: object) -> None:
        return None


def _patch_ticks(
    monkeypatch: pytest.MonkeyPatch,
    harness: _Harness,
    *,
    on_due_scan: Callable[[int], None] = lambda _n: None,
) -> list[int]:
    """Replace the tick bodies; each due-scan 'commits' one run, then enqueues it
    (the real order: enqueue only what the tick committed, after commit)."""
    ticks: list[int] = []

    def fake_due_scan(_sf: Any, _settings: Any, enqueue: Any, *, now: Any) -> list[Any]:
        ticks.append(len(ticks) + 1)
        harness.events.append(f"tick{len(ticks)}.commit")
        on_due_scan(len(ticks))
        run_id = uuid.uuid4()
        enqueue(run_id)
        return [run_id]

    monkeypatch.setattr(service, "due_scan_once", fake_due_scan)
    monkeypatch.setattr(service, "reconcile_once", lambda *_a, **_k: [])
    return ticks


def test_sigterm_during_idle_wait_exits_promptly_after_one_tick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    h = _Harness(monkeypatch, during_init=lambda: None)
    ticks = _patch_ticks(monkeypatch, h)
    _sigterm_self_after(0.3)  # lands inside the 30 s inter-tick wait

    t0 = time.monotonic()
    sched_main.main()
    elapsed = time.monotonic() - t0

    assert elapsed < BOUND_S, (
        f"shutdown took {elapsed:.2f}s (regression: blocked in the scan sleep)"
    )
    assert ticks == [1]  # no new tick after the stop request
    assert h.events == ["tick1.commit", "enqueue", "engine.dispose", "broker.close"]


def test_sigterm_during_a_tick_completes_that_tick_and_starts_no_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    h = _Harness(monkeypatch, during_init=lambda: None)

    def stop_mid_tick(n: int) -> None:
        if n == 1:
            os.kill(os.getpid(), signal.SIGTERM)  # after commit, before enqueue

    ticks = _patch_ticks(monkeypatch, h, on_due_scan=stop_mid_tick)

    t0 = time.monotonic()
    sched_main.main()
    assert time.monotonic() - t0 < BOUND_S

    # The committed run of the interrupted tick is still enqueued exactly once
    # (commit-then-enqueue boundary kept); nothing is scanned or enqueued after.
    assert ticks == [1]
    assert len(h.enqueued) == 1
    assert h.events == ["tick1.commit", "enqueue", "engine.dispose", "broker.close"]


def test_sigterm_during_initialization_starts_no_tick(monkeypatch: pytest.MonkeyPatch) -> None:
    h = _Harness(monkeypatch, during_init=lambda: os.kill(os.getpid(), signal.SIGTERM))
    ticks = _patch_ticks(monkeypatch, h)

    t0 = time.monotonic()
    sched_main.main()
    assert time.monotonic() - t0 < BOUND_S

    assert ticks == []
    assert h.enqueued == []
    assert h.events == ["engine.dispose", "broker.close"]


def test_repeated_sigterm_is_ignored_once_shutdown_started(monkeypatch: pytest.MonkeyPatch) -> None:
    h = _Harness(monkeypatch, during_init=lambda: None)

    def stop_twice(n: int) -> None:
        if n == 1:
            os.kill(os.getpid(), signal.SIGTERM)
            os.kill(os.getpid(), signal.SIGTERM)  # must not interrupt or re-trigger
            os.kill(os.getpid(), signal.SIGINT)

    ticks = _patch_ticks(monkeypatch, h, on_due_scan=stop_twice)
    sched_main.main()

    assert ticks == [1]
    assert h.events == ["tick1.commit", "enqueue", "engine.dispose", "broker.close"]
    # Further stop signals are ignored for the rest of the process lifetime, so
    # they cannot cut cleanup or interpreter finalization short.
    assert signal.getsignal(signal.SIGTERM) == signal.SIG_IGN
    assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN


def test_handlers_are_installed_before_any_initialization(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def capture(*_a: Any, **_k: Any) -> Settings:
        seen["sigterm"] = signal.getsignal(signal.SIGTERM)
        raise RuntimeError("stop the test at the first initialization step")

    monkeypatch.setattr(sched_main, "get_settings", capture)
    with pytest.raises(RuntimeError):
        sched_main.main()
    assert callable(seen["sigterm"])  # our handler, not SIG_DFL (ignored at PID 1)


def test_normal_operation_is_unchanged_without_a_signal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without a stop request the loop keeps ticking on its interval; the stop
    event only shortens the WAIT. Bounded here by iterations."""
    calls: list[str] = []

    def due(*_a: Any, **_k: Any) -> list[Any]:
        calls.append("due")
        return []

    def rec(*_a: Any, **_k: Any) -> list[Any]:
        calls.append("rec")
        return []

    monkeypatch.setattr(service, "due_scan_once", due)
    monkeypatch.setattr(service, "reconcile_once", rec)
    stop = threading.Event()
    waits: list[float] = []

    def wait(seconds: float) -> None:
        waits.append(seconds)
        stop.wait(0)  # not set: returns immediately in the test

    service.run(
        _settings(),
        lambda: None,  # type: ignore[arg-type]
        lambda _r: None,
        iterations=3,
        sleep=wait,
        should_continue=lambda: not stop.is_set(),
    )
    assert calls.count("due") == 3
    assert waits == [SCAN_INTERVAL_S, SCAN_INTERVAL_S]
