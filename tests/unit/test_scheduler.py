"""The scheduler emits heartbeats and honors the iteration bound."""

import structlog

from nlw.core.config import Settings
from nlw.scheduler.service import run


def test_heartbeat_emits_once() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    with structlog.testing.capture_logs() as logs:
        run(settings, interval=0, iterations=1, sleep=lambda _seconds: None)

    events = [entry["event"] for entry in logs]
    assert events == ["scheduler.heartbeat"]


def test_heartbeat_bounded_by_iterations() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    slept: list[float] = []
    with structlog.testing.capture_logs() as logs:
        run(settings, interval=5, iterations=3, sleep=slept.append)

    assert len(logs) == 3
    # Sleeps happen between iterations only: 3 heartbeats -> 2 sleeps.
    assert slept == [5, 5]
