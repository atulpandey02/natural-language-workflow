"""Scheduler service loop.

M1b is heartbeat-only: it proves the scheduler process/container exists in the
topology. Real due-schedule reading and enqueuing arrives in M8. The loop is
written to be testable — ``sleep`` and ``should_continue`` are injectable so
tests run one deterministic iteration without waiting.
"""

import time
from collections.abc import Callable

import structlog

from nlw.core.config import Settings

log = structlog.get_logger(__name__)


def run(
    settings: Settings,
    *,
    interval: float = 30.0,
    iterations: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
    should_continue: Callable[[], bool] = lambda: True,
) -> None:
    """Emit a heartbeat every ``interval`` seconds until stopped.

    ``iterations`` bounds the loop (used by tests); ``None`` means run forever.
    """
    count = 0
    while should_continue():
        log.info("scheduler.heartbeat", app_env=settings.app_env)
        count += 1
        if iterations is not None and count >= iterations:
            break
        sleep(interval)
