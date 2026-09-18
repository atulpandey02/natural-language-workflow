"""Entrypoint for the scheduler role: ``python -m nlw.scheduler``."""

import signal
from types import FrameType

import structlog

from nlw.core.config import get_settings
from nlw.core.logging import configure_logging
from nlw.scheduler.service import run

log = structlog.get_logger(__name__)


def main() -> None:
    settings = get_settings()
    configure_logging(settings)

    running = {"active": True}

    def handle_stop(signum: int, frame: FrameType | None) -> None:
        log.info("scheduler.shutdown", signal=signum)
        running["active"] = False

    signal.signal(signal.SIGTERM, handle_stop)
    signal.signal(signal.SIGINT, handle_stop)

    log.info("scheduler.start", app_env=settings.app_env)
    run(settings, should_continue=lambda: running["active"])


if __name__ == "__main__":
    main()
