"""Entrypoint for the scheduler role: ``python -m nlw.scheduler``.

Connects as the least-privilege ``nlw_scheduler`` role (via DATABASE_URL) and
enqueues run advancements onto Redis. It never resolves secrets or executes
tools — importing the worker actor only gives us the enqueue side of the queue.
"""

import signal
import uuid
from types import FrameType

import structlog

from nlw.core.config import get_settings
from nlw.core.logging import configure_logging
from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.scheduler.service import run

log = structlog.get_logger(__name__)


def main() -> None:
    settings = get_settings()
    configure_logging(settings)

    engine = create_sync_engine(settings)
    session_factory = create_sync_sessionmaker(engine)

    # Enqueue-only use of the queue; import here so the broker is configured once.
    from nlw.worker.actors import advance_run

    def enqueue(run_id: uuid.UUID) -> None:
        advance_run.send(str(run_id))

    running = {"active": True}

    def handle_stop(signum: int, frame: FrameType | None) -> None:
        log.info("scheduler.shutdown", signal=signum)
        running["active"] = False

    signal.signal(signal.SIGTERM, handle_stop)
    signal.signal(signal.SIGINT, handle_stop)

    log.info("scheduler.start", app_env=settings.app_env)
    try:
        run(settings, session_factory, enqueue, should_continue=lambda: running["active"])
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
