"""Entrypoint for the scheduler role: ``python -m nlw.scheduler``.

Connects as the least-privilege ``nlw_scheduler`` role (via DATABASE_URL) and
enqueues run advancements onto Redis. It never resolves secrets or executes
tools — importing the worker actor only gives us the enqueue side of the queue.
"""

import signal
import threading
import uuid
from types import FrameType

import structlog

from nlw.core.config import get_settings
from nlw.core.logging import configure_logging
from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.observability.metrics import set_ctx_signer_configured, start_metrics_server
from nlw.scheduler.service import run
from nlw.tenancy.keys import build_signer, set_process_signer
from nlw.tenancy.readiness import check_signed_context_sync
from nlw.tenancy.signing import Purpose

log = structlog.get_logger(__name__)


def install_stop_handlers(stop: threading.Event) -> None:
    """SIGTERM/SIGINT request a graceful stop by setting ``stop``.

    Installed before anything else runs: the scheduler is PID 1 in its
    container, and the kernel discards a signal to PID 1 that has no handler,
    so a SIGTERM during initialization would otherwise be lost and Docker would
    SIGKILL the process at the end of its grace period. The first signal also
    makes further SIGTERM/SIGINT ignored: shutdown is already under way and
    bounded, and a repeated signal must not interrupt resource cleanup or
    interpreter finalization (which restores the default, fatal action).
    """

    def handle_stop(signum: int, frame: FrameType | None) -> None:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if not stop.is_set():
            log.info("scheduler.shutdown", signal=signum)
        stop.set()

    signal.signal(signal.SIGTERM, handle_stop)
    signal.signal(signal.SIGINT, handle_stop)


def main() -> None:
    stop = threading.Event()
    install_stop_handlers(stop)
    settings = get_settings()
    configure_logging(settings)
    start_metrics_server(settings, role="scheduler")

    engine = create_sync_engine(settings)
    # Authoritative recovery lock (M11.5 P2 addendum): refuse to start against a
    # restored database whose newest generation is not operator-enabled. Mandatory,
    # not gated on any env flag; a never-restored DB is unaffected; fails closed.
    from nlw.backup.recovery_lock import assert_startup_allowed_sync

    assert_startup_allowed_sync(engine)
    session_factory = create_sync_sessionmaker(engine)
    # Signed scheduler_reconcile context (P3B): sign with THIS process's key file
    # and prove the database verifies it before scanning anything. Fails closed.
    signer = build_signer(settings, Purpose.SCHEDULER_RECONCILE)
    set_process_signer(signer)
    set_ctx_signer_configured(str(Purpose.SCHEDULER_RECONCILE), True)
    with session_factory() as session:
        check_signed_context_sync(session, signer)

    # Enqueue-only use of the queue; import here so the broker is configured once.
    from nlw.worker.actors import advance_run

    def enqueue(run_id: uuid.UUID) -> None:
        advance_run.send(str(run_id))

    def wait_or_stop(seconds: float) -> None:
        stop.wait(seconds)

    log.info("scheduler.start", app_env=settings.app_env)
    try:
        # A stop that arrived during initialization means no tick ever starts.
        # Otherwise the current tick (commit, then enqueue what it committed)
        # always completes, and the inter-tick wait is `stop.wait`, which a
        # signal ends at once — unlike time.sleep, which PEP 475 resumes after
        # the handler returns, holding shutdown for up to a full scan interval.
        run(
            settings,
            session_factory,
            enqueue,
            sleep=wait_or_stop,
            should_continue=lambda: not stop.is_set(),
        )
    finally:
        engine.dispose()
        advance_run.broker.close()
        log.info("scheduler.stopped")


if __name__ == "__main__":
    main()
