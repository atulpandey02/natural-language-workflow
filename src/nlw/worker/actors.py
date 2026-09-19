"""Worker actors and the global broker configuration.

The worker entrypoint is ``dramatiq nlw.worker.actors``: importing this module
configures the global broker from settings and registers every actor.

M1b ships a single trivial ``ping`` actor that proves the enqueue -> Redis ->
worker path. It writes a short-lived Redis marker purely as a demonstration
signal; it is **not** workflow state. The real actor in later milestones will be
``advance_run(run_id)`` and will load authoritative state from Postgres.
"""

import uuid

import dramatiq
import redis
import structlog
from sqlalchemy.orm import Session, sessionmaker

from nlw.core.config import get_settings
from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.engine.execution import process_advance
from nlw.worker.broker import make_broker

log = structlog.get_logger(__name__)

# Configure the global broker so actors below bind to it. The worker process and
# any enqueuing process read REDIS_URL from the environment via get_settings().
dramatiq.set_broker(make_broker(get_settings()))

# Marker TTL: the demonstration signal is ephemeral by design.
_PING_MARKER_TTL_SECONDS = 60

# Lazily-created synchronous session factory for the worker (connects as the
# nlw_worker role; Dramatiq actors are synchronous).
_sessionmaker: sessionmaker[Session] | None = None


def _get_sessionmaker() -> sessionmaker[Session]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = create_sync_sessionmaker(create_sync_engine(get_settings()))
    return _sessionmaker


@dramatiq.actor
def ping(token: str) -> None:
    """Log receipt and write an ephemeral Redis marker keyed by ``token``."""
    log.info("worker.ping", token=token)
    client = redis.from_url(get_settings().redis_url)
    try:
        client.set(f"nlw:ping:{token}", "ok", ex=_PING_MARKER_TTL_SECONDS)
    finally:
        client.close()


@dramatiq.actor
def advance_run(run_id: str) -> None:
    """Advance a durable run by one step, then enqueue the next advancement.

    Enqueue happens only after the step commit, and its failure propagates so the
    message is retried rather than silently dropped.
    """

    def _enqueue(rid: uuid.UUID, delay_seconds: float | None = None) -> None:
        if delay_seconds is not None and delay_seconds > 0:
            # Dramatiq delayed delivery (ms); used for action retry backoff and
            # for deferring while another worker holds a live action lease.
            advance_run.send_with_options(args=(str(rid),), delay=int(delay_seconds * 1000))
        else:
            advance_run.send(str(rid))

    outcome = process_advance(_get_sessionmaker(), uuid.UUID(run_id), _enqueue)
    log.info("worker.advance_run", run_id=run_id, result=outcome.result, step_id=outcome.step_id)
