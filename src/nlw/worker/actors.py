"""Worker actors and the global broker configuration.

The worker entrypoint is ``dramatiq nlw.worker.actors``: importing this module
configures the global broker from settings and registers every actor.

M1b ships a single trivial ``ping`` actor that proves the enqueue -> Redis ->
worker path. It writes a short-lived Redis marker purely as a demonstration
signal; it is **not** workflow state. The real actor in later milestones will be
``advance_run(run_id)`` and will load authoritative state from Postgres.
"""

import time
import uuid

import dramatiq
import redis
import structlog
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import QueuePool

from nlw.core.config import get_settings
from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.engine.execution import process_advance
from nlw.observability import metrics
from nlw.observability.correlation import bind_request_context, clear_request_context
from nlw.worker.broker import make_broker

log = structlog.get_logger(__name__)

_settings = get_settings()

# Configure the global broker so actors below bind to it. The worker process and
# any enqueuing process read REDIS_URL from the environment via get_settings().
dramatiq.set_broker(make_broker(_settings))

# Marker TTL: the demonstration signal is ephemeral by design.
_PING_MARKER_TTL_SECONDS = 60

# Lazily-created synchronous session factory for the worker (connects as the
# nlw_worker role; Dramatiq actors are synchronous).
_engine: Engine | None = None
_sessionmaker: sessionmaker[Session] | None = None


def _get_sessionmaker() -> sessionmaker[Session]:
    global _engine, _sessionmaker
    if _sessionmaker is None:
        _engine = create_sync_engine(get_settings())
        _sessionmaker = create_sync_sessionmaker(_engine)
    return _sessionmaker


def register_worker_capacity_metrics() -> None:
    """Register scrape-time DB-pool + Redis queue-depth providers (M11, D2).

    Called once from the worker boot hook so the numbers reflect the worker's own
    engine + the shared Redis transport.
    """
    _get_sessionmaker()  # ensure the engine exists
    pool = _engine.pool if _engine is not None else None
    if isinstance(pool, QueuePool):
        metrics.register_pool_provider(lambda: (pool.checkedout(), pool.overflow()))

    depth_client = redis.from_url(get_settings().redis_url)

    def _queue_ready_depth() -> int:
        # Best-effort transport depth (Dramatiq default queue list). NOT
        # authoritative outstanding workflow state — durable state is in Postgres.
        try:
            return int(depth_client.llen("dramatiq:default"))
        except Exception:
            return 0

    metrics.register_queue_provider(_queue_ready_depth)
    metrics.register_capacity_collector()


@dramatiq.actor
def ping(token: str) -> None:
    """Log receipt and write an ephemeral Redis marker keyed by ``token``."""
    log.info("worker.ping", token=token)
    client = redis.from_url(get_settings().redis_url)
    try:
        client.set(f"nlw:ping:{token}", "ok", ex=_PING_MARKER_TTL_SECONDS)
    finally:
        client.close()


@dramatiq.actor(
    max_retries=_settings.worker_max_retries,
    min_backoff=_settings.worker_min_backoff_ms,
    max_backoff=_settings.worker_max_backoff_ms,
)
def advance_run(run_id: str) -> None:
    """Advance a durable run by one step, then enqueue the next advancement.

    Enqueue happens only after the step commit, and its failure propagates so the
    message is retried rather than silently dropped. Infra retries are bounded
    (``worker_max_retries``); on exhaustion the reconciler safely re-drives the
    run from Postgres. ``run_id`` is the durable correlation key, bound into the
    log context for this task and cleared at the boundary.
    """

    def _enqueue(rid: uuid.UUID, delay_seconds: float | None = None) -> None:
        if delay_seconds is not None and delay_seconds > 0:
            # Dramatiq delayed delivery (ms); used for action retry backoff and
            # for deferring while another worker holds a live action lease.
            advance_run.send_with_options(args=(str(rid),), delay=int(delay_seconds * 1000))
        else:
            advance_run.send(str(rid))

    bind_request_context(run_id=run_id)
    start = time.perf_counter()
    result_label = "error"
    try:
        outcome = process_advance(_get_sessionmaker(), uuid.UUID(run_id), _enqueue)
        result_label = outcome.result
    except Exception as exc:
        metrics.record_error(type(exc).__name__)
        raise
    finally:
        metrics.record_advance(result_label, time.perf_counter() - start)
        clear_request_context()
    log.info("worker.advance_run", run_id=run_id, result=outcome.result, step_id=outcome.step_id)
