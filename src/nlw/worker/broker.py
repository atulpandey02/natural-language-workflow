"""Dramatiq broker construction and Redis health check.

Redis is transport only (ADR-002); durable workflow state lives in Postgres.
This module is intentionally side-effect free: it builds a broker on request
and probes Redis for readiness. The global broker is set in ``nlw.worker.actors``
(imported by the worker entrypoint), so the API can import ``check_redis`` here
without pulling in that global configuration.
"""

import redis.asyncio as aioredis
import structlog
from dramatiq.brokers.redis import RedisBroker
from dramatiq.middleware import Middleware, MiddlewareError

from nlw.core.config import Settings, get_settings
from nlw.observability.metrics import start_metrics_server

log = structlog.get_logger(__name__)


class MetricsMiddleware(Middleware):
    """Start the internal Prometheus metrics server once the worker boots.

    Using ``after_worker_boot`` (not import time) means the server binds only in a
    real ``dramatiq`` worker process — never when the API/scheduler merely import
    the actors module to enqueue, and never during tests that import the module.
    """

    def after_worker_boot(self, broker: object, worker: object) -> None:
        try:
            if start_metrics_server(get_settings(), role="worker"):
                log.info("worker.metrics_started")
            # Register capacity providers (DB pool + Redis queue depth) once the
            # worker process is up (M11 capacity metrics).
            from nlw.worker.actors import register_worker_capacity_metrics

            register_worker_capacity_metrics()
        except Exception:  # metrics must never take down the worker
            log.warning("worker.metrics_start_failed")


class WorkerBootRefused(MiddlewareError):
    """Fatal worker-boot refusal.

    Subclasses dramatiq's ``MiddlewareError`` because that is the ONE exception
    class ``Broker.emit_before`` re-raises (pinned dramatiq 2.2.1,
    ``broker.py::emit_before``: ``except MiddlewareError: raise``). Every other
    exception raised from a ``before_*`` hook is logged at CRITICAL and
    **swallowed**, after which ``Worker.start()`` goes on to install the consumer
    middleware and start its worker threads. Raising this class instead makes
    ``Worker.start()`` abort before any consumer or worker thread exists; under
    the ``dramatiq`` CLI the worker process then exits non-zero and the parent
    shuts down with that exit status.

    The message is author-controlled (our own recovery-lock reason), never driver
    or DSN text, so the resulting traceback is safe to print.
    """


class RecoveryLockMiddleware(Middleware):
    """Authoritative recovery-lock preflight at worker boot (M11.5 P2 addendum).

    ``before_worker_boot`` fires only in a real ``dramatiq`` worker process (not when
    the API/scheduler import the actors module to enqueue). It consults the DB
    recovery lock as the ``nlw_worker`` role and raises :class:`WorkerBootRefused`
    — the framework-fatal exception — if the newest restore generation is not
    operator-enabled, or if the state cannot be determined. Mandatory: not gated
    on any env flag. A never-restored DB boots normally; anything else fails closed
    with no consumer or worker thread ever started.
    """

    def before_worker_boot(self, broker: object, worker: object) -> None:
        from nlw.backup.recovery_lock import (
            RecoveryLocked,
            RecoveryStateUnknown,
            assert_startup_allowed_sync,
        )
        from nlw.db.session import create_sync_engine

        try:
            engine = create_sync_engine(get_settings())
        except Exception as exc:  # cannot even build the engine -> indeterminate
            log.error("worker.recovery_lock_refused", error_class=type(exc).__name__)
            raise WorkerBootRefused(
                "worker boot refused: recovery-lock state unreadable (database engine)"
            ) from None
        try:
            assert_startup_allowed_sync(engine)
        except (RecoveryLocked, RecoveryStateUnknown) as exc:
            # ``str(exc)`` is our own controlled reason (never driver/DSN text).
            log.error(
                "worker.recovery_lock_refused", error_class=type(exc).__name__, reason=str(exc)
            )
            raise WorkerBootRefused(f"worker boot refused: {type(exc).__name__}: {exc}") from None
        except Exception as exc:  # any other failure is indeterminate -> fail closed
            log.error("worker.recovery_lock_refused", error_class=type(exc).__name__)
            raise WorkerBootRefused(
                f"worker boot refused: recovery-lock preflight failed ({type(exc).__name__})"
            ) from None
        finally:
            engine.dispose()
        log.info("worker.recovery_lock_ok")


def make_broker(settings: Settings) -> RedisBroker:
    """Build a Redis-backed Dramatiq broker for ``settings.redis_url``."""
    # dramatiq ships py.typed but leaves RedisBroker.__init__ unannotated.
    broker = RedisBroker(url=settings.redis_url)  # type: ignore[no-untyped-call]
    # Recovery-lock preflight FIRST — a locked restore must abort boot before any
    # metrics server binds or actors register.
    broker.add_middleware(RecoveryLockMiddleware())
    broker.add_middleware(MetricsMiddleware())
    return broker


async def check_redis(settings: Settings) -> None:
    """Ping Redis to verify reachability. Raises on failure (readiness signal).

    Short timeouts keep the readiness endpoint from hanging when Redis is down.
    """
    client = aioredis.from_url(
        settings.redis_url,
        socket_connect_timeout=2,
        socket_timeout=2,
    )
    try:
        await client.ping()
    finally:
        await client.aclose()
