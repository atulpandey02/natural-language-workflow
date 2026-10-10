"""The dataset-ingest runtime: ``dramatiq nlw.ingest_service.actors --queues dataset_ingest``.

Importing this module configures THIS process's broker (ADR-031). Only the
ingest service imports it; the API enqueues with ``nlw.datasets.envelope`` through
its own broker. It imports no worker, connector, planner, model or secret-store
module (a unit test pins this), and the process holds only its own database
role (``nlw_ingest``), its own signing key, Redis and dataset storage settings.

Boot is refused (framework-fatal, no consumer starts) when:

- the DR recovery lock does not permit runtimes;
- its key does not verify as a ``dataset_ingest`` context in the database;
- no dataset store is configured (staging/production: local storage is refused
  and no other backend exists, owner decision O-2), so a dormant container
  there can never process anything.

Shutdown: Dramatiq stops consuming on SIGTERM; a message that starts after the
stop flag is set is re-queued WITHOUT claiming a lease; in-flight work finishes
or, if killed, its database-time lease expires and a redelivery reclaims it.
"""

from __future__ import annotations

import asyncio
import threading

import dramatiq
import structlog
from dramatiq.brokers.redis import RedisBroker
from dramatiq.middleware import Middleware, MiddlewareError

from nlw.backup.recovery_lock import RecoveryLocked, RecoveryStateUnknown
from nlw.core.config import Settings, get_settings
from nlw.datasets.envelope import ACTOR_NAME, QUEUE_NAME
from nlw.db.session import create_engine, create_sessionmaker, create_sync_engine
from nlw.ingest_service import processing
from nlw.observability.metrics import start_metrics_server
from nlw.storage.blob import BlobStore
from nlw.storage.factory import dataset_store
from nlw.tenancy.keys import build_signer
from nlw.tenancy.signing import ContextSigner, Purpose

log = structlog.get_logger(__name__)

_settings = get_settings()
_stopping = threading.Event()
_signer: ContextSigner | None = None
# Built once at boot (an S3 store verifies its pinned identity then).
_store: BlobStore | None = None

# Profiling is bounded by its own wall clock; the actor gets that plus margin.
_TIME_LIMIT_MS = (int(_settings.dataset_profile_timeout_s) + 120) * 1000
_MAX_RETRIES = 5  # transient failures (database/Redis); refusals are not retried
_STOPPING_REQUEUE_MS = 5_000
_RECOVERY_REQUEUE_MS = 60_000


class IngestBootRefused(MiddlewareError):
    """Framework-fatal boot refusal (see ``nlw.worker.broker.WorkerBootRefused``
    for why the class matters). Messages are author-controlled, never secrets."""


def _boot_checks(settings: Settings) -> tuple[ContextSigner, BlobStore]:
    from nlw.backup.recovery_lock import assert_startup_allowed_sync
    from nlw.tenancy.readiness import check_signed_context_sync

    store = dataset_store(settings, service="ingest")
    if store is None:
        raise IngestBootRefused("ingest boot refused: no dataset store is configured")
    signer = build_signer(settings, Purpose.DATASET_INGEST)
    engine = create_sync_engine(settings)
    try:
        assert_startup_allowed_sync(engine)
        from sqlalchemy.orm import Session

        with Session(engine) as session:
            check_signed_context_sync(session, signer)
    finally:
        engine.dispose()
    return signer, store


class IngestBootMiddleware(Middleware):
    def before_worker_boot(self, broker: object, worker: object) -> None:
        global _signer, _store
        try:
            _signer, _store = _boot_checks(get_settings())
        except IngestBootRefused:
            raise
        except Exception as exc:  # indeterminate -> fail closed, class only
            log.error("ingest.boot_refused", error_class=type(exc).__name__)
            raise IngestBootRefused(f"ingest boot refused ({type(exc).__name__})") from None
        log.info("ingest.boot_ok")

    def after_worker_boot(self, broker: object, worker: object) -> None:
        try:
            if start_metrics_server(get_settings(), role="ingest"):
                log.info("ingest.metrics_started")
        except Exception:  # metrics must never take down the runtime
            log.warning("ingest.metrics_start_failed")


class StopFlagMiddleware(Middleware):
    """Set the stop flag as soon as shutdown begins, so no new work starts."""

    def before_worker_shutdown(self, broker: object, worker: object) -> None:
        _stopping.set()
        log.info("ingest.stopping")


def make_broker(settings: Settings) -> RedisBroker:
    broker = RedisBroker(url=settings.redis_url)  # type: ignore[no-untyped-call]
    broker.add_middleware(IngestBootMiddleware())
    broker.add_middleware(StopFlagMiddleware())
    return broker


dramatiq.set_broker(make_broker(_settings))


async def _run(envelope_json: str) -> processing.ProcessResult:
    settings = get_settings()
    store = _store
    if store is None or _signer is None:  # boot checks make this unreachable
        raise RuntimeError("ingest runtime is not booted")
    engine = create_engine(settings)
    try:
        return await processing.process_envelope(
            maker=create_sessionmaker(engine),
            signer=_signer,
            store=store,
            config=processing.config_from_settings(settings),
            message=envelope_json,
        )
    finally:
        await engine.dispose()


@dramatiq.actor(
    actor_name=ACTOR_NAME,
    queue_name=QUEUE_NAME,
    max_retries=_MAX_RETRIES,
    time_limit=_TIME_LIMIT_MS,
)
def process_dataset_version(envelope_json: str) -> None:
    if _stopping.is_set():
        # Shutting down: hand the message back untouched (no lease claimed).
        raise dramatiq.Retry("ingest runtime is stopping", delay=_STOPPING_REQUEUE_MS)
    try:
        result = asyncio.run(_run(envelope_json))
    except (RecoveryLocked, RecoveryStateUnknown) as exc:
        # A restore is not operator-enabled (or its state is unreadable): touch
        # nothing, hand the message back for later.
        log.warning("ingest.recovery_locked", error_class=type(exc).__name__)
        raise dramatiq.Retry("recovery lock", delay=_RECOVERY_REQUEUE_MS) from None
    log.info("ingest.message_done", result=result)
