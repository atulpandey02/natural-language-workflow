"""The dataset dispatcher: ``python -m nlw.ingest_dispatch.dispatcher``.

A committed processing request whose enqueue was lost (ADR-031) waits until
something re-sends its envelope. This process does that unattended, as the
``nlw_ingest_dispatch`` role, which can do exactly one thing with dataset data:
call ``dataset_dispatch_pending()`` (migration 0027). It holds no signing key,
no dataset storage, no LLM, connector, backup or operator secret, and it never
writes to the database. The ingest runtime re-verifies every envelope and its
lease settles a version once, so a re-send is always harmless.

Each cycle (``dataset_dispatch_interval_s``):

1. the DR recovery lock must permit runtimes (otherwise: nothing, ``locked``);
2. one sweep at a time across this and the operator CLI (a session advisory
   lock; otherwise: nothing, ``busy``);
3. read one bounded, oldest-first batch of waiting requests older than
   ``dataset_dispatch_min_age_s`` and still fresh for the consumer, plus the
   aggregate stats for monitoring;
4. re-send each request at most once per ``dataset_dispatch_resend_s`` (an
   in-memory bound; a restart re-sends at most one extra copy).

Requests too old for the consumer cannot be renewed here (a request names the
admin who asked for it): they are counted (``nlw_dataset_dispatch_stale``) and
need an admin re-dispatch. Logs and metrics carry counts only.

Boot is refused (exit 3) unless the process is connected AS
``nlw_ingest_dispatch`` and the recovery lock permits runtimes.
"""

from __future__ import annotations

import signal
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from nlw.backup.recovery_lock import RecoveryLocked, RecoveryStateUnknown, check_recovery_lock
from nlw.core.config import Settings, get_settings
from nlw.datasets.envelope import MAX_ENVELOPE_AGE_S, WorkEnvelope, enqueue_envelope
from nlw.observability.metrics import record_dataset_dispatch, start_metrics_server

log = structlog.get_logger(__name__)

ROLE = "nlw_ingest_dispatch"
# Shared with ``python -m nlw.ops.datasets dispatch-pending``: one sweep at a time.
_SQL_LOCK = text("SELECT pg_try_advisory_lock(hashtext('nlw.ops.datasets.dispatch_pending'))")
_SQL_UNLOCK = text("SELECT pg_advisory_unlock(hashtext('nlw.ops.datasets.dispatch_pending'))")
_SQL_PENDING = text("SELECT * FROM dataset_dispatch_pending(:limit, :min_age, :fresh_age)")
# Fresh for the consumer with margin (it refuses envelopes older than the max).
FRESH_AGE_S = MAX_ENVELOPE_AGE_S - 3600


class DispatchBootRefused(RuntimeError):
    """The dispatcher must not run (wrong identity or recovery lock)."""


@dataclass
class CycleResult:
    result: str
    pending: int = 0
    oldest_age_s: float = 0.0
    stale: int = 0
    enqueued: int = 0


@dataclass
class DispatchState:
    """request id -> monotonic time it was last re-sent by THIS process."""

    last_sent: dict[uuid.UUID, float] = field(default_factory=dict)


def _envelope(row: Any) -> WorkEnvelope:
    return WorkEnvelope(
        request_id=row.request_id,
        tenant_id=row.tenant_id,
        dataset_id=row.dataset_id,
        version_id=row.version_id,
        content_sha256=row.content_sha256,
        envelope_sha256=row.envelope_sha256,
        requested_at_us=int(row.requested_at_us),
    )


def _read_batch(conn: Connection, settings: Settings) -> list[Any] | None:
    """The batch (with stats on every row) or None when another sweep runs."""
    if not conn.execute(_SQL_LOCK).scalar():
        return None
    try:
        rows = conn.execute(
            _SQL_PENDING,
            {
                "limit": settings.dataset_dispatch_batch,
                "min_age": settings.dataset_dispatch_min_age_s,
                "fresh_age": FRESH_AGE_S,
            },
        ).all()
    finally:
        conn.execute(_SQL_UNLOCK)
        conn.commit()
    return list(rows)


def run_cycle(
    engine: Engine,
    broker: Any,
    settings: Settings,
    state: DispatchState,
    *,
    clock: Any = time.monotonic,
) -> CycleResult:
    """One dispatch cycle. Never raises for a locked or busy database; a
    database or broker failure raises (the caller records ``error``)."""
    with engine.connect() as conn:
        try:
            check_recovery_lock(conn)
        except (RecoveryLocked, RecoveryStateUnknown):
            conn.rollback()
            return CycleResult("locked")
        conn.rollback()
        rows = _read_batch(conn, settings)
    if rows is None:
        return CycleResult("busy")
    head = rows[0]  # the function always returns the stats row
    out = CycleResult(
        "ok",
        pending=int(head.pending_total),
        oldest_age_s=float(head.oldest_age_s),
        stale=int(head.stale_total),
    )
    now = clock()
    batch = [r for r in rows if r.request_id is not None]
    for row in batch:
        last = state.last_sent.get(row.request_id)
        if last is not None and now - last < settings.dataset_dispatch_resend_s:
            continue
        enqueue_envelope(broker, _envelope(row))  # a failure stops the cycle
        state.last_sent[row.request_id] = now
        out.enqueued += 1
    # Bounded memory: forget requests that are no longer waiting.
    waiting = {r.request_id for r in batch}
    for rid in [k for k in state.last_sent if k not in waiting]:
        del state.last_sent[rid]
    return out


def boot_checks(engine: Engine) -> None:
    """Refuse to run as anything but the dispatcher role, or while locked."""
    with engine.connect() as conn:
        user = conn.execute(text("SELECT session_user")).scalar()
        if user != ROLE:
            raise DispatchBootRefused(f"dispatcher must connect as {ROLE}")
        try:
            check_recovery_lock(conn)
        except (RecoveryLocked, RecoveryStateUnknown) as exc:
            raise DispatchBootRefused(f"recovery lock ({type(exc).__name__})") from None
        finally:
            conn.rollback()


def serve(settings: Settings, stop: threading.Event) -> int:
    from dramatiq.brokers.redis import RedisBroker

    from nlw.db.session import create_sync_engine

    engine = create_sync_engine(settings)
    try:
        boot_checks(engine)
    except DispatchBootRefused as exc:
        log.error("dispatch.boot_refused", reason=str(exc))
        engine.dispose()
        return 3
    except Exception as exc:  # indeterminate -> fail closed, class only
        log.error("dispatch.boot_refused", error_class=type(exc).__name__)
        engine.dispose()
        return 3
    broker = RedisBroker(url=settings.redis_url)  # type: ignore[no-untyped-call]
    try:
        if start_metrics_server(settings, role="ingest-dispatch"):
            log.info("dispatch.metrics_started")
    except Exception:  # metrics must never take down the runtime
        log.warning("dispatch.metrics_start_failed")
    log.info("dispatch.boot_ok", interval_s=settings.dataset_dispatch_interval_s)
    state = DispatchState()
    try:
        while not stop.is_set():
            try:
                res = run_cycle(engine, broker, settings, state)
            except Exception as exc:  # database/broker trouble: retry next cycle
                record_dataset_dispatch("error")
                log.warning("dispatch.cycle_failed", error_class=type(exc).__name__)
            else:
                record_dataset_dispatch(
                    res.result,
                    pending=res.pending,
                    oldest_age_s=res.oldest_age_s,
                    stale=res.stale,
                    enqueued=res.enqueued,
                    now=time.time(),
                )
                log.info(
                    "dispatch.cycle",
                    result=res.result,
                    pending=res.pending,
                    stale=res.stale,
                    enqueued=res.enqueued,
                )
            stop.wait(settings.dataset_dispatch_interval_s)
    finally:
        broker.close()
        engine.dispose()
        log.info("dispatch.stopped")
    return 0


def main() -> int:
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    return serve(get_settings(), stop)


if __name__ == "__main__":
    raise SystemExit(main())
