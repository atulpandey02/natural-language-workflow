"""Scheduler service (M8): a durable due-schedule scanner + stale-run reconciler.

Two operations, both DB-claim/idempotent (so multiple scheduler processes are
safe): ``due_scan_once`` creates runs exactly-once and enqueues them after commit;
``reconcile_once`` re-enqueues stuck runs (writes nothing). The scheduler NEVER
executes tools, resolves secrets, or bypasses approvals — it only creates and
enqueues runs; the worker does the rest.

``sleep``/``should_continue``/``now`` are injectable so tests run deterministic
single iterations.
"""

import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

import structlog
from sqlalchemy.orm import Session, sessionmaker

from nlw.core.config import Settings
from nlw.scheduler.due import CreatedRun, scan_due
from nlw.scheduler.reconcile import find_stuck_runs

log = structlog.get_logger(__name__)

EnqueueFn = Callable[[uuid.UUID], None]


def _now() -> datetime:
    return datetime.now(UTC)


def due_scan_once(
    session_factory: sessionmaker[Session],
    settings: Settings,
    enqueue: EnqueueFn,
    *,
    now: datetime | None = None,
) -> list[CreatedRun]:
    """Claim due schedules, create runs (exactly-once) + advance, COMMIT, enqueue."""
    at = now or _now()
    with session_factory() as session, session.begin():
        created = scan_due(
            session,
            at,
            catchup_window_s=settings.scheduler_catchup_window_s,
            batch_limit=settings.scheduler_batch_limit,
        )
    for c in created:  # AFTER commit
        enqueue(c.run_id)
    if created:
        log.info("scheduler.due_scan", created=len(created))
    return created


def reconcile_once(
    session_factory: sessionmaker[Session],
    settings: Settings,
    enqueue: EnqueueFn,
    *,
    now: datetime | None = None,
) -> list[uuid.UUID]:
    """Find stuck runs and re-enqueue them (idempotent; no state writes)."""
    at = now or _now()
    with session_factory() as session, session.begin():
        run_ids = find_stuck_runs(
            session,
            at,
            pending_threshold_s=settings.scheduler_pending_threshold_s,
            batch_limit=settings.scheduler_batch_limit,
        )
    for run_id in run_ids:  # AFTER commit (read-only txn)
        enqueue(run_id)
    if run_ids:
        log.info("scheduler.reconcile", re_enqueued=len(run_ids))
    return run_ids


def run(
    settings: Settings,
    session_factory: sessionmaker[Session],
    enqueue: EnqueueFn,
    *,
    iterations: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
    should_continue: Callable[[], bool] = lambda: True,
    now: Callable[[], datetime] = _now,
) -> None:
    """Main loop: due-scan every tick, reconcile on its slower cadence."""
    count = 0
    last_reconcile = 0.0
    while should_continue():
        try:
            due_scan_once(session_factory, settings, enqueue, now=now())
            monotonic = time.monotonic()
            if monotonic - last_reconcile >= settings.scheduler_reconcile_interval_s:
                reconcile_once(session_factory, settings, enqueue, now=now())
                last_reconcile = monotonic
        except Exception:  # a scheduler tick must never crash the loop
            log.exception("scheduler.tick_failed")
        count += 1
        if iterations is not None and count >= iterations:
            break
        sleep(settings.scheduler_scan_interval_s)
