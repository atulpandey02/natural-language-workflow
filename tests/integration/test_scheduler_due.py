"""Due-schedule scan: exactly-once run creation, concurrency (SKIP LOCKED +
unique), catch-up window, restart no-re-fire, and end-to-end execution (M8).
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import psycopg
import pytest
from sqlalchemy.orm import Session, sessionmaker

from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.engine.execution import execute_advancement
from nlw.scheduler.due import scan_due
from nlw.scheduler.service import due_scan_once
from nlw.tenancy.keys import process_signer
from nlw.tenancy.session import set_scheduler_context_sync
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

_PLAN = {"steps": [{"id": "a", "tool": "fake.echo", "args": {"x": 1}}]}


def _scheduler_sm(pg_stack: SimpleNamespace) -> sessionmaker[Session]:
    return create_sync_sessionmaker(create_sync_engine(pg_stack.scheduler_settings))


def _worker_sm(pg_stack: SimpleNamespace) -> sessionmaker[Session]:
    return create_sync_sessionmaker(create_sync_engine(pg_stack.worker_settings))


def _seed_workflow(owner_libpq: str, tenant_id: uuid.UUID) -> tuple[uuid.UUID, uuid.UUID]:
    wf, ver = uuid.uuid4(), uuid.uuid4()
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf, tenant_id)
        )
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,%s::jsonb)",
            (ver, tenant_id, wf, json.dumps(_PLAN)),
        )
        c.execute("UPDATE workflows SET current_version_id=%s WHERE id=%s", (ver, wf))
    return wf, ver


def _seed_schedule(
    owner_libpq: str,
    tenant_id: uuid.UUID,
    workflow_id: uuid.UUID,
    version_id: uuid.UUID,
    created_by: uuid.UUID,
    *,
    next_run_at: datetime,
    frequency: str = "daily",
    minute: int = 0,
    hour: int | None = 9,
    day_of_week: int | None = None,
    enabled: bool = True,
    tz: str = "UTC",
) -> uuid.UUID:
    sid = uuid.uuid4()
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO schedules (id, tenant_id, workflow_id, workflow_version_id, timezone, "
            "frequency, minute, hour, day_of_week, enabled, next_run_at, created_by) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                sid,
                tenant_id,
                workflow_id,
                version_id,
                tz,
                frequency,
                minute,
                hour,
                day_of_week,
                enabled,
                next_run_at,
                created_by,
            ),
        )
    return sid


def _runs(owner_libpq: str, schedule_id: uuid.UUID) -> list[tuple[object, ...]]:
    with psycopg.connect(owner_libpq) as c:
        return c.execute(
            "SELECT id, status, trigger, workflow_version_id, scheduled_for FROM workflow_runs "
            "WHERE schedule_id=%s ORDER BY created_at",
            (schedule_id,),
        ).fetchall()


def _schedule_row(owner_libpq: str, sid: uuid.UUID) -> tuple[datetime, datetime | None]:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute(
            "SELECT next_run_at, last_scheduled_for FROM schedules WHERE id=%s", (sid,)
        ).fetchone()
    assert row is not None
    return row


def test_due_scan_creates_pinned_run_and_advances(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    wf, ver = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    now = datetime(2026, 1, 15, 14, 0, tzinfo=UTC)  # 09:00 EST-equivalent in UTC tz
    sid = _seed_schedule(
        pg_stack.owner_libpq,
        m.tenant_id,
        wf,
        ver,
        m.user_id,
        next_run_at=now - timedelta(minutes=1),
        tz="UTC",
        hour=14,
        minute=0,
    )
    enq: list[uuid.UUID] = []
    created = due_scan_once(
        _scheduler_sm(pg_stack), pg_stack.scheduler_settings, enq.append, now=now
    )

    assert len(created) == 1
    runs = _runs(pg_stack.owner_libpq, sid)
    assert len(runs) == 1
    _id, status, trigger, wvid, _sf = runs[0]
    assert status == "PENDING" and trigger == "schedule"
    assert wvid == ver  # pinned immutable version (req 1/8)
    assert enq == [created[0].run_id]
    # next_run_at advanced to a future occurrence; last_scheduled_for set (run made).
    next_at, last_for = _schedule_row(pg_stack.owner_libpq, sid)
    assert next_at > now
    assert last_for is not None


def test_disabled_schedule_not_fired(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    wf, ver = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    now = datetime(2026, 1, 15, 14, 0, tzinfo=UTC)
    sid = _seed_schedule(
        pg_stack.owner_libpq,
        m.tenant_id,
        wf,
        ver,
        m.user_id,
        next_run_at=now - timedelta(minutes=1),
        enabled=False,
        tz="UTC",
        hour=14,
    )
    created = due_scan_once(
        _scheduler_sm(pg_stack), pg_stack.scheduler_settings, lambda _r: None, now=now
    )
    assert created == []
    assert _runs(pg_stack.owner_libpq, sid) == []


def test_catchup_skips_occurrence_older_than_window(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    wf, ver = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    now = datetime(2026, 1, 15, 20, 0, tzinfo=UTC)
    # next_run_at far in the past (schedule down for hours); latest occurrence
    # (today 14:00 UTC) is > 1h before now (20:00) -> beyond catch-up -> skip fire.
    sid = _seed_schedule(
        pg_stack.owner_libpq,
        m.tenant_id,
        wf,
        ver,
        m.user_id,
        next_run_at=now - timedelta(days=2),
        tz="UTC",
        hour=14,
        minute=0,
    )
    created = due_scan_once(
        _scheduler_sm(pg_stack), pg_stack.scheduler_settings, lambda _r: None, now=now
    )
    assert created == []
    assert _runs(pg_stack.owner_libpq, sid) == []
    # ...but next_run_at is still advanced to the future (no stuck re-scan).
    next_at, last_for = _schedule_row(pg_stack.owner_libpq, sid)
    assert next_at > now
    assert last_for is None  # no run created -> last_scheduled_for untouched (req 10)


def test_concurrent_scan_skip_locked_creates_one_run(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    wf, ver = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    now = datetime(2026, 1, 15, 14, 0, tzinfo=UTC)
    sid = _seed_schedule(
        pg_stack.owner_libpq,
        m.tenant_id,
        wf,
        ver,
        m.user_id,
        next_run_at=now - timedelta(minutes=1),
        tz="UTC",
        hour=14,
        minute=0,
    )
    sm = _scheduler_sm(pg_stack)
    # Two overlapping transactions; A holds the row lock, B SKIP LOCKED skips it.
    # Each transaction carries its own SIGNED scheduler context (P3B); the due-scan
    # policies verify the claim, so a bare nlw_scheduler session sees no schedules.
    sched = process_signer(Purpose.SCHEDULER_RECONCILE)
    sa = sm()
    sa.begin()
    set_scheduler_context_sync(sa, sched)
    created_a = scan_due(sa, now, catchup_window_s=3600, batch_limit=10)
    sb = sm()
    sb.begin()
    set_scheduler_context_sync(sb, sched)
    created_b = scan_due(sb, now, catchup_window_s=3600, batch_limit=10)
    sa.commit()
    sb.commit()
    sa.close()
    sb.close()
    assert len(created_a) == 1
    assert created_b == []  # B skipped the locked schedule
    assert len(_runs(pg_stack.owner_libpq, sid)) == 1


def test_unique_constraint_backstops_duplicate_occurrence(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    wf, ver = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    now = datetime(2026, 1, 15, 14, 0, tzinfo=UTC)
    sid = _seed_schedule(
        pg_stack.owner_libpq,
        m.tenant_id,
        wf,
        ver,
        m.user_id,
        next_run_at=now - timedelta(minutes=1),
        tz="UTC",
        hour=14,
        minute=0,
    )
    sm = _scheduler_sm(pg_stack)
    assert len(due_scan_once(sm, pg_stack.scheduler_settings, lambda _r: None, now=now)) == 1
    # Force the schedule due again for the SAME occurrence; the unique constraint
    # (schedule_id, scheduled_for) makes the second insert a no-op.
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute(
            "UPDATE schedules SET next_run_at=%s WHERE id=%s", (now - timedelta(minutes=1), sid)
        )
    created2 = due_scan_once(sm, pg_stack.scheduler_settings, lambda _r: None, now=now)
    assert created2 == []
    assert len(_runs(pg_stack.owner_libpq, sid)) == 1  # still exactly one


def test_restart_does_not_refire(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    wf, ver = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    now = datetime(2026, 1, 15, 14, 0, tzinfo=UTC)
    _seed_schedule(
        pg_stack.owner_libpq,
        m.tenant_id,
        wf,
        ver,
        m.user_id,
        next_run_at=now - timedelta(minutes=1),
        tz="UTC",
        hour=14,
        minute=0,
    )
    sm = _scheduler_sm(pg_stack)
    assert len(due_scan_once(sm, pg_stack.scheduler_settings, lambda _r: None, now=now)) == 1
    # A "restart" = a fresh scan at the same now: next_run_at already advanced.
    assert due_scan_once(sm, pg_stack.scheduler_settings, lambda _r: None, now=now) == []


def test_scheduled_run_executes_to_completion(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    wf, ver = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    now = datetime(2026, 1, 15, 14, 0, tzinfo=UTC)
    sid = _seed_schedule(
        pg_stack.owner_libpq,
        m.tenant_id,
        wf,
        ver,
        m.user_id,
        next_run_at=now - timedelta(minutes=1),
        tz="UTC",
        hour=14,
        minute=0,
    )
    created = due_scan_once(
        _scheduler_sm(pg_stack), pg_stack.scheduler_settings, lambda _r: None, now=now
    )
    run_id = created[0].run_id
    worker_sm = _worker_sm(pg_stack)
    for _ in range(4):
        if execute_advancement(worker_sm, run_id).result in ("completed", "failed", "noop"):
            break
    with psycopg.connect(pg_stack.owner_libpq) as c:
        status = c.execute("SELECT status FROM workflow_runs WHERE id=%s", (run_id,)).fetchone()
    assert status is not None and status[0] == "COMPLETED"
    assert sid is not None
