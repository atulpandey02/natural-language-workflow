"""Scheduled-run idempotency namespace separation + occurrence identity (P1D, A).

A manual client Idempotency-Key and a scheduler-created occurrence live in
SEPARATE namespaces: a manual key can never collide with, suppress, or be mistaken
for a scheduled occurrence, and scheduled uniqueness comes solely from the
immutable occurrence identity (schedule_id, scheduled_for).
"""

import threading
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import psycopg
import pytest
from test_scheduler_due import (  # sibling module (pytest prepend import mode)
    _scheduler_sm,
    _seed_schedule,
    _seed_workflow,
)

from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.scheduler.recurrence import Frequency, Recurrence, latest_occurrence
from nlw.scheduler.service import due_scan_once

pytestmark = pytest.mark.integration


def _all_runs(owner_libpq: str, tenant_id: uuid.UUID) -> list[dict[str, object]]:
    with psycopg.connect(owner_libpq) as c:
        c.row_factory = psycopg.rows.dict_row  # type: ignore[assignment]
        return [
            dict(r)
            for r in c.execute(
                "SELECT id, trigger, schedule_id, scheduled_for, idempotency_key "
                "FROM workflow_runs WHERE tenant_id=%s ORDER BY created_at",
                (tenant_id,),
            ).fetchall()
        ]


def _insert_manual(
    owner_libpq: str, tenant_id: uuid.UUID, wf: uuid.UUID, ver: uuid.UUID, key: str
) -> uuid.UUID:
    rid = uuid.uuid4()
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status, "
            "trigger, idempotency_key) VALUES (%s,%s,%s,%s,'PENDING','manual',%s)",
            (rid, tenant_id, wf, ver, key),
        )
    return rid


def test_manual_key_cannot_suppress_a_scheduled_occurrence(pg_stack: SimpleNamespace) -> None:
    """The core P1D defect: a manual run whose idempotency_key equals the OLD
    scheduler-derived key must NOT suppress the scheduled occurrence."""
    m = pg_stack.seed_member()
    wf, ver = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    now = datetime(2026, 5, 1, 9, 30, tzinfo=UTC)
    sid = _seed_schedule(
        pg_stack.owner_libpq,
        m.tenant_id,
        wf,
        ver,
        m.user_id,
        next_run_at=now - timedelta(minutes=1),  # due
    )
    scheduled_for = latest_occurrence(
        Recurrence(timezone="UTC", frequency=Frequency.DAILY, minute=0, hour=9), now
    )
    assert scheduled_for is not None
    # A manual run occupying the EXACT old colliding key format.
    colliding_key = f"sched:{sid}:{scheduled_for.isoformat()}"
    manual_id = _insert_manual(pg_stack.owner_libpq, m.tenant_id, wf, ver, colliding_key)

    created = due_scan_once(
        _scheduler_sm(pg_stack), pg_stack.scheduler_settings, lambda _r: None, now=now
    )

    assert len(created) == 1  # the scheduled occurrence was still created
    runs = _all_runs(pg_stack.owner_libpq, m.tenant_id)
    assert len(runs) == 2  # the manual run AND a distinct scheduled run
    scheduled = [r for r in runs if r["trigger"] == "schedule"]
    manual = [r for r in runs if r["trigger"] == "manual"]
    assert len(scheduled) == 1 and len(manual) == 1
    assert scheduled[0]["id"] != manual_id
    assert scheduled[0]["idempotency_key"] is None  # NULL: not in the client namespace
    assert manual[0]["idempotency_key"] == colliding_key  # manual keeps its own key


def test_distinct_occurrences_create_distinct_runs(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    wf, ver = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    sm = _scheduler_sm(pg_stack)
    day1 = datetime(2026, 5, 1, 9, 30, tzinfo=UTC)
    day2 = datetime(2026, 5, 2, 9, 30, tzinfo=UTC)
    _seed_schedule(
        pg_stack.owner_libpq,
        m.tenant_id,
        wf,
        ver,
        m.user_id,
        next_run_at=day1 - timedelta(minutes=1),
    )

    assert len(due_scan_once(sm, pg_stack.scheduler_settings, lambda _r: None, now=day1)) == 1
    assert len(due_scan_once(sm, pg_stack.scheduler_settings, lambda _r: None, now=day2)) == 1

    runs = [r for r in _all_runs(pg_stack.owner_libpq, m.tenant_id) if r["trigger"] == "schedule"]
    assert len(runs) == 2
    assert runs[0]["scheduled_for"] != runs[1]["scheduled_for"]  # distinct occurrences


def test_two_schedules_same_workflow_and_time_stay_distinct(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    wf, ver = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    sm = _scheduler_sm(pg_stack)
    now = datetime(2026, 5, 1, 9, 30, tzinfo=UTC)
    # Two schedules, same workflow, same recurrence (=> same scheduled_for).
    s1 = _seed_schedule(
        pg_stack.owner_libpq,
        m.tenant_id,
        wf,
        ver,
        m.user_id,
        next_run_at=now - timedelta(minutes=1),
    )
    s2 = _seed_schedule(
        pg_stack.owner_libpq,
        m.tenant_id,
        wf,
        ver,
        m.user_id,
        next_run_at=now - timedelta(minutes=1),
    )
    created = due_scan_once(sm, pg_stack.scheduler_settings, lambda _r: None, now=now)
    assert len(created) == 2  # one run PER schedule (distinct schedule_id)
    runs = [r for r in _all_runs(pg_stack.owner_libpq, m.tenant_id) if r["trigger"] == "schedule"]
    sched_ids = {r["schedule_id"] for r in runs}
    assert sched_ids == {s1, s2}
    # Same occurrence time, but the (schedule_id, scheduled_for) identity differs.
    assert runs[0]["scheduled_for"] == runs[1]["scheduled_for"]


def test_scheduled_run_gets_the_schedule_tenant(pg_stack: SimpleNamespace) -> None:
    """Tenant isolation: a scheduled run is created under the schedule's own tenant
    only; another tenant's due scan does not touch it."""
    a = pg_stack.seed_member()
    b = pg_stack.seed_member()
    wf, ver = _seed_workflow(pg_stack.owner_libpq, a.tenant_id)
    now = datetime(2026, 5, 1, 9, 30, tzinfo=UTC)
    _seed_schedule(
        pg_stack.owner_libpq,
        a.tenant_id,
        wf,
        ver,
        a.user_id,
        next_run_at=now - timedelta(minutes=1),
    )
    due_scan_once(_scheduler_sm(pg_stack), pg_stack.scheduler_settings, lambda _r: None, now=now)

    assert (
        len([r for r in _all_runs(pg_stack.owner_libpq, a.tenant_id) if r["trigger"] == "schedule"])
        == 1
    )
    assert _all_runs(pg_stack.owner_libpq, b.tenant_id) == []  # tenant B has nothing


def test_two_schedulers_racing_one_occurrence_create_one_run(pg_stack: SimpleNamespace) -> None:
    """Two full scheduler instances racing the SAME occurrence, each on its OWN
    connection, create exactly one run (SKIP LOCKED + unique occurrence)."""
    m = pg_stack.seed_member()
    wf, ver = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    now = datetime(2026, 5, 1, 9, 30, tzinfo=UTC)
    _seed_schedule(
        pg_stack.owner_libpq,
        m.tenant_id,
        wf,
        ver,
        m.user_id,
        next_run_at=now - timedelta(minutes=1),
    )
    sms = [
        create_sync_sessionmaker(create_sync_engine(pg_stack.scheduler_settings)) for _ in range(2)
    ]
    barrier = threading.Barrier(2)
    counts: list[int] = [0, 0]

    def racer(i: int) -> None:
        barrier.wait()
        counts[i] = len(
            due_scan_once(sms[i], pg_stack.scheduler_settings, lambda _r: None, now=now)
        )

    threads = [threading.Thread(target=racer, args=(i,)) for i in range(2)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    assert sum(counts) == 1  # exactly one instance created the occurrence's run
    runs = [r for r in _all_runs(pg_stack.owner_libpq, m.tenant_id) if r["trigger"] == "schedule"]
    assert len(runs) == 1  # no duplicate scheduled run
