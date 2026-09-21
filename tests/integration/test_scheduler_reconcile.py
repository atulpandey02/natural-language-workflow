"""Stale-run reconciliation eligibility + re-enqueue (M8).

Seeds runs in each relevant state and asserts exactly which are re-enqueued.
The reconciler writes nothing; the worker's M7 resume logic enforces
lease/next_attempt_at/approval, so re-enqueue is always safe.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import psycopg
import pytest
from sqlalchemy.orm import Session, sessionmaker

from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.scheduler.reconcile import find_stuck_runs
from nlw.scheduler.service import reconcile_once

pytestmark = pytest.mark.integration

_PLAN = {"steps": [{"id": "a", "tool": "fake.echo", "args": {}}]}
NOW = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
OLD = NOW - timedelta(minutes=10)  # older than the 60s threshold
FRESH = NOW - timedelta(seconds=5)


def _sched_sm(pg_stack: SimpleNamespace) -> sessionmaker[Session]:
    return create_sync_sessionmaker(create_sync_engine(pg_stack.scheduler_settings))


def _seed_wf(owner: str, tenant: uuid.UUID) -> uuid.UUID:
    wf, ver = uuid.uuid4(), uuid.uuid4()
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf, tenant))
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,%s::jsonb)",
            (ver, tenant, wf, json.dumps(_PLAN)),
        )
    return ver


def _run(
    owner: str,
    tenant: uuid.UUID,
    ver: uuid.UUID,
    status: str,
    *,
    created: datetime,
    updated: datetime,
) -> uuid.UUID:
    rid = uuid.uuid4()
    wf = uuid.uuid4()
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'w')", (wf, tenant))
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status, "
            "created_at, updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (rid, tenant, wf, ver, status, created, updated),
        )
    return rid


def _ext_action(
    owner: str,
    tenant: uuid.UUID,
    run_id: uuid.UUID,
    *,
    lease_expires: datetime | None,
    next_attempt: datetime | None,
    status: str = "pending",
    step_id: str = "a",
) -> None:
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute(
            "INSERT INTO external_actions (id, tenant_id, run_id, step_id, connector_id, tool, "
            "external_action_key, status, attempts, lease_token, lease_expires_at, "
            "next_attempt_at) "
            "VALUES (%s,%s,%s,%s,%s,'webhook.send',%s,%s,1,%s,%s,%s)",
            (
                uuid.uuid4(),
                tenant,
                run_id,
                step_id,
                uuid.uuid4(),
                uuid.uuid4(),
                status,
                uuid.uuid4(),
                lease_expires,
                next_attempt,
            ),
        )


def _approval(owner: str, tenant: uuid.UUID, run_id: uuid.UUID, status: str) -> None:
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute(
            "INSERT INTO approvals (id, tenant_id, run_id, step_id, connector_id, connector_name, "
            "tool, status) VALUES (%s,%s,%s,'a',%s,'hook','webhook.send',%s)",
            (uuid.uuid4(), tenant, run_id, uuid.uuid4(), status),
        )


def test_reconcile_eligibility_matrix(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    ver = _seed_wf(pg_stack.owner_libpq, m.tenant_id)
    o = pg_stack.owner_libpq
    t = m.tenant_id

    pending_old = _run(o, t, ver, "PENDING", created=OLD, updated=OLD)  # -> yes
    pending_fresh = _run(o, t, ver, "PENDING", created=FRESH, updated=FRESH)  # -> no

    running_expired = _run(o, t, ver, "RUNNING", created=OLD, updated=OLD)
    _ext_action(
        o, t, running_expired, lease_expires=NOW - timedelta(minutes=1), next_attempt=None
    )  # yes

    running_live = _run(o, t, ver, "RUNNING", created=OLD, updated=OLD)
    _ext_action(
        o, t, running_live, lease_expires=NOW + timedelta(minutes=5), next_attempt=None
    )  # no

    running_backoff = _run(o, t, ver, "RUNNING", created=OLD, updated=OLD)
    _ext_action(
        o,
        t,
        running_backoff,
        lease_expires=NOW - timedelta(minutes=1),
        next_attempt=NOW + timedelta(minutes=5),
    )  # no (future next_attempt)

    running_ordinary = _run(o, t, ver, "RUNNING", created=OLD, updated=OLD)  # no ext action -> yes

    waiting_approved = _run(o, t, ver, "WAITING_APPROVAL", created=OLD, updated=OLD)
    _approval(o, t, waiting_approved, "approved")  # yes

    waiting_rejected = _run(o, t, ver, "WAITING_APPROVAL", created=OLD, updated=OLD)
    _approval(o, t, waiting_rejected, "rejected")  # yes (req 3)

    waiting_pending = _run(o, t, ver, "WAITING_APPROVAL", created=OLD, updated=OLD)
    _approval(o, t, waiting_pending, "pending")  # no

    completed = _run(o, t, ver, "COMPLETED", created=OLD, updated=OLD)  # no
    failed = _run(o, t, ver, "FAILED", created=OLD, updated=OLD)  # no

    with _sched_sm(pg_stack)() as s, s.begin():
        # Large horizon so nothing is treated as beyond-horizon here.
        stuck = {
            r.run_id
            for r in find_stuck_runs(
                s, NOW, pending_threshold_s=60, batch_limit=100, recovery_horizon_s=10**9
            )
        }

    assert pending_old in stuck
    assert running_expired in stuck
    assert running_ordinary in stuck
    assert waiting_approved in stuck
    assert waiting_rejected in stuck

    assert pending_fresh not in stuck
    assert running_live not in stuck
    assert running_backoff not in stuck
    assert waiting_pending not in stuck
    assert completed not in stuck
    assert failed not in stuck


def test_reconcile_excludes_runs_with_unknown_actions(pg_stack: SimpleNamespace) -> None:
    """An UNKNOWN (ambiguous-outcome) action is TERMINAL and must never be
    reclaimed, resumed, or redelivered (P1C part H). The reconciler must never
    re-enqueue a run bearing one, even if the run looks RUNNING and stale."""
    m = pg_stack.seed_member()
    ver = _seed_wf(pg_stack.owner_libpq, m.tenant_id)
    o, t = pg_stack.owner_libpq, m.tenant_id

    # A stale RUNNING run whose ONLY action is unknown: without the guard the
    # NOT-EXISTS(pending) stall branch would wrongly re-enqueue it.
    unknown_only = _run(o, t, ver, "RUNNING", created=OLD, updated=OLD)
    _ext_action(o, t, unknown_only, lease_expires=None, next_attempt=None, status="unknown")

    # A stale RUNNING run with an expired-lease PENDING action AND an unknown
    # action from a different step: the run must still NOT be auto-driven.
    mixed = _run(o, t, ver, "RUNNING", created=OLD, updated=OLD)
    _ext_action(
        o, t, mixed, lease_expires=NOW - timedelta(minutes=1), next_attempt=None, step_id="a"
    )
    _ext_action(o, t, mixed, lease_expires=None, next_attempt=None, status="unknown", step_id="b")

    # Control: a normal expired-lease pending action IS eligible.
    resumable = _run(o, t, ver, "RUNNING", created=OLD, updated=OLD)
    _ext_action(o, t, resumable, lease_expires=NOW - timedelta(minutes=1), next_attempt=None)

    with _sched_sm(pg_stack)() as s, s.begin():
        stuck = {
            r.run_id
            for r in find_stuck_runs(
                s, NOW, pending_threshold_s=60, batch_limit=100, recovery_horizon_s=10**9
            )
        }

    assert unknown_only not in stuck
    assert mixed not in stuck
    assert resumable in stuck


def test_reconcile_once_reenqueues_orphan_pending(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    ver = _seed_wf(pg_stack.owner_libpq, m.tenant_id)
    orphan = _run(pg_stack.owner_libpq, m.tenant_id, ver, "PENDING", created=OLD, updated=OLD)

    enq: list[uuid.UUID] = []
    reconcile_once(_sched_sm(pg_stack), pg_stack.scheduler_settings, enq.append, now=NOW)
    assert orphan in enq


def test_reconcile_respects_recovery_horizon(pg_stack: SimpleNamespace) -> None:
    """A PENDING run past the recovery horizon is flagged beyond-horizon and NOT
    re-enqueued (poisoned-run guard, req 4); a recent one still is."""
    m = pg_stack.seed_member()
    ver = _seed_wf(pg_stack.owner_libpq, m.tenant_id)
    o, t = pg_stack.owner_libpq, m.tenant_id

    ancient = NOW - timedelta(days=30)  # far beyond a 1-day horizon
    poisoned = _run(o, t, ver, "PENDING", created=ancient, updated=ancient)
    recent = _run(o, t, ver, "PENDING", created=OLD, updated=OLD)

    horizon_settings = pg_stack.scheduler_settings.model_copy(
        update={"scheduler_recovery_horizon_s": 86_400}
    )
    enq: list[uuid.UUID] = []
    reconcile_once(_sched_sm(pg_stack), horizon_settings, enq.append, now=NOW)

    assert recent in enq
    assert poisoned not in enq  # past horizon: surfaced via gauge/log, not re-driven

    # The run's state is never mutated to FAILED by the reconciler.
    with psycopg.connect(o) as c:
        status = c.execute("SELECT status FROM workflow_runs WHERE id = %s", (poisoned,)).fetchone()
    assert status is not None and status[0] == "PENDING"
