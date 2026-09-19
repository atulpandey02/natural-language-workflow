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
) -> None:
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute(
            "INSERT INTO external_actions (id, tenant_id, run_id, step_id, connector_id, tool, "
            "external_action_key, status, attempts, lease_token, lease_expires_at, "
            "next_attempt_at) "
            "VALUES (%s,%s,%s,'a',%s,'webhook.send',%s,'pending',1,%s,%s,%s)",
            (
                uuid.uuid4(),
                tenant,
                run_id,
                uuid.uuid4(),
                uuid.uuid4(),
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
        stuck = set(find_stuck_runs(s, NOW, pending_threshold_s=60, batch_limit=100))

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


def test_reconcile_once_reenqueues_orphan_pending(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    ver = _seed_wf(pg_stack.owner_libpq, m.tenant_id)
    orphan = _run(pg_stack.owner_libpq, m.tenant_id, ver, "PENDING", created=OLD, updated=OLD)

    enq: list[uuid.UUID] = []
    reconcile_once(_sched_sm(pg_stack), pg_stack.scheduler_settings, enq.append, now=NOW)
    assert orphan in enq
