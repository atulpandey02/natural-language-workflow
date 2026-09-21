"""Post-restore quiescence transition matrix, idempotency, isolation, audit (P2).

Runs the real ``quiesce`` operation (owner/superuser connection, bypasses FORCE
RLS) against a real migrated database seeded with two tenants' work.
"""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import psycopg
import pytest
from sqlalchemy import create_engine

from nlw.backup.config import DR_RESTORE_UNCERTAIN
from nlw.backup.quiescence import quiesce
from nlw.engine.actions import ACTION_OUTCOME_UNKNOWN

pytestmark = pytest.mark.integration

_PLAN = '{"steps":[{"id":"a","tool":"fake.echo","args":{}}]}'


def _seed_tenant(owner: str) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID]:
    """Return (tenant, user, workflow_version, workflow)."""
    tid, uid, wf, ver = (uuid.uuid4() for _ in range(4))
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute("INSERT INTO workspaces (id, name, slug) VALUES (%s,'w',%s)", (tid, f"w-{tid}"))
        c.execute(
            "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s)",
            (uid, str(uid), f"{uid}@e.com"),
        )
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf, tid))
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,%s::jsonb)",
            (ver, tid, wf, _PLAN),
        )
    return tid, uid, ver, wf


def _run(
    owner: str, tid: uuid.UUID, ver: uuid.UUID, status: str, key: str | None = None
) -> uuid.UUID:
    rid, wf = uuid.uuid4(), uuid.uuid4()
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'w')", (wf, tid))
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status, "
            "idempotency_key) VALUES (%s,%s,%s,%s,%s,%s)",
            (rid, tid, wf, ver, status, key),
        )
    return rid


def _step(owner: str, tid: uuid.UUID, run_id: uuid.UUID, status: str) -> None:
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute(
            "INSERT INTO step_runs (id, tenant_id, run_id, step_id, tool, status, attempt) "
            "VALUES (%s,%s,%s,'a','webhook.send',%s,0)",
            (uuid.uuid4(), tid, run_id, status),
        )


def _action(owner: str, tid: uuid.UUID, run_id: uuid.UUID, status: str, key: uuid.UUID) -> None:
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute(
            "INSERT INTO external_actions (id, tenant_id, run_id, step_id, connector_id, tool, "
            "external_action_key, status, attempts, lease_token, lease_owner, lease_expires_at, "
            "next_attempt_at) VALUES (%s,%s,%s,'a',%s,'webhook.send',%s,%s,1,%s,'w',now(),now())",
            (uuid.uuid4(), tid, run_id, uuid.uuid4(), key, status, uuid.uuid4()),
        )


def _schedule(
    owner: str, tid: uuid.UUID, wf: uuid.UUID, ver: uuid.UUID, uid: uuid.UUID, next_run_at: datetime
) -> uuid.UUID:
    sid = uuid.uuid4()
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute(
            "INSERT INTO schedules (id, tenant_id, workflow_id, workflow_version_id, timezone, "
            "frequency, minute, hour, enabled, next_run_at, created_by) "
            "VALUES (%s,%s,%s,%s,'UTC','daily',0,9,true,%s,%s)",
            (sid, tid, wf, ver, next_run_at, uid),
        )
    return sid


def _one(owner: str, sql: str, params: tuple[object, ...] = ()) -> object:
    with psycopg.connect(owner) as c:
        row = c.execute(sql, params).fetchone()
    return row[0] if row else None


def test_quiescence_transition_matrix_and_isolation(pg_stack: SimpleNamespace) -> None:
    o = pg_stack.owner_libpq
    engine = create_engine(pg_stack.owner_sa)
    cutoff_ref = datetime.now(UTC)

    # Two tenants, each with a mix of non-terminal + terminal work.
    ta, ua, va, wfa = _seed_tenant(o)
    tb, ub, vb, wfb = _seed_tenant(o)

    # Non-terminal runs (must be quiesced) across BOTH tenants.
    pending = _run(o, ta, va, "PENDING", key="user-key-a")
    running = _run(o, ta, va, "RUNNING")
    waiting = _run(o, tb, vb, "WAITING_APPROVAL")
    # Terminal runs (must be untouched).
    completed = _run(o, ta, va, "COMPLETED")
    failed = _run(o, tb, vb, "FAILED")

    _step(o, ta, running, "RUNNING")  # non-terminal step -> FAILED
    _step(o, ta, completed, "SUCCESS")  # terminal step -> unchanged

    key_pending = uuid.uuid4()
    _action(o, ta, running, "pending", key_pending)  # -> unknown
    key_success = uuid.uuid4()
    _action(o, ta, completed, "success", key_success)  # unchanged

    # Schedules: one stale (would replay), one already-future.
    stale_sched = _schedule(o, ta, wfa, va, ua, cutoff_ref - timedelta(hours=1))
    future_at = cutoff_ref + timedelta(days=3)
    future_sched = _schedule(o, tb, wfb, vb, ub, future_at)

    result = quiesce(engine)

    # Runs: all 3 non-terminal (both tenants) FAILED with the DR reason; terminal unchanged.
    assert result.runs_quiesced == 3
    for rid in (pending, running, waiting):
        assert _one(o, "SELECT status FROM workflow_runs WHERE id=%s", (rid,)) == "FAILED"
        assert (
            _one(o, "SELECT error FROM workflow_runs WHERE id=%s", (rid,)) == DR_RESTORE_UNCERTAIN
        )
    assert _one(o, "SELECT status FROM workflow_runs WHERE id=%s", (completed,)) == "COMPLETED"
    assert _one(o, "SELECT status FROM workflow_runs WHERE id=%s", (failed,)) == "FAILED"
    # Idempotency key preserved (not reused/regenerated).
    assert (
        _one(o, "SELECT idempotency_key FROM workflow_runs WHERE id=%s", (pending,)) == "user-key-a"
    )

    # Steps: non-terminal -> FAILED; SUCCESS unchanged.
    assert _one(o, "SELECT status FROM step_runs WHERE run_id=%s", (running,)) == "FAILED"
    assert (
        _one(o, "SELECT error FROM step_runs WHERE run_id=%s", (running,)) == DR_RESTORE_UNCERTAIN
    )
    assert _one(o, "SELECT status FROM step_runs WHERE run_id=%s", (completed,)) == "SUCCESS"

    # Actions: pending -> unknown (lease cleared, key unchanged); success unchanged.
    assert result.actions_unknowned == 1
    assert (
        _one(o, "SELECT status FROM external_actions WHERE external_action_key=%s", (key_pending,))
        == "unknown"
    )
    assert (
        _one(
            o,
            "SELECT error_class FROM external_actions WHERE external_action_key=%s",
            (key_pending,),
        )
        == ACTION_OUTCOME_UNKNOWN
    )
    assert (
        _one(
            o,
            "SELECT lease_token FROM external_actions WHERE external_action_key=%s",
            (key_pending,),
        )
        is None
    )
    assert (
        _one(
            o,
            "SELECT next_attempt_at FROM external_actions WHERE external_action_key=%s",
            (key_pending,),
        )
        is None
    )
    assert (
        _one(o, "SELECT status FROM external_actions WHERE external_action_key=%s", (key_success,))
        == "success"
    )

    # Schedules: stale recomputed strictly after cutoff; future untouched.
    assert result.schedules_recomputed == 1
    new_next = _one(o, "SELECT next_run_at FROM schedules WHERE id=%s", (stale_sched,))
    assert isinstance(new_next, datetime)
    assert new_next > result.cutoff
    assert _one(o, "SELECT next_run_at FROM schedules WHERE id=%s", (future_sched,)) == future_at

    # Audit event recorded with counts.
    assert result.event_recorded
    assert (
        _one(o, "SELECT runs_quiesced FROM dr_restore_events ORDER BY restored_at DESC LIMIT 1")
        == 3
    )


def test_quiescence_is_idempotent(pg_stack: SimpleNamespace) -> None:
    o = pg_stack.owner_libpq
    engine = create_engine(pg_stack.owner_sa)
    ta, ua, va, wfa = _seed_tenant(o)
    _run(o, ta, va, "RUNNING")
    _schedule(o, ta, wfa, va, ua, datetime.now(UTC) - timedelta(hours=2))

    first = quiesce(engine)
    assert first.runs_quiesced == 1 and first.event_recorded

    second = quiesce(engine)
    assert second.runs_quiesced == 0
    assert second.actions_unknowned == 0
    assert second.schedules_recomputed == 0  # already after cutoff
    assert second.event_recorded is False  # no new audit row on a no-op re-run
    events = _one(o, "SELECT count(*) FROM dr_restore_events")
    assert events == 1  # only the first run recorded
