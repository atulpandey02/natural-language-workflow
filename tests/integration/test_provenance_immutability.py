"""Provenance & decision immutability — direct-SQL adversarial tests (M11.5 P3A+).

Establishes, against a real PostgreSQL, that authorization provenance cannot be
rewritten by any runtime role and that a terminal approval decision is final:

- ``approvals.requested_by_user_id`` is immutable (column grant for nlw_app; a
  BEFORE-UPDATE trigger for every other role, including the table owner).
- ``workflow_runs.initiated_by_user_id`` is immutable — closes the confirmed gap
  where nlw_worker's table-level UPDATE could rewrite run provenance.
- ``schedules.created_by`` is immutable — closes the confirmed gap where nlw_app's
  table-level UPDATE could rewrite schedule provenance.
- The FIRST terminal approval decision is immutable: no APPROVED<->REJECTED, no
  ->PENDING, and decided_by/decided_at cannot change once decided.

Each test first shows the legitimate write still works, then proves the attack is
rejected (fail closed) and the row is unchanged.
"""

import uuid
from types import SimpleNamespace

import psycopg
import pytest

pytestmark = pytest.mark.integration


def _seed_ws(owner_libpq: str) -> uuid.UUID:
    tid = uuid.uuid4()
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute("INSERT INTO workspaces (id, name, slug) VALUES (%s,'ws',%s)", (tid, f"w-{tid}"))
    return tid


def _seed_user(owner_libpq: str, tid: uuid.UUID, sub: str, role: str) -> uuid.UUID:
    uid = uuid.uuid4()
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s)",
            (uid, sub, f"{sub}@x.com"),
        )
        c.execute(
            "INSERT INTO memberships (id, user_id, workspace_id, role) VALUES (%s,%s,%s,%s)",
            (uuid.uuid4(), uid, tid, role),
        )
    return uid


def _seed_run_and_approval(
    owner_libpq: str, tid: uuid.UUID, requester: uuid.UUID
) -> tuple[uuid.UUID, uuid.UUID]:
    wf, ver, run, appr, conn_id = (uuid.uuid4() for _ in range(5))
    plan = '{"steps":[{"id":"notify","tool":"webhook.send","args":{},"connector":"hook"}]}'
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO connectors (id, tenant_id, type, name, config, secret_ref, status) "
            "VALUES (%s,%s,'webhook','hook','{\"url\":\"https://s.example/h\"}'::jsonb,NULL,'active')",
            (conn_id, tid),
        )
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf, tid))
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,%s::jsonb)",
            (ver, tid, wf, plan),
        )
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status, "
            "initiated_by_user_id) VALUES (%s,%s,%s,%s,'WAITING_APPROVAL',%s)",
            (run, tid, wf, ver, requester),
        )
        c.execute(
            "INSERT INTO approvals (id, tenant_id, run_id, step_id, connector_id, connector_name, "
            "tool, status, requested_by_user_id) "
            "VALUES (%s,%s,%s,'notify',%s,'hook','webhook.send','pending',%s)",
            (appr, tid, run, conn_id, requester),
        )
    return run, appr


def _seed_schedule(owner_libpq: str, tid: uuid.UUID, creator: uuid.UUID) -> uuid.UUID:
    wf, ver, sid = (uuid.uuid4() for _ in range(3))
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf, tid))
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,'{\"steps\":[]}'::jsonb)",
            (ver, tid, wf),
        )
        c.execute(
            "INSERT INTO schedules (id, tenant_id, workflow_id, workflow_version_id, timezone, "
            "frequency, minute, hour, enabled, next_run_at, created_by) "
            "VALUES (%s,%s,%s,%s,'UTC','daily',0,9,true,now(),%s)",
            (sid, tid, wf, ver, creator),
        )
    return sid


# --- A1: nlw_app cannot rewrite/nullify approvals.requested_by_user_id (grant) ---
def test_app_cannot_rewrite_requester_column_grant(pg_stack: SimpleNamespace) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    a = _seed_user(pg_stack.owner_libpq, tid, "a1", "owner")
    b = _seed_user(pg_stack.owner_libpq, tid, "b1", "member")
    _run, appr = _seed_run_and_approval(pg_stack.owner_libpq, tid, a)
    with psycopg.connect(pg_stack.app_libpq, autocommit=True) as c:
        c.execute("SELECT set_config('app.user_id', %s, false)", (str(a),))
        c.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tid),))
        # Combined self-approve AND rewrite requester A->B in one UPDATE.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(
                "UPDATE approvals SET status='approved', decided_by=%s, decided_at=now(), "
                "requested_by_user_id=%s WHERE id=%s",
                (a, b, appr),
            )
        # Nullify requester to defeat the four-eyes NOT NULL guard.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("UPDATE approvals SET requested_by_user_id=NULL WHERE id=%s", (appr,))
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT status, requested_by_user_id FROM approvals WHERE id=%s", (appr,)
        ).fetchone()
    assert row is not None and row[0] == "pending" and uuid.UUID(str(row[1])) == a


# --- A2: the trigger blocks a requester rewrite even for a role WITH table UPDATE ---
def test_trigger_blocks_requester_rewrite_even_for_owner(pg_stack: SimpleNamespace) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    a = _seed_user(pg_stack.owner_libpq, tid, "a2", "owner")
    b = _seed_user(pg_stack.owner_libpq, tid, "b2", "member")
    _run, appr = _seed_run_and_approval(pg_stack.owner_libpq, tid, a)
    # owner_libpq has full table UPDATE, yet the BEFORE-UPDATE trigger rejects it.
    with (
        psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        c.execute("UPDATE approvals SET requested_by_user_id=%s WHERE id=%s", (b, appr))
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT requested_by_user_id FROM approvals WHERE id=%s", (appr,)
        ).fetchone()
    assert row is not None and uuid.UUID(str(row[0])) == a


# --- A3: nlw_worker cannot rewrite workflow_runs.initiated_by_user_id (trigger) ---
def test_worker_cannot_rewrite_run_initiator(pg_stack: SimpleNamespace) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    a = _seed_user(pg_stack.owner_libpq, tid, "a3", "owner")
    b = _seed_user(pg_stack.owner_libpq, tid, "b3", "member")
    run, _appr = _seed_run_and_approval(pg_stack.owner_libpq, tid, a)
    with psycopg.connect(pg_stack.worker_libpq, autocommit=True) as c:
        c.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tid),))
        # A legitimate status update (no provenance change) is allowed.
        c.execute("UPDATE workflow_runs SET status='RUNNING' WHERE id=%s", (run,))
        # Rewriting the initiator is rejected by the immutability trigger.
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute("UPDATE workflow_runs SET initiated_by_user_id=%s WHERE id=%s", (b, run))
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT status, initiated_by_user_id FROM workflow_runs WHERE id=%s", (run,)
        ).fetchone()
    assert row is not None and row[0] == "RUNNING" and uuid.UUID(str(row[1])) == a


# --- A4: nlw_app cannot rewrite schedules.created_by (trigger) ---
def test_app_cannot_rewrite_schedule_creator(pg_stack: SimpleNamespace) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    a = _seed_user(pg_stack.owner_libpq, tid, "a4", "owner")
    b = _seed_user(pg_stack.owner_libpq, tid, "b4", "member")
    sid = _seed_schedule(pg_stack.owner_libpq, tid, a)
    with psycopg.connect(pg_stack.app_libpq, autocommit=True) as c:
        c.execute("SELECT set_config('app.user_id', %s, false)", (str(a),))
        c.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tid),))
        # A legitimate enable/disable update is allowed.
        c.execute("UPDATE schedules SET enabled=false WHERE id=%s", (sid,))
        # Rewriting the creator is rejected by the immutability trigger.
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute("UPDATE schedules SET created_by=%s WHERE id=%s", (b, sid))
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute("SELECT created_by FROM schedules WHERE id=%s", (sid,)).fetchone()
    assert row is not None and uuid.UUID(str(row[0])) == a


# --- A5: a terminal approval decision is immutable (no flip / re-decide) ---
def test_terminal_decision_is_immutable(pg_stack: SimpleNamespace) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    req = _seed_user(pg_stack.owner_libpq, tid, "reqA5", "member")
    dec = _seed_user(pg_stack.owner_libpq, tid, "decA5", "owner")
    _run, appr = _seed_run_and_approval(pg_stack.owner_libpq, tid, req)
    with psycopg.connect(pg_stack.app_libpq, autocommit=True) as c:
        c.execute("SELECT set_config('app.user_id', %s, false)", (str(dec),))
        c.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tid),))
        # Legitimate first decision: pending -> approved.
        c.execute(
            "UPDATE approvals SET status='approved', decided_by=%s, decided_at=now() WHERE id=%s",
            (dec, appr),
        )
        # Flip approved -> rejected is rejected (terminal is final).
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute(
                "UPDATE approvals SET status='rejected', decided_at=now() WHERE id=%s", (appr,)
            )
        # Re-open approved -> pending is rejected.
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute("UPDATE approvals SET status='pending' WHERE id=%s", (appr,))
        # Rewriting decided_by after the decision is rejected.
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute("UPDATE approvals SET decided_by=%s WHERE id=%s", (req, appr))
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute("SELECT status, decided_by FROM approvals WHERE id=%s", (appr,)).fetchone()
    assert row is not None and row[0] == "approved" and uuid.UUID(str(row[1])) == dec
