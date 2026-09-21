"""P1D scheduler/reconciler smoke driver (host side).

Runs the REAL packaged scheduler/reconciler code against the containerized
Postgres stood up by ``smoke-p1d-scheduler-reconciler.sh``. Proves, against a real
DB with migration 0013 applied:

1. migration 0013 is live (last_progress_at, recon indexes, scheduler step_runs
   column grant WITHOUT step I/O);
2. one run per scheduled occurrence, and a repeat scan creates NO duplicate;
3. the reconciler recovers an eligible stale run while EXCLUDING beyond-horizon
   and terminal P1C-UNKNOWN runs;
4. per-tenant fairness: a noisy tenant is capped, a quiet tenant still progresses;
5. approval reconciliation binds to the CURRENTLY-blocked step only.

Env: OWNER_LIBPQ (owner), SCHED_SA (scheduler SQLAlchemy URL).
"""

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta

import psycopg

from nlw.core.config import Settings
from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.scheduler.due import scan_due
from nlw.scheduler.reconcile import find_stuck_runs

OWNER = os.environ.get("OWNER_LIBPQ", "postgresql://nlw:nlw@localhost:5433/nlw")
SCHED_SA = os.environ.get(
    "SCHED_SA", "postgresql+psycopg://nlw_scheduler:nlw_scheduler@localhost:5433/nlw"
)
NOW = datetime(2026, 5, 1, 9, 30, tzinfo=UTC)
OLD = NOW - timedelta(minutes=10)
ANCIENT = NOW - timedelta(days=40)


def _fail(msg: str) -> None:
    print(f"SMOKE FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def _ok(msg: str) -> None:
    print(f"  [ok] {msg}")


def _sched_sm():  # type: ignore[no-untyped-def]
    return create_sync_sessionmaker(
        create_sync_engine(Settings(_env_file=None, database_url=SCHED_SA))
    )


def _tenant() -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    """Create a workspace + user + workflow(version); return (tenant, user, ver)."""
    tid, uid, wf, ver = (uuid.uuid4() for _ in range(4))
    with psycopg.connect(OWNER, autocommit=True) as c:
        c.execute("INSERT INTO workspaces (id, name, slug) VALUES (%s,'ws',%s)", (tid, f"ws-{tid}"))
        c.execute(
            "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s)",
            (uid, str(uid), f"{uid}@e.com"),
        )
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf, tid))
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            'VALUES (%s,%s,%s,1,\'{"steps":[{"id":"a","tool":"fake.echo","args":{}}]}\'::jsonb)',
            (ver, tid, wf),
        )
        c.execute("UPDATE workflows SET current_version_id=%s WHERE id=%s", (ver, wf))
    return tid, uid, ver, wf  # type: ignore[return-value]


def _run(tid, ver, status, *, created, last_progress=None, run_id=None):  # type: ignore[no-untyped-def]
    rid = run_id or uuid.uuid4()
    wf = uuid.uuid4()
    with psycopg.connect(OWNER, autocommit=True) as c:
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'w')", (wf, tid))
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status, "
            "created_at, updated_at, last_progress_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (rid, tid, wf, ver, status, created, created, last_progress),
        )
    return rid


def check_migration() -> None:
    with psycopg.connect(OWNER) as c:
        col = c.execute(
            "SELECT count(*) FROM information_schema.columns "
            "WHERE table_name='workflow_runs' AND column_name='last_progress_at'"
        ).fetchone()[0]
        idx = c.execute(
            "SELECT count(*) FROM pg_indexes WHERE tablename='workflow_runs' "
            "AND indexname LIKE 'ix_workflow_runs_recon_%'"
        ).fetchone()[0]
    if col != 1:
        _fail("last_progress_at column missing")
    if idx != 3:
        _fail(f"expected 3 recon indexes, found {idx}")
    # Scheduler can read step status but NOT step I/O.
    with psycopg.connect(SCHED_SA.replace("postgresql+psycopg", "postgresql")) as c:
        c.execute("SELECT run_id, step_id, status FROM step_runs")  # allowed
        try:
            c.execute("SELECT input, output FROM step_runs")
            _fail("scheduler could read step I/O (isolation broken)")
        except psycopg.errors.InsufficientPrivilege:
            pass
    _ok("migration 0013 live: last_progress_at, 3 recon indexes, scheduler step-status-only grant")


def check_occurrence_idempotency() -> None:
    tid, uid, ver, wf = _tenant()
    sid = uuid.uuid4()
    with psycopg.connect(OWNER, autocommit=True) as c:
        c.execute(
            "INSERT INTO schedules (id, tenant_id, workflow_id, workflow_version_id, timezone, "
            "frequency, minute, hour, enabled, next_run_at, created_by) "
            "VALUES (%s,%s,%s,%s,'UTC','daily',0,9,true,%s,%s)",
            (sid, tid, wf, ver, NOW - timedelta(minutes=1), uid),
        )
    sm = _sched_sm()
    with sm() as s, s.begin():
        created1 = scan_due(s, NOW, catchup_window_s=3600, batch_limit=10)
    with sm() as s, s.begin():
        created2 = scan_due(s, NOW, catchup_window_s=3600, batch_limit=10)
    if len(created1) != 1:
        _fail(f"first scan created {len(created1)} runs, expected 1")
    if created2:
        _fail(f"repeat scan created {len(created2)} runs, expected 0 (idempotent)")
    with psycopg.connect(OWNER) as c:
        key = c.execute(
            "SELECT idempotency_key FROM workflow_runs WHERE schedule_id=%s", (sid,)
        ).fetchone()[0]
    if key is not None:
        _fail(f"scheduled run has non-null idempotency_key {key!r} (namespace not separated)")
    _ok("one run per occurrence; repeat scan is a no-op; scheduled key is NULL")


def check_reconciler_fairness_and_eligibility() -> None:
    noisy_t, _, noisy_ver, _ = _tenant()
    quiet_t, _, quiet_ver, _ = _tenant()
    # Noisy tenant: 60 stale PENDING (> per-tenant cap of 20).
    for _ in range(60):
        _run(noisy_t, noisy_ver, "PENDING", created=OLD)
    quiet = _run(quiet_t, quiet_ver, "PENDING", created=OLD)
    beyond = _run(noisy_t, noisy_ver, "PENDING", created=ANCIENT)  # past horizon
    # A terminal P1C-UNKNOWN run must never be re-enqueued.
    unknown_run = _run(noisy_t, noisy_ver, "RUNNING", created=OLD, last_progress=OLD)
    with psycopg.connect(OWNER, autocommit=True) as c:
        c.execute(
            "INSERT INTO external_actions (id, tenant_id, run_id, step_id, connector_id, tool, "
            "external_action_key, status, attempts) "
            "VALUES (%s,%s,%s,'a',%s,'webhook.send',%s,'unknown',1)",
            (uuid.uuid4(), noisy_t, unknown_run, uuid.uuid4(), uuid.uuid4()),
        )

    with _sched_sm()() as s, s.begin():
        batch = find_stuck_runs(
            s,
            NOW,
            pending_threshold_s=60,
            batch_limit=100,
            recovery_horizon_s=86_400,
            per_tenant_limit=20,
        )
    ids = set(batch.run_ids)
    if quiet not in ids:
        _fail("quiet tenant's eligible run was starved")
    if beyond in ids:
        _fail("beyond-horizon run was re-enqueued")
    if unknown_run in ids:
        _fail("terminal UNKNOWN run was re-enqueued")
    noisy_selected = sum(1 for rid in batch.run_ids if _tenant_of(rid) == noisy_t)
    if noisy_selected > 20:
        _fail(f"noisy tenant exceeded per-tenant cap: {noisy_selected}")
    _ok(
        f"reconciler: quiet recovered, noisy capped at {noisy_selected}<=20, "
        f"beyond-horizon={batch.beyond_horizon} excluded, UNKNOWN excluded"
    )


def _tenant_of(run_id: uuid.UUID) -> uuid.UUID:
    with psycopg.connect(OWNER) as c:
        row = c.execute("SELECT tenant_id FROM workflow_runs WHERE id=%s", (run_id,)).fetchone()
    return uuid.UUID(str(row[0]))


def check_approval_binding() -> None:
    tid, _, ver, _ = _tenant()
    run = _run(tid, ver, "WAITING_APPROVAL", created=OLD, last_progress=OLD)
    with psycopg.connect(OWNER, autocommit=True) as c:
        # Historical approved step 'a' (SUCCESS) + current pending step 'b'.
        for step_id, st in (("a", "SUCCESS"), ("b", "WAITING_APPROVAL")):
            c.execute(
                "INSERT INTO step_runs (id, tenant_id, run_id, step_id, tool, status, attempt) "
                "VALUES (%s,%s,%s,%s,'webhook.send',%s,0)",
                (uuid.uuid4(), tid, run, step_id, st),
            )
        for step_id, st in (("a", "approved"), ("b", "pending")):
            c.execute(
                "INSERT INTO approvals (id, tenant_id, run_id, step_id, connector_id, "
                "connector_name, tool, status) VALUES (%s,%s,%s,%s,%s,'h','webhook.send',%s)",
                (uuid.uuid4(), tid, run, step_id, uuid.uuid4(), st),
            )

    def selected() -> bool:
        with _sched_sm()() as s, s.begin():
            b = find_stuck_runs(
                s,
                NOW,
                pending_threshold_s=60,
                batch_limit=100,
                recovery_horizon_s=86_400,
                per_tenant_limit=20,
            )
        return run in set(b.run_ids)

    if selected():
        _fail("run re-enqueued while current step's approval is still pending")
    with psycopg.connect(OWNER, autocommit=True) as c:
        c.execute("UPDATE approvals SET status='approved' WHERE run_id=%s AND step_id='b'", (run,))
    if not selected():
        _fail("run NOT re-enqueued after the current step's approval was decided")
    _ok("approval reconciliation binds to the currently-blocked step only")


def check_single_approval_instance() -> None:
    """Current-vs-historical binding: the DB enforces one approval per (run_id,
    step_id), so a historical decided row cannot coexist with the current pending
    one for the SAME step — a second insert fails closed."""
    tid, _, ver, _ = _tenant()
    run = _run(tid, ver, "WAITING_APPROVAL", created=OLD, last_progress=OLD)
    with psycopg.connect(OWNER, autocommit=True) as c:
        c.execute(
            "INSERT INTO step_runs (id, tenant_id, run_id, step_id, tool, status, attempt) "
            "VALUES (%s,%s,%s,'s','webhook.send','WAITING_APPROVAL',0)",
            (uuid.uuid4(), tid, run),
        )
        c.execute(
            "INSERT INTO approvals (id, tenant_id, run_id, step_id, connector_id, connector_name, "
            "tool, status) VALUES (%s,%s,%s,'s',%s,'h','webhook.send','pending')",
            (uuid.uuid4(), tid, run, uuid.uuid4()),
        )
    # Injecting a second (historical) approval for the same (run_id, step_id) fails.
    rejected = False
    try:
        with psycopg.connect(OWNER, autocommit=True) as c:
            c.execute(
                "INSERT INTO approvals (id, tenant_id, run_id, step_id, connector_id, "
                "connector_name, tool, status) VALUES (%s,%s,%s,'s',%s,'h','webhook.send',"
                "'approved')",
                (uuid.uuid4(), tid, run, uuid.uuid4()),
            )
    except psycopg.errors.UniqueViolation:
        rejected = True
    if not rejected:
        _fail("a second approval for the same (run_id, step_id) was allowed")
    with psycopg.connect(OWNER) as c:
        n = c.execute(
            "SELECT count(*) FROM approvals WHERE run_id=%s AND step_id='s'", (run,)
        ).fetchone()[0]
    if n != 1:
        _fail(f"expected exactly one approval per (run_id, step_id), found {n}")
    _ok("exactly one approval per (run_id, step_id); historical/current cannot coexist")


def main() -> None:
    print("P1D scheduler/reconciler smoke (containerized Postgres, real packaged code)")
    check_migration()
    check_occurrence_idempotency()
    check_reconciler_fairness_and_eligibility()
    check_approval_binding()
    check_single_approval_instance()
    print(
        "SMOKE PASS: scheduler occurrence idempotency, reconciler fairness/eligibility, "
        "progress-aware recovery, approval-to-step binding, and single-approval-instance "
        "binding all verified."
    )


if __name__ == "__main__":
    main()
