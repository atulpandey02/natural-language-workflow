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
from nlw.scheduler.reconcile import _CANDIDATES_SQL, ReconcileBatch, find_stuck_runs
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
    last_progress: datetime | None = None,
    run_id: uuid.UUID | None = None,
) -> uuid.UUID:
    rid = run_id or uuid.uuid4()
    wf = uuid.uuid4()
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'w')", (wf, tenant))
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status, "
            "created_at, updated_at, last_progress_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (rid, tenant, wf, ver, status, created, updated, last_progress),
        )
    return rid


def _step(
    owner: str,
    tenant: uuid.UUID,
    run_id: uuid.UUID,
    *,
    step_id: str = "a",
    status: str = "WAITING_APPROVAL",
    tool: str = "webhook.send",
) -> None:
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute(
            "INSERT INTO step_runs (id, tenant_id, run_id, step_id, tool, status, attempt) "
            "VALUES (%s,%s,%s,%s,%s,%s,0)",
            (uuid.uuid4(), tenant, run_id, step_id, tool, status),
        )


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


def _approval(
    owner: str,
    tenant: uuid.UUID,
    run_id: uuid.UUID,
    status: str,
    *,
    step_id: str = "a",
    step_status: str = "WAITING_APPROVAL",
    with_step: bool = True,
) -> None:
    # A WAITING_APPROVAL run's approval is bound to its currently-blocked step
    # (P1D): the reconciler only re-drives when THAT step's approval is decided, so
    # seed the matching step_run in the given status.
    if with_step:
        _step(owner, tenant, run_id, step_id=step_id, status=step_status)
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute(
            "INSERT INTO approvals (id, tenant_id, run_id, step_id, connector_id, connector_name, "
            "tool, status) VALUES (%s,%s,%s,%s,%s,'hook','webhook.send',%s)",
            (uuid.uuid4(), tenant, run_id, step_id, uuid.uuid4(), status),
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
        stuck = set(
            find_stuck_runs(
                s,
                NOW,
                pending_threshold_s=60,
                batch_limit=100,
                recovery_horizon_s=10**9,
                per_tenant_limit=100,
            ).run_ids
        )

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
        stuck = set(
            find_stuck_runs(
                s,
                NOW,
                pending_threshold_s=60,
                batch_limit=100,
                recovery_horizon_s=10**9,
                per_tenant_limit=100,
            ).run_ids
        )

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


# --- P1D: candidate ordering, fairness, progress, approval binding ---


def _batch(
    pg_stack: SimpleNamespace,
    *,
    batch: int,
    per_tenant: int,
    horizon_s: int = 10**9,
    pending_s: int = 60,
) -> ReconcileBatch:
    with _sched_sm(pg_stack)() as s, s.begin():
        return find_stuck_runs(
            s,
            NOW,
            pending_threshold_s=pending_s,
            batch_limit=batch,
            recovery_horizon_s=horizon_s,
            per_tenant_limit=per_tenant,
        )


def _tenant_of(owner: str, run_id: uuid.UUID) -> uuid.UUID:
    with psycopg.connect(owner) as c:
        row = c.execute("SELECT tenant_id FROM workflow_runs WHERE id=%s", (run_id,)).fetchone()
    assert row is not None
    return uuid.UUID(str(row[0]))


def _bulk_pending(owner: str, tenant: uuid.UUID, ver: uuid.UUID, n: int, created: datetime) -> None:
    wf = uuid.uuid4()
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'w')", (wf, tenant))
        with c.cursor() as cur:
            cur.executemany(
                "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, "
                "status, created_at, updated_at) VALUES (%s,%s,%s,%s,'PENDING',%s,%s)",
                [(uuid.uuid4(), tenant, wf, ver, created, created) for _ in range(n)],
            )


def test_beyond_horizon_exceeding_batch_still_surfaces_eligible_row(
    pg_stack: SimpleNamespace,
) -> None:
    """Req 8 / defect B: many beyond-horizon rows (more than the batch) must NOT
    crowd out a single eligible stale row — eligibility/horizon filter BEFORE
    LIMIT. (Under the old ORDER-BY-updated_at-then-LIMIT design the ancient rows
    filled the batch and the eligible row was never reached.)"""
    m = pg_stack.seed_member()
    ver = _seed_wf(pg_stack.owner_libpq, m.tenant_id)
    o, t = pg_stack.owner_libpq, m.tenant_id

    ancient = NOW - timedelta(days=30)  # beyond a 1-day horizon
    _bulk_pending(o, t, ver, 25, ancient)  # 25 beyond-horizon rows (>> batch of 5)
    eligible = _run(o, t, ver, "PENDING", created=OLD, updated=OLD)  # stale, within horizon

    batch = _batch(pg_stack, batch=5, per_tenant=5, horizon_s=86_400)

    assert eligible in batch.run_ids  # the eligible row surfaced despite 25 beyond rows
    assert batch.beyond_horizon == 25  # all ancient rows counted, not re-enqueued
    assert len(batch.run_ids) <= 5


def test_noisy_tenant_does_not_starve_quiet_tenant(pg_stack: SimpleNamespace) -> None:
    """Req 9 / defect D: one tenant with far more stale rows than the batch cannot
    starve a quiet tenant's single eligible row."""
    noisy = pg_stack.seed_member()
    quiet = pg_stack.seed_member()
    ver_n = _seed_wf(pg_stack.owner_libpq, noisy.tenant_id)
    ver_q = _seed_wf(pg_stack.owner_libpq, quiet.tenant_id)

    _bulk_pending(pg_stack.owner_libpq, noisy.tenant_id, ver_n, 150, OLD)  # > batch of 100
    quiet_run = _run(
        pg_stack.owner_libpq, quiet.tenant_id, ver_q, "PENDING", created=OLD, updated=OLD
    )

    batch = _batch(pg_stack, batch=100, per_tenant=20)

    assert quiet_run in batch.run_ids  # the quiet tenant still makes progress
    # The noisy tenant is capped at its per-tenant share, not the whole batch.
    noisy_selected = sum(
        1 for rid in batch.run_ids if _tenant_of(pg_stack.owner_libpq, rid) == noisy.tenant_id
    )
    assert noisy_selected == 20  # exactly the per-tenant cap
    assert batch.fairness_deferred == 130  # 150 - 20 deferred to a later scan


def test_per_tenant_and_global_caps_are_respected(pg_stack: SimpleNamespace) -> None:
    """Req 10: total <= batch_limit and per-tenant <= per_tenant_limit."""
    members = [pg_stack.seed_member() for _ in range(4)]
    for mem in members:
        ver = _seed_wf(pg_stack.owner_libpq, mem.tenant_id)
        _bulk_pending(pg_stack.owner_libpq, mem.tenant_id, ver, 30, OLD)

    batch = _batch(pg_stack, batch=50, per_tenant=15)

    assert len(batch.run_ids) <= 50  # global cap
    per_tenant: dict[uuid.UUID, int] = {}
    for rid in batch.run_ids:
        tid = _tenant_of(pg_stack.owner_libpq, rid)
        per_tenant[tid] = per_tenant.get(tid, 0) + 1
    assert all(v <= 15 for v in per_tenant.values())  # per-tenant cap


def test_concurrent_reconcilers_write_nothing_and_both_select(pg_stack: SimpleNamespace) -> None:
    """Req 11: two reconcilers on separate connections both SELECT the stale run
    without mutating/claiming it (the reconciler writes nothing); worker-level
    FOR UPDATE + idempotent replay then advance it at most once."""
    import threading

    m = pg_stack.seed_member()
    ver = _seed_wf(pg_stack.owner_libpq, m.tenant_id)
    run_id = _run(pg_stack.owner_libpq, m.tenant_id, ver, "PENDING", created=OLD, updated=OLD)

    barrier = threading.Barrier(2)
    seen: list[list[uuid.UUID]] = [[], []]

    def racer(i: int) -> None:
        barrier.wait()
        seen[i] = _batch(pg_stack, batch=100, per_tenant=100).run_ids

    threads = [threading.Thread(target=racer, args=(i,)) for i in range(2)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    assert run_id in seen[0] and run_id in seen[1]  # both select it (read-only)
    # The reconciler mutated nothing: still PENDING, progress untouched (req 13).
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT status, last_progress_at FROM workflow_runs WHERE id=%s", (run_id,)
        ).fetchone()
    assert row is not None and row[0] == "PENDING" and row[1] is None


def test_fresh_progress_prevents_premature_recovery(pg_stack: SimpleNamespace) -> None:
    """Req 12 / defect C: a RUNNING run created long ago but ACTIVELY progressing
    (fresh last_progress_at) is NOT reconciled; the same run with stale progress
    IS. Proves staleness is measured by last_progress_at, not created/updated_at."""
    m = pg_stack.seed_member()
    ver = _seed_wf(pg_stack.owner_libpq, m.tenant_id)
    o, t = pg_stack.owner_libpq, m.tenant_id

    progressing = _run(o, t, ver, "RUNNING", created=OLD, updated=OLD, last_progress=FRESH)
    stalled = _run(o, t, ver, "RUNNING", created=OLD, updated=NOW, last_progress=OLD)

    stuck = set(_batch(pg_stack, batch=100, per_tenant=100).run_ids)
    assert progressing not in stuck  # actively progressing -> left alone
    assert stalled in stuck  # no progress since the threshold -> recovered


def test_reconcile_binds_approval_to_the_current_waiting_step(pg_stack: SimpleNamespace) -> None:
    """Req 18/19/23 / defect E: a run with a HISTORICAL decided approval (its step
    already advanced) whose CURRENT waiting step's approval is still pending must
    NOT be re-enqueued. Only the currently-blocked step's approval counts."""
    m = pg_stack.seed_member()
    ver = _seed_wf(pg_stack.owner_libpq, m.tenant_id)
    o, t = pg_stack.owner_libpq, m.tenant_id

    # Run blocked on step 'b' (pending approval); step 'a' was approved earlier and
    # is now SUCCESS (historical). A run-scoped "any decided approval" check would
    # wrongly re-enqueue this run.
    run_id = _run(o, t, ver, "WAITING_APPROVAL", created=OLD, updated=OLD)
    _step(o, t, run_id, step_id="a", status="SUCCESS")
    _approval(o, t, run_id, "approved", step_id="a", with_step=False)  # historical, decided
    _step(o, t, run_id, step_id="b", status="WAITING_APPROVAL")
    _approval(o, t, run_id, "pending", step_id="b", with_step=False)  # current, pending

    stuck = set(_batch(pg_stack, batch=100, per_tenant=100).run_ids)
    assert run_id not in stuck  # current step still pending -> stays blocked

    # Now decide the CURRENT step's approval -> the run becomes eligible.
    with psycopg.connect(o, autocommit=True) as c:
        c.execute(
            "UPDATE approvals SET status='approved' WHERE run_id=%s AND step_id='b'", (run_id,)
        )
    stuck2 = set(_batch(pg_stack, batch=100, per_tenant=100).run_ids)
    assert run_id in stuck2


def test_reconcile_ignores_a_decided_approval_for_a_non_waiting_step(
    pg_stack: SimpleNamespace,
) -> None:
    """Req 23: a decided approval whose step is NOT in WAITING_APPROVAL status does
    not re-drive the run (the binding requires the step to be currently blocked)."""
    m = pg_stack.seed_member()
    ver = _seed_wf(pg_stack.owner_libpq, m.tenant_id)
    o, t = pg_stack.owner_libpq, m.tenant_id

    # The run is WAITING_APPROVAL, but the ONLY decided approval belongs to a step
    # that is already FAILED/past (not the blocked one), and the blocked step 'c'
    # has no decided approval.
    run_id = _run(o, t, ver, "WAITING_APPROVAL", created=OLD, updated=OLD)
    _step(o, t, run_id, step_id="a", status="FAILED")
    _approval(o, t, run_id, "rejected", step_id="a", with_step=False)
    _step(o, t, run_id, step_id="c", status="WAITING_APPROVAL")
    _approval(o, t, run_id, "pending", step_id="c", with_step=False)

    stuck = set(_batch(pg_stack, batch=100, per_tenant=100).run_ids)
    assert run_id not in stuck


def test_reconciler_candidate_query_avoids_full_table_scan(pg_stack: SimpleNamespace) -> None:
    """Part G: on a realistic mostly-terminal table the candidate query must NOT
    seq-scan-and-sort the whole of workflow_runs every poll — the planner naturally
    uses an index (a partial recon index / the tenant index) to prune candidates."""
    m = pg_stack.seed_member()
    ver = _seed_wf(pg_stack.owner_libpq, m.tenant_id)
    # Realistic shape: the vast majority of runs are terminal; a handful are stale.
    wf = uuid.uuid4()
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'w')", (wf, m.tenant_id)
        )
        with c.cursor() as cur:
            cur.executemany(
                "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, "
                "status, created_at, updated_at, last_progress_at) "
                "VALUES (%s,%s,%s,%s,'COMPLETED',%s,%s,%s)",
                [(uuid.uuid4(), m.tenant_id, wf, ver, OLD, OLD, OLD) for _ in range(3000)],
            )
    _bulk_pending(pg_stack.owner_libpq, m.tenant_id, ver, 40, OLD)  # the few eligible rows

    from sqlalchemy import text as _text

    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute("ANALYZE workflow_runs")

    params = {
        "now": NOW,
        "stale_before": NOW - timedelta(seconds=60),
        "horizon_before": NOW - timedelta(days=1),
        "batch": 100,
        "per_tenant_limit": 20,
    }
    with _sched_sm(pg_stack)() as s, s.begin():
        plan = "\n".join(
            str(row[0]) for row in s.execute(_text("EXPLAIN " + _CANDIDATES_SQL.text), params).all()
        )
    # The planner uses an index (recon partial or the tenant index) to reach the
    # candidates and does NOT sequentially scan the whole workflow_runs table.
    assert "Index Scan" in plan or "Bitmap Index Scan" in plan, plan
    assert "Seq Scan on workflow_runs" not in plan, plan
