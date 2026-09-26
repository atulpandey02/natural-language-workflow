"""Fail-closed schedule ownership authorization (M12B final, Part 4).

A schedule creates occurrences only while its CREATOR remains an active member of
the workspace with a sufficient (owner/admin) role. Removal/demotion BLOCKS future
occurrences (no run, no enqueue) with a stable reason until an authorized admin
reassigns/re-enables it. Already-running occurrences keep the run/action safety
model; connector-binding freshness is enforced at execution (Part 3). The model
never decides authorization.

Each workspace keeps a distinct OWNER plus the schedule CREATOR (an admin), so a
test can remove/demote the creator without tripping the last-owner guard.
"""

import json
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import httpx
import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from nlw.api.app import create_app
from nlw.db.session import create_sync_engine, create_sync_sessionmaker
from nlw.engine.actions import ActionExecResult, ActionTask, run_action
from nlw.engine.execution import process_advance
from nlw.feasibility.connector_binding import build_binding
from nlw.scheduler.due import scan_due
from nlw.tenancy.keys import process_signer
from nlw.tenancy.session import set_scheduler_context_sync
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

NOW = datetime(2026, 1, 15, 14, 0, tzinfo=UTC)
ISSUER = "https://proj.supabase.co/auth/v1"
SECRET = "dev-secret-for-tests-32bytes-min-length"
_PLAN = {"steps": [{"id": "a", "tool": "fake.echo", "args": {"x": 1}}]}
_WEBHOOK_PLAN = {
    "steps": [
        {"id": "notify", "tool": "webhook.send", "args": {"payload": {"x": 1}}, "connector": "hook"}
    ]
}


class Setup(SimpleNamespace):
    tenant_id: uuid.UUID
    owner_id: uuid.UUID
    creator_id: uuid.UUID


def _scheduler_sm(pg_stack: SimpleNamespace) -> sessionmaker[Session]:
    return create_sync_sessionmaker(create_sync_engine(pg_stack.scheduler_settings))


def _worker_sm(pg_stack: SimpleNamespace) -> sessionmaker[Session]:
    return create_sync_sessionmaker(create_sync_engine(pg_stack.worker_settings))


def _setup(pg_stack: SimpleNamespace) -> Setup:
    """A workspace with a distinct OWNER and an admin CREATOR of schedules."""
    owner = pg_stack.seed_member()  # role owner (kept so the tenant always has one)
    creator = pg_stack.add_membership(owner.tenant_id, "admin")
    return Setup(tenant_id=owner.tenant_id, owner_id=owner.user_id, creator_id=creator)


def _seed_workflow(
    owner: str, tenant: uuid.UUID, plan: dict[str, Any], bindings: dict[str, Any] | None = None
) -> tuple[uuid.UUID, uuid.UUID]:
    wf, ver = uuid.uuid4(), uuid.uuid4()
    binding_json = json.dumps(bindings) if bindings else None
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf, tenant))
        c.execute(
            "INSERT INTO workflow_versions "
            "(id, tenant_id, workflow_id, version, plan, connector_bindings) "
            "VALUES (%s,%s,%s,1,%s::jsonb,%s::jsonb)",
            (ver, tenant, wf, json.dumps(plan), binding_json),
        )
        c.execute("UPDATE workflows SET current_version_id=%s WHERE id=%s", (ver, wf))
    return wf, ver


def _seed_schedule(
    owner: str, tenant: uuid.UUID, wf: uuid.UUID, ver: uuid.UUID, creator: uuid.UUID
) -> uuid.UUID:
    sid = uuid.uuid4()
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute(
            "INSERT INTO schedules (id, tenant_id, workflow_id, workflow_version_id, timezone, "
            "frequency, minute, hour, day_of_week, enabled, next_run_at, created_by) "
            "VALUES (%s,%s,%s,%s,'UTC','daily',0,14,NULL,true,%s,%s)",
            (sid, tenant, wf, ver, NOW - timedelta(minutes=1), creator),
        )
    return sid


def _seed_webhook(owner: str, tenant: uuid.UUID) -> uuid.UUID:
    cid = uuid.uuid4()
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute(
            "INSERT INTO connectors (id, tenant_id, type, name, config, status) "
            "VALUES (%s,%s,'webhook','hook','{\"url\":\"https://sink.example/h\"}'::jsonb,'active')",
            (cid, tenant),
        )
    return cid


def _scan(pg_stack: SimpleNamespace, now: datetime = NOW) -> int:
    with _scheduler_sm(pg_stack)() as s, s.begin():
        set_scheduler_context_sync(s, process_signer(Purpose.SCHEDULER_RECONCILE))
        return len(scan_due(s, now, catchup_window_s=3600, batch_limit=50))


def _run_count(owner: str, sid: uuid.UUID) -> int:
    with psycopg.connect(owner) as c:
        row = c.execute(
            "SELECT count(*) FROM workflow_runs WHERE schedule_id=%s", (sid,)
        ).fetchone()
    assert row is not None
    return int(row[0])


def _blocked(owner: str, sid: uuid.UUID) -> str | None:
    with psycopg.connect(owner) as c:
        row = c.execute("SELECT blocked_reason FROM schedules WHERE id=%s", (sid,)).fetchone()
    return row[0] if row else None


def _first_run(owner: str, sid: uuid.UUID) -> uuid.UUID:
    with psycopg.connect(owner) as c:
        row = c.execute(
            "SELECT id FROM workflow_runs WHERE schedule_id=%s LIMIT 1", (sid,)
        ).fetchone()
    assert row is not None
    return uuid.UUID(str(row[0]))


def _remove_membership(owner: str, user_id: uuid.UUID, tenant: uuid.UUID) -> None:
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute("DELETE FROM memberships WHERE user_id=%s AND workspace_id=%s", (user_id, tenant))


def _set_role(owner: str, user_id: uuid.UUID, tenant: uuid.UUID, role: str) -> None:
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute(
            "UPDATE memberships SET role=%s WHERE user_id=%s AND workspace_id=%s",
            (role, user_id, tenant),
        )


def _client(pg_stack: SimpleNamespace) -> TestClient:
    client = TestClient(create_app(pg_stack.settings))
    client.__enter__()
    return client


def _auth(pg_stack: SimpleNamespace, user_id: uuid.UUID, tenant_id: uuid.UUID) -> dict[str, str]:
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT auth_provider_id, email FROM users WHERE id=%s", (user_id,)
        ).fetchone()
    assert row is not None
    sub, email = row
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": "authenticated",
            "exp": int(time.time()) + 300,
            "sub": sub,
            "email": email,
        },
        SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}", "X-Workspace-Id": str(tenant_id)}


def _ok_runner(calls: dict[str, int]) -> Callable[[ActionTask], ActionExecResult]:
    def run(task: ActionTask) -> ActionExecResult:
        calls["n"] += 1
        return run_action(task, transport=httpx.MockTransport(lambda r: httpx.Response(200)))

    return run


# --- 1. active creator -> one occurrence ---------------------------------------------
def test_1_active_creator_creates_one_occurrence(pg_stack: SimpleNamespace) -> None:
    s = _setup(pg_stack)
    wf, ver = _seed_workflow(pg_stack.owner_libpq, s.tenant_id, _PLAN)
    sid = _seed_schedule(pg_stack.owner_libpq, s.tenant_id, wf, ver, s.creator_id)
    assert _scan(pg_stack) == 1
    assert _run_count(pg_stack.owner_libpq, sid) == 1
    assert _blocked(pg_stack.owner_libpq, sid) is None


# --- 2. creator removed -> no occurrence / enqueue -----------------------------------
def test_2_creator_removed_blocks(pg_stack: SimpleNamespace) -> None:
    s = _setup(pg_stack)
    wf, ver = _seed_workflow(pg_stack.owner_libpq, s.tenant_id, _PLAN)
    sid = _seed_schedule(pg_stack.owner_libpq, s.tenant_id, wf, ver, s.creator_id)
    _remove_membership(pg_stack.owner_libpq, s.creator_id, s.tenant_id)
    assert _scan(pg_stack) == 0
    assert _run_count(pg_stack.owner_libpq, sid) == 0
    assert _blocked(pg_stack.owner_libpq, sid) == "CREATOR_NOT_A_MEMBER"


# --- 3. creator demoted below required role -> blocked -------------------------------
def test_3_creator_demoted_blocks(pg_stack: SimpleNamespace) -> None:
    s = _setup(pg_stack)
    wf, ver = _seed_workflow(pg_stack.owner_libpq, s.tenant_id, _PLAN)
    sid = _seed_schedule(pg_stack.owner_libpq, s.tenant_id, wf, ver, s.creator_id)
    _set_role(pg_stack.owner_libpq, s.creator_id, s.tenant_id, "member")
    assert _scan(pg_stack) == 0
    assert _run_count(pg_stack.owner_libpq, sid) == 0
    assert _blocked(pg_stack.owner_libpq, sid) == "CREATOR_ROLE_INSUFFICIENT"


# --- 4. an unrelated member's removal leaves the schedule unaffected -----------------
def test_4_unrelated_member_removed_unaffected(pg_stack: SimpleNamespace) -> None:
    s = _setup(pg_stack)
    other = pg_stack.add_membership(s.tenant_id, "member")
    wf, ver = _seed_workflow(pg_stack.owner_libpq, s.tenant_id, _PLAN)
    sid = _seed_schedule(pg_stack.owner_libpq, s.tenant_id, wf, ver, s.creator_id)
    _remove_membership(pg_stack.owner_libpq, other, s.tenant_id)
    assert _scan(pg_stack) == 1
    assert _run_count(pg_stack.owner_libpq, sid) == 1


# --- 5. reassignment through the explicit path resumes occurrences -------------------
def test_5_reassign_resumes(pg_stack: SimpleNamespace) -> None:
    s = _setup(pg_stack)
    wf, ver = _seed_workflow(pg_stack.owner_libpq, s.tenant_id, _PLAN)
    sid = _seed_schedule(pg_stack.owner_libpq, s.tenant_id, wf, ver, s.creator_id)
    _remove_membership(pg_stack.owner_libpq, s.creator_id, s.tenant_id)
    assert _scan(pg_stack) == 0
    assert _blocked(pg_stack.owner_libpq, sid) == "CREATOR_NOT_A_MEMBER"
    # Explicit remediation: an admin restores the creator's authorization, then
    # unblocks the schedule -> future occurrences resume.
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO memberships (id, user_id, workspace_id, role) VALUES (%s,%s,%s,'admin')",
            (uuid.uuid4(), s.creator_id, s.tenant_id),
        )
    client = _client(pg_stack)
    r = client.post(f"/schedules/{sid}/unblock", headers=_auth(pg_stack, s.owner_id, s.tenant_id))
    assert r.status_code == 200, r.text
    assert r.json()["blocked_reason"] is None
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute(
            "UPDATE schedules SET next_run_at=%s WHERE id=%s", (NOW - timedelta(minutes=1), sid)
        )
    assert _scan(pg_stack) == 1
    assert _run_count(pg_stack.owner_libpq, sid) == 1


# --- 6. a scheduled run with a stale connector binding is safe (no side effect) ------
def test_6_stale_binding_scheduled_run_is_safe(pg_stack: SimpleNamespace) -> None:
    s = _setup(pg_stack)
    cid = _seed_webhook(pg_stack.owner_libpq, s.tenant_id)
    bindings = {"notify": build_binding(str(cid), "webhook", {"url": "https://sink.example/h"})}
    wf, ver = _seed_workflow(pg_stack.owner_libpq, s.tenant_id, _WEBHOOK_PLAN, bindings)
    sid = _seed_schedule(pg_stack.owner_libpq, s.tenant_id, wf, ver, s.creator_id)
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute(
            'UPDATE connectors SET config=\'{"url":"https://evil.example"}\'::jsonb WHERE id=%s',
            (cid,),
        )
    assert _scan(pg_stack) == 1  # authorization is fine; the run is created
    run_id = _first_run(pg_stack.owner_libpq, sid)
    calls = {"n": 0}
    sm = _worker_sm(pg_stack)
    last = "noop"
    for _ in range(8):
        last = process_advance(sm, run_id, lambda *_a: None, None, _ok_runner(calls)).result
        if last in ("failed", "completed", "waiting", "noop"):
            break
    assert last in ("failed", "waiting") and calls["n"] == 0  # never delivered


# --- 7. a strengthened approval requirement is never bypassed ------------------------
def test_7_approval_not_bypassed(pg_stack: SimpleNamespace) -> None:
    s = _setup(pg_stack)
    cid = _seed_webhook(pg_stack.owner_libpq, s.tenant_id)
    bindings = {"notify": build_binding(str(cid), "webhook", {"url": "https://sink.example/h"})}
    wf, ver = _seed_workflow(pg_stack.owner_libpq, s.tenant_id, _WEBHOOK_PLAN, bindings)
    sid = _seed_schedule(pg_stack.owner_libpq, s.tenant_id, wf, ver, s.creator_id)
    assert _scan(pg_stack) == 1
    run_id = _first_run(pg_stack.owner_libpq, sid)
    calls = {"n": 0}
    sm = _worker_sm(pg_stack)
    # webhook.send requires approval: the scheduled run PARKS, it does not auto-send.
    assert (
        process_advance(sm, run_id, lambda *_a: None, None, _ok_runner(calls)).result == "waiting"
    )
    assert calls["n"] == 0


# --- 8. concurrent ticks cannot create work while blocked ----------------------------
def test_8_concurrent_ticks_while_blocked(pg_stack: SimpleNamespace) -> None:
    s = _setup(pg_stack)
    wf, ver = _seed_workflow(pg_stack.owner_libpq, s.tenant_id, _PLAN)
    sid = _seed_schedule(pg_stack.owner_libpq, s.tenant_id, wf, ver, s.creator_id)
    _remove_membership(pg_stack.owner_libpq, s.creator_id, s.tenant_id)
    assert _scan(pg_stack) == 0
    assert _scan(pg_stack) == 0
    assert _run_count(pg_stack.owner_libpq, sid) == 0


# --- 9. cross-tenant reassignment is impossible --------------------------------------
def test_9_cross_tenant_reassign_impossible(pg_stack: SimpleNamespace) -> None:
    a = _setup(pg_stack)
    wf, ver = _seed_workflow(pg_stack.owner_libpq, a.tenant_id, _PLAN)
    sid = _seed_schedule(pg_stack.owner_libpq, a.tenant_id, wf, ver, a.creator_id)
    _remove_membership(pg_stack.owner_libpq, a.creator_id, a.tenant_id)
    assert _scan(pg_stack) == 0
    b = _setup(pg_stack)  # a different tenant's admin/owner
    client = _client(pg_stack)
    r = client.post(f"/schedules/{sid}/unblock", headers=_auth(pg_stack, b.owner_id, b.tenant_id))
    assert r.status_code == 404  # RLS-scoped: invisible cross-tenant
    assert _blocked(pg_stack.owner_libpq, sid) == "CREATOR_NOT_A_MEMBER"


# --- 10. a blocked schedule does not generate unbounded failed-run rows ---------------
def test_10_blocked_no_unbounded_runs(pg_stack: SimpleNamespace) -> None:
    s = _setup(pg_stack)
    wf, ver = _seed_workflow(pg_stack.owner_libpq, s.tenant_id, _PLAN)
    sid = _seed_schedule(pg_stack.owner_libpq, s.tenant_id, wf, ver, s.creator_id)
    _remove_membership(pg_stack.owner_libpq, s.creator_id, s.tenant_id)
    for tick in range(5):
        _scan(pg_stack, NOW + timedelta(days=tick))
    assert _run_count(pg_stack.owner_libpq, sid) == 0


# --- 11. unblock is refused while the creator is STILL unauthorized ------------------
def test_11_unblock_refused_while_creator_still_unauthorized(pg_stack: SimpleNamespace) -> None:
    s = _setup(pg_stack)
    wf, ver = _seed_workflow(pg_stack.owner_libpq, s.tenant_id, _PLAN)
    sid = _seed_schedule(pg_stack.owner_libpq, s.tenant_id, wf, ver, s.creator_id)
    _set_role(pg_stack.owner_libpq, s.creator_id, s.tenant_id, "member")  # demoted
    assert _scan(pg_stack) == 0
    assert _blocked(pg_stack.owner_libpq, sid) == "CREATOR_ROLE_INSUFFICIENT"
    client = _client(pg_stack)
    headers = _auth(pg_stack, s.owner_id, s.tenant_id)
    # A current admin cannot clear the block while the creator remains unauthorized:
    # the endpoint re-validates with the scheduler's checker and refuses (409).
    r = client.post(f"/schedules/{sid}/unblock", headers=headers)
    assert r.status_code == 409, r.text
    assert r.json()["error"]["code"] == "SCHEDULE_CREATOR_UNAUTHORIZED"
    assert _blocked(pg_stack.owner_libpq, sid) == "CREATOR_ROLE_INSUFFICIENT"
    assert _run_count(pg_stack.owner_libpq, sid) == 0
    # Once the creator's role is restored, the same call succeeds.
    _set_role(pg_stack.owner_libpq, s.creator_id, s.tenant_id, "admin")
    r = client.post(f"/schedules/{sid}/unblock", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["blocked_reason"] is None


# --- 12-16. truthful unblock: audited, idempotent, forward-only, atomic ---------------
def _events(owner: str, tenant: uuid.UUID) -> list[tuple[str, str | None, str | None, str | None]]:
    with psycopg.connect(owner) as c:
        rows = c.execute(
            "SELECT event_type, actor_user_id::text, subject_id::text, detail "
            "FROM authz_audit_events WHERE tenant_id=%s AND event_type LIKE 'schedule.%%' "
            "ORDER BY created_at",
            (tenant,),
        ).fetchall()
    return [(r[0], r[1], r[2], r[3]) for r in rows]


def _blocked_at(owner: str, sid: uuid.UUID) -> datetime | None:
    with psycopg.connect(owner) as c:
        row = c.execute("SELECT blocked_at FROM schedules WHERE id=%s", (sid,)).fetchone()
    return row[0] if row else None


def _block(pg_stack: SimpleNamespace) -> tuple[Setup, uuid.UUID]:
    s = _setup(pg_stack)
    wf, ver = _seed_workflow(pg_stack.owner_libpq, s.tenant_id, _PLAN)
    sid = _seed_schedule(pg_stack.owner_libpq, s.tenant_id, wf, ver, s.creator_id)
    _set_role(pg_stack.owner_libpq, s.creator_id, s.tenant_id, "member")
    assert _scan(pg_stack) == 0
    assert _blocked(pg_stack.owner_libpq, sid) == "CREATOR_ROLE_INSUFFICIENT"
    assert _blocked_at(pg_stack.owner_libpq, sid) is not None
    return s, sid


def test_12_successful_unblock_is_audited_in_the_same_transaction(
    pg_stack: SimpleNamespace,
) -> None:
    s, sid = _block(pg_stack)
    _set_role(pg_stack.owner_libpq, s.creator_id, s.tenant_id, "admin")  # authorization restored
    client = _client(pg_stack)
    before = datetime.now(UTC)
    r = client.post(f"/schedules/{sid}/unblock", headers=_auth(pg_stack, s.owner_id, s.tenant_id))
    assert r.status_code == 200, r.text
    body = r.json()
    # The API reports the truthful state: both fields cleared, still enabled.
    assert body["blocked_reason"] is None and body["blocked_at"] is None
    assert body["enabled"] is True
    assert _blocked_at(pg_stack.owner_libpq, sid) is None
    # Forward-only: the next occurrence is strictly in the future (no catch-up).
    assert datetime.fromisoformat(body["next_run_at"]) > before
    # Exactly one append-only event: stable type, actor, subject, prior reason code —
    # nothing else (no emails, no policy internals).
    events = _events(pg_stack.owner_libpq, s.tenant_id)
    assert events == [
        ("schedule.unblocked", str(s.owner_id), str(sid), "CREATOR_ROLE_INSUFFICIENT")
    ]
    # created_by is immutable across the unblock.
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute("SELECT created_by FROM schedules WHERE id=%s", (sid,)).fetchone()
    assert row is not None and uuid.UUID(str(row[0])) == s.creator_id


def test_13_member_cannot_unblock_and_nothing_is_audited(pg_stack: SimpleNamespace) -> None:
    s, sid = _block(pg_stack)
    _set_role(pg_stack.owner_libpq, s.creator_id, s.tenant_id, "admin")
    member = pg_stack.add_membership(s.tenant_id, "member")
    client = _client(pg_stack)
    r = client.post(f"/schedules/{sid}/unblock", headers=_auth(pg_stack, member, s.tenant_id))
    assert r.status_code == 403, r.text
    assert _blocked(pg_stack.owner_libpq, sid) == "CREATOR_ROLE_INSUFFICIENT"
    assert _events(pg_stack.owner_libpq, s.tenant_id) == []


def test_14_refused_unblock_writes_no_audit_event(pg_stack: SimpleNamespace) -> None:
    s, sid = _block(pg_stack)  # creator still demoted
    client = _client(pg_stack)
    r = client.post(f"/schedules/{sid}/unblock", headers=_auth(pg_stack, s.owner_id, s.tenant_id))
    assert r.status_code == 409, r.text
    assert _events(pg_stack.owner_libpq, s.tenant_id) == []
    assert _blocked_at(pg_stack.owner_libpq, sid) is not None


def test_15_unblocking_an_unblocked_schedule_is_a_no_op(pg_stack: SimpleNamespace) -> None:
    """No state transition -> no audit event and no next_run_at churn (idempotent)."""
    s = _setup(pg_stack)
    wf, ver = _seed_workflow(pg_stack.owner_libpq, s.tenant_id, _PLAN)
    sid = _seed_schedule(pg_stack.owner_libpq, s.tenant_id, wf, ver, s.creator_id)
    client = _client(pg_stack)
    headers = _auth(pg_stack, s.owner_id, s.tenant_id)
    before = client.get(f"/schedules/{sid}", headers=headers).json()
    assert before["blocked_reason"] is None
    r = client.post(f"/schedules/{sid}/unblock", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["next_run_at"] == before["next_run_at"]
    assert _events(pg_stack.owner_libpq, s.tenant_id) == []


def test_16_unblock_and_its_audit_event_are_atomic(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the audit write fails, the unblock does not happen either."""
    from sqlalchemy.exc import OperationalError

    from nlw.db.repositories import AuditRepository

    s, sid = _block(pg_stack)
    _set_role(pg_stack.owner_libpq, s.creator_id, s.tenant_id, "admin")

    async def _boom(*_a: object, **_k: object) -> None:
        raise OperationalError("INSERT", {}, Exception("connection lost"))

    monkeypatch.setattr(AuditRepository, "emit", _boom)
    client = TestClient(create_app(pg_stack.settings), raise_server_exceptions=False)
    client.__enter__()
    r = client.post(f"/schedules/{sid}/unblock", headers=_auth(pg_stack, s.owner_id, s.tenant_id))
    assert r.status_code >= 500, r.text
    assert "connection lost" not in r.text
    assert _blocked(pg_stack.owner_libpq, sid) == "CREATOR_ROLE_INSUFFICIENT"  # rolled back
    assert _events(pg_stack.owner_libpq, s.tenant_id) == []


# --- 17-18. concurrent unblock: exactly one transition, exactly one audit event -----
def _synchronized_read(monkeypatch: pytest.MonkeyPatch, parties: int) -> threading.Barrier:
    """Inject a deterministic barrier at the handler's schedule READ so every
    concurrent request has read the row before any of them writes.

    Without a row lock (the reported race) all readers pass the barrier holding the
    same blocked snapshot and each performs the transition. With ``SELECT ... FOR
    UPDATE`` the second read blocks inside PostgreSQL until the first request
    commits, so the lock holder's wait simply times out (a release valve, not the
    proof) and the loser reads the already-cleared row. The correctness assertions
    never depend on timing: only the lock decides who transitions."""
    from nlw.db.repositories import ScheduleRepository

    target = "get_for_update" if hasattr(ScheduleRepository, "get_for_update") else "get"
    real = getattr(ScheduleRepository, target)
    barrier = threading.Barrier(parties)

    async def synced(self: Any, *args: Any, **kwargs: Any) -> Any:
        row = await real(self, *args, **kwargs)
        try:
            barrier.wait(timeout=3)
        except threading.BrokenBarrierError:
            pass
        return row

    monkeypatch.setattr(ScheduleRepository, target, synced)
    return barrier


def _post_unblock(pg_stack: SimpleNamespace, sid: uuid.UUID, headers: dict[str, str]) -> Any:
    with TestClient(create_app(pg_stack.settings), raise_server_exceptions=False) as c:
        return c.post(f"/schedules/{sid}/unblock", headers=headers)


def _run_concurrently(fns: list[Callable[[], Any]]) -> list[Any]:
    results: list[Any] = [None] * len(fns)
    start = threading.Barrier(len(fns))

    def runner(i: int) -> None:
        start.wait()  # all requests are in flight together
        results[i] = fns[i]()

    threads = [threading.Thread(target=runner, args=(i,)) for i in range(len(fns))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert all(not t.is_alive() for t in threads), "a concurrent request never returned"
    return results


def test_17_concurrent_authorized_unblocks_commit_exactly_one_transition(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    s, sid = _block(pg_stack)
    _set_role(pg_stack.owner_libpq, s.creator_id, s.tenant_id, "admin")  # restored
    owner_h = _auth(pg_stack, s.owner_id, s.tenant_id)
    admin_h = _auth(pg_stack, s.creator_id, s.tenant_id)  # a second authorized actor
    _synchronized_read(monkeypatch, parties=2)
    before = datetime.now(UTC)

    ra, rb = _run_concurrently(
        [
            lambda: _post_unblock(pg_stack, sid, owner_h),
            lambda: _post_unblock(pg_stack, sid, admin_h),
        ]
    )
    assert ra.status_code == 200 and rb.status_code == 200, (ra.text, rb.text)
    a, b = ra.json(), rb.json()
    # Both observe the same committed, unblocked state (the loser is a no-op that
    # returns what the winner committed) — one forward next_run_at, no partial state.
    assert a["blocked_reason"] is None and b["blocked_reason"] is None
    assert a["blocked_at"] is None and b["blocked_at"] is None
    assert a["next_run_at"] == b["next_run_at"]
    assert datetime.fromisoformat(a["next_run_at"]) > before
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT blocked_reason, blocked_at, next_run_at, created_by FROM schedules WHERE id=%s",
            (sid,),
        ).fetchone()
    assert row is not None and row[0] is None and row[1] is None
    assert row[2].isoformat() == a["next_run_at"]
    assert uuid.UUID(str(row[3])) == s.creator_id  # created_by untouched
    # EXACTLY one audit event for the one logical transition.
    events = _events(pg_stack.owner_libpq, s.tenant_id)
    assert len(events) == 1, events
    assert events[0][0] == "schedule.unblocked"
    assert events[0][1] in {str(s.owner_id), str(s.creator_id)}
    assert events[0][2] == str(sid) and events[0][3] == "CREATOR_ROLE_INSUFFICIENT"


def test_18_concurrent_unauthorized_unblocks_write_no_audit(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    s, sid = _block(pg_stack)
    _set_role(pg_stack.owner_libpq, s.creator_id, s.tenant_id, "admin")
    m1 = pg_stack.add_membership(s.tenant_id, "member")
    m2 = pg_stack.add_membership(s.tenant_id, "member")
    h1 = _auth(pg_stack, m1, s.tenant_id)
    h2 = _auth(pg_stack, m2, s.tenant_id)
    _synchronized_read(monkeypatch, parties=2)  # never reached: 403 precedes the read

    ra, rb = _run_concurrently(
        [lambda: _post_unblock(pg_stack, sid, h1), lambda: _post_unblock(pg_stack, sid, h2)]
    )
    assert ra.status_code == 403 and rb.status_code == 403
    assert _blocked(pg_stack.owner_libpq, sid) == "CREATOR_ROLE_INSUFFICIENT"
    assert _blocked_at(pg_stack.owner_libpq, sid) is not None
    assert _events(pg_stack.owner_libpq, s.tenant_id) == []
