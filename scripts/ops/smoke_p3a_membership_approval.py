"""P3A membership + approval separation-of-duties smoke driver (host side).

Runs against the docker-compose stack stood up by
``smoke-p3a-membership-approval.sh``: the REAL rebuilt api + worker images, a real
Redis broker, and a containerized Postgres with the actual Alembic migrations
(incl. 0015). It proves, end-to-end through the running system, the P3A security
invariants — separation of duties, provenance immutability, the owner invariant,
the dedicated membership-admin owner, and the append-only audit (with one event per
committed transition) — and that the P2 disaster-recovery validation is still green
on the P3A schema.

The approval flow here uses the REAL park path: a PENDING run is enqueued and the
containerized worker parks it (emitting approval.requested) before a genuine
four-eyes decision. (Some negative/DB-level steps seed rows directly; that is fine
because the real park path is also covered by the integration suite.)

Env:
  OWNER_LIBPQ / APP_LIBPQ / WORKER_LIBPQ  role libpq URLs (localhost:5433)
  REDIS_URL        broker the host uses to enqueue (default localhost:6379)
  API_URL          base URL of the api service (default http://localhost:8000)
  SMOKE_JWT_SECRET HS256 secret the api verifies (matches compose SUPABASE_JWT_SECRET)
  SMOKE_ISSUER     JWT issuer (matches api's derived Supabase issuer)
"""

from __future__ import annotations

import hashlib
import os
import sys
import threading
import time
import uuid

import jwt
import psycopg
import requests

OWNER_LIBPQ = os.environ.get("OWNER_LIBPQ", "postgresql://nlw:nlw@localhost:5433/nlw")
APP_LIBPQ = os.environ.get("APP_LIBPQ", "postgresql://nlw_app:nlw_app@localhost:5433/nlw")
WORKER_LIBPQ = os.environ.get(
    "WORKER_LIBPQ", "postgresql://nlw_worker:nlw_worker@localhost:5433/nlw"
)
API_URL = os.environ.get("API_URL", "http://localhost:8000")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
JWT_SECRET = os.environ.get("SMOKE_JWT_SECRET", "dev-secret-for-tests-32bytes-min-length")
ISSUER = os.environ.get("SMOKE_ISSUER", "https://proj.supabase.co/auth/v1")
AUD = "authenticated"

_n = 0


def _ok(msg: str) -> None:
    print(f"  [ok] {msg}")


def _fail(msg: str) -> None:
    print(f"SMOKE FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def _step(title: str) -> None:
    global _n
    _n += 1
    print(f"--- step {_n}: {title} ---")


def _auth(sub: str, email: str | None = None) -> dict[str, str]:
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUD,
            "exp": int(time.time()) + 600,
            "sub": sub,
            "email": email or f"{sub}@x.io",
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def _enqueue(run_id: uuid.UUID) -> None:
    os.environ["REDIS_URL"] = REDIS_URL
    os.environ.setdefault("NLW_REDIS_URL", REDIS_URL)
    from nlw.worker.actors import advance_run

    advance_run.send(str(run_id))


def _seed_ws() -> uuid.UUID:
    tid = uuid.uuid4()
    with psycopg.connect(OWNER_LIBPQ, autocommit=True) as c:
        c.execute("INSERT INTO workspaces (id, name, slug) VALUES (%s,'ws',%s)", (tid, f"w-{tid}"))
    return tid


def _seed_user(tid: uuid.UUID, sub: str, role: str) -> uuid.UUID:
    uid = uuid.uuid4()
    with psycopg.connect(OWNER_LIBPQ, autocommit=True) as c:
        c.execute(
            "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s)",
            (uid, sub, f"{sub}@x.io"),
        )
        c.execute(
            "INSERT INTO memberships (id, user_id, workspace_id, role) VALUES (%s,%s,%s,%s)",
            (uuid.uuid4(), uid, tid, role),
        )
    return uid


def _seed_action_run(tid: uuid.UUID, requester: uuid.UUID) -> uuid.UUID:
    """A PENDING run with a webhook.send (approval-gated) step, NO step_runs and NO
    approval — so the real worker parks it and emits approval.requested."""
    wf, ver, run, conn_id = (uuid.uuid4() for _ in range(4))
    hook = f"hook-{conn_id.hex[:8]}"
    plan = '{"steps":[{"id":"notify","tool":"webhook.send","args":{},"connector":"' + hook + '"}]}'
    with psycopg.connect(OWNER_LIBPQ, autocommit=True) as c:
        c.execute(
            "INSERT INTO connectors (id, tenant_id, type, name, config, secret_ref, status) "
            "VALUES (%s,%s,'webhook',%s,'{\"url\":\"https://s.example/h\"}'::jsonb,NULL,'active')",
            (conn_id, tid, hook),
        )
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,%s)", (wf, tid, hook))
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,%s::jsonb)",
            (ver, tid, wf, plan),
        )
        c.execute(
            "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status, "
            "initiated_by_user_id) VALUES (%s,%s,%s,%s,'PENDING',%s)",
            (run, tid, wf, ver, requester),
        )
    return run


def _scalar(libpq: str, sql: str, params: tuple[object, ...] = ()) -> object:
    with psycopg.connect(libpq) as c:
        row = c.execute(sql, params).fetchone()
    return row[0] if row else None


def _wait(libpq: str, sql: str, params: tuple[object, ...], want: object, secs: int = 30) -> object:
    deadline = time.time() + secs
    val = None
    while time.time() < deadline:
        val = _scalar(libpq, sql, params)
        if val == want:
            return val
        time.sleep(1)
    return val


def main() -> None:
    # 1) Live P3A schema + the dedicated manage_membership owner.
    _step("live P3A schema; manage_membership owned by nlw_membership_admin")
    fns = _scalar(
        OWNER_LIBPQ,
        "SELECT count(*) FROM pg_proc WHERE proname IN "
        "('manage_membership','accept_workspace_invitation','enforce_approval_immutability',"
        "'enforce_run_initiator_immutability','enforce_schedule_creator_immutability')",
    )
    if fns != 5:
        _fail(f"expected 5 P3A functions live, found {fns}")
    owner = _scalar(
        OWNER_LIBPQ,
        "SELECT r.rolname FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner "
        "WHERE p.proname='manage_membership'",
    )
    if owner != "nlw_membership_admin":
        _fail(f"manage_membership owner is {owner!r}, expected nlw_membership_admin")
    # The owner's blast radius: memberships DML + audit INSERT, nothing sensitive.
    leaks = [
        f"{t}:{p}"
        for t in ("users", "workspaces", "connectors", "dr_restore_events", "approvals")
        for p in ("SELECT", "INSERT", "UPDATE", "DELETE")
        if _scalar(OWNER_LIBPQ, "SELECT has_table_privilege('nlw_membership_admin',%s,%s)", (t, p))
    ]
    if leaks:
        _fail(f"nlw_membership_admin has unexpected access: {leaks}")
    for role in ("nlw_app", "nlw_worker"):
        for priv in ("UPDATE", "DELETE"):
            if _scalar(
                OWNER_LIBPQ, "SELECT has_table_privilege(%s,'authz_audit_events',%s)", (role, priv)
            ):
                _fail(f"{role} has {priv} on authz_audit_events (audit not append-only)")
    _ok("5 P3A functions live; manage_membership owner narrow; audit append-only")

    tid = _seed_ws()
    _owner_u = _seed_user(tid, "p3a-owner", "owner")
    admin = _seed_user(tid, "p3a-admin", "admin")

    # 2) Invitation via the API stores ONLY the token hash + one invitation.created.
    _step("invitation via API: hash only + invitation.created audit")
    owner_h = {**_auth("p3a-owner"), "X-Workspace-Id": str(tid)}
    r = requests.post(
        f"{API_URL}/invitations",
        headers=owner_h,
        json={"email": "invited@x.io", "role": "admin"},
        timeout=15,
    )
    if r.status_code != 201:
        _fail(f"invitation create failed: {r.status_code} {r.text}")
    raw = r.json()["token"]
    with psycopg.connect(OWNER_LIBPQ) as c:
        hashes = {row[0] for row in c.execute("SELECT token_hash FROM workspace_invitations")}
    if raw in hashes or hashlib.sha256(raw.encode()).hexdigest() not in hashes:
        _fail("raw token stored, or hash missing, in PG")
    n_created = _scalar(
        OWNER_LIBPQ,
        "SELECT count(*) FROM authz_audit_events WHERE event_type='invitation.created' "
        "AND tenant_id=%s",
        (tid,),
    )
    if n_created != 1:
        _fail(f"invitation.created events = {n_created} (expected 1)")
    _ok("raw token absent; only sha256 hash persisted; invitation.created x1")

    # 3) A genuinely different user accepts -> invitation.accepted + membership.added.
    _step("second user accepts: invitation.accepted + membership.added audit")
    invited_h = _auth("p3a-invited", email="invited@x.io")
    r = requests.post(
        f"{API_URL}/invitations/accept", headers=invited_h, json={"token": raw}, timeout=15
    )
    if r.status_code != 200:
        _fail(f"accept failed: {r.status_code} {r.text}")
    invited_uid = _scalar(OWNER_LIBPQ, "SELECT id FROM users WHERE auth_provider_id='p3a-invited'")
    is_member = _scalar(
        OWNER_LIBPQ,
        "SELECT role FROM memberships WHERE workspace_id=%s AND user_id=%s",
        (tid, invited_uid),
    )
    if is_member != "admin":
        _fail(f"invited user role is {is_member!r}, expected admin")
    accepted = _scalar(
        OWNER_LIBPQ,
        "SELECT count(*) FROM authz_audit_events WHERE event_type='invitation.accepted' "
        "AND tenant_id=%s",
        (tid,),
    )
    added = _scalar(
        OWNER_LIBPQ,
        "SELECT count(*) FROM authz_audit_events WHERE event_type='membership.added' "
        "AND tenant_id=%s",
        (tid,),
    )
    if accepted != 1 or added != 1:
        _fail(f"expected invitation.accepted x1 + membership.added x1, got {accepted}/{added}")
    _ok("invited user joined as admin; invitation.accepted x1 + membership.added x1")

    # 4) REAL park: the worker parks a PENDING run and emits approval.requested.
    _step("real worker parks a run and emits approval.requested")
    requester = _seed_user(tid, "p3a-req", "admin")  # admin so the API reaches four-eyes
    run = _seed_action_run(tid, requester)
    _enqueue(run)
    status = _wait(
        OWNER_LIBPQ, "SELECT status FROM workflow_runs WHERE id=%s", (run,), "WAITING_APPROVAL"
    )
    if status != "WAITING_APPROVAL":
        _fail(f"worker did not park the run (status={status})")
    appr = _scalar(OWNER_LIBPQ, "SELECT id FROM approvals WHERE run_id=%s", (run,))
    requested = _scalar(
        OWNER_LIBPQ,
        "SELECT count(*) FROM authz_audit_events WHERE event_type='approval.requested' "
        "AND subject_id=%s",
        (appr,),
    )
    if requested != 1:
        _fail(f"approval.requested events = {requested} (expected 1)")
    _ok("run parked at WAITING_APPROVAL; approval.requested x1")

    # 5) Self-approval denied via the API (403) and by direct SQL (RLS 42501).
    _step("self-approval denied via API and via direct SQL")
    self_h = {**_auth("p3a-req"), "X-Workspace-Id": str(tid)}
    r = requests.post(f"{API_URL}/approvals/{appr}/approve", headers=self_h, timeout=15)
    if r.status_code != 403:
        _fail(f"API self-approval not denied: {r.status_code} {r.text}")
    with psycopg.connect(APP_LIBPQ, autocommit=True) as c:
        c.execute("SELECT set_config('app.user_id', %s, false)", (str(requester),))
        c.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tid),))
        try:
            c.execute(
                "UPDATE approvals SET status='approved', decided_by=%s, decided_at=now() "
                "WHERE id=%s",
                (requester, appr),
            )
            _fail("direct-SQL self-approval succeeded (four-eyes bypass)")
        except psycopg.errors.InsufficientPrivilege:
            pass
    if _scalar(OWNER_LIBPQ, "SELECT status FROM approvals WHERE id=%s", (appr,)) != "pending":
        _fail("self-approved approval changed status")
    _ok("API self-approval -> 403; direct-SQL self-approval -> denied; stays pending")

    # 6) A different admin approves; the worker advances once; audit is not duplicated.
    _step("eligible admin approves; worker advances once; approval.approved x1 (no dup on replay)")
    admin_h = {**_auth("p3a-admin"), "X-Workspace-Id": str(tid)}
    r = requests.post(f"{API_URL}/approvals/{appr}/approve", headers=admin_h, timeout=15)
    if r.status_code != 200:
        _fail(f"eligible approval failed: {r.status_code} {r.text}")
    status = _wait(OWNER_LIBPQ, "SELECT status FROM workflow_runs WHERE id=%s", (run,), "RUNNING")
    if status == "WAITING_APPROVAL":
        _fail("worker did not resume the approved run")
    requests.post(f"{API_URL}/approvals/{appr}/approve", headers=admin_h, timeout=15)  # replay
    approved = _scalar(
        OWNER_LIBPQ,
        "SELECT count(*) FROM authz_audit_events WHERE event_type='approval.approved' "
        "AND subject_id=%s",
        (appr,),
    )
    if approved != 1:
        _fail(f"approval.approved events = {approved} (expected exactly 1 despite replay)")
    _ok(f"run advanced past WAITING_APPROVAL (status={status}); approval.approved x1")

    # 7) Provenance rewrite denied for runtime roles.
    _step("provenance rewrite denied (worker run-initiator, app requester)")
    with psycopg.connect(WORKER_LIBPQ, autocommit=True) as c:
        c.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tid),))
        try:
            c.execute("UPDATE workflow_runs SET initiated_by_user_id=%s WHERE id=%s", (admin, run))
            _fail("worker rewrote workflow_runs.initiated_by_user_id")
        except psycopg.errors.CheckViolation:
            pass
    with psycopg.connect(APP_LIBPQ, autocommit=True) as c:
        c.execute("SELECT set_config('app.user_id', %s, false)", (str(admin),))
        c.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tid),))
        try:
            c.execute("UPDATE approvals SET requested_by_user_id=NULL WHERE id=%s", (appr,))
            _fail("app nullified approvals.requested_by_user_id")
        except psycopg.errors.InsufficientPrivilege:
            pass
    _ok("run-initiator + requester rewrites rejected (trigger / column grant)")

    # 8) A terminal decision is immutable.
    _step("terminal decision is immutable")
    with psycopg.connect(OWNER_LIBPQ, autocommit=True) as c:
        try:
            c.execute("UPDATE approvals SET status='rejected' WHERE id=%s", (appr,))
            _fail("terminal approval flipped to rejected")
        except psycopg.errors.CheckViolation:
            pass
    _ok("APPROVED->REJECTED flip rejected by immutability trigger")

    # 9) Final-owner race: concurrent removals leave exactly one owner (function-only).
    _step("final-owner deterministic race preserves at least one owner")
    o1 = _seed_user(tid, "p3a-owner-a", "owner")
    o2 = _seed_user(tid, "p3a-owner-b", "owner")
    results: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(2)

    def rm(actor: uuid.UUID, target: uuid.UUID) -> None:
        with psycopg.connect(APP_LIBPQ, autocommit=False) as conn:
            conn.execute("SELECT set_config('app.user_id', %s, false)", (str(actor),))
            conn.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tid),))
            barrier.wait()
            try:
                conn.execute("SELECT manage_membership(%s,%s,'remove',NULL)", (tid, target))
                conn.commit()
                out = "ok"
            except Exception:
                conn.rollback()
                out = "fail"
        with lock:
            results.append(out)

    ts = [threading.Thread(target=rm, args=a) for a in ((o1, o2), (o2, o1))]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    if "fail" not in results:
        _fail(f"both owner removals succeeded: {results}")
    remaining = _scalar(
        OWNER_LIBPQ,
        "SELECT count(*) FROM memberships WHERE workspace_id=%s AND role='owner'",
        (tid,),
    )
    if int(remaining) < 1:  # type: ignore[arg-type]
        _fail("workspace left with zero owners")
    _ok(f"concurrent removals -> {sorted(results)}; owners remaining = {remaining}")

    # 10) The append-only audit cannot be rewritten/erased by a runtime role.
    _step("audit trail cannot be tampered by nlw_app")
    with psycopg.connect(APP_LIBPQ, autocommit=True) as c:
        c.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tid),))
        for sql in (
            "UPDATE authz_audit_events SET event_type='x' WHERE tenant_id=%s",
            "DELETE FROM authz_audit_events WHERE tenant_id=%s",
        ):
            try:
                c.execute(sql, (tid,))
                _fail(f"audit tamper succeeded: {sql}")
            except psycopg.errors.InsufficientPrivilege:
                pass
    _ok("nlw_app UPDATE/DELETE on authz_audit_events -> permission denied")

    # 11) P2 disaster-recovery validation is still green on the P3A schema.
    _step("P2 recovery validation is green on the P3A schema")
    from sqlalchemy import create_engine

    from nlw.backup.quiescence import quiesce
    from nlw.backup.validate import validate_restore

    engine = create_engine(OWNER_LIBPQ.replace("postgresql://", "postgresql+psycopg://"))
    quiesce(engine)
    report = validate_restore(engine)
    if not report["ok"]:
        failing = [(c["name"], c["detail"]) for c in report["checks"] if not c["ok"]]
        _fail(f"DR validation failed: {failing}")
    _ok("validate_restore ok (incl. P3A membership/invitation/provenance checks)")

    print("ALL P3A SMOKE CHECKS PASSED")


if __name__ == "__main__":
    main()
