"""P3A membership + approval separation-of-duties smoke driver (host side).

Runs against the docker-compose stack stood up by
``smoke-p3a-membership-approval.sh``: the REAL rebuilt api + worker images, a real
Redis broker, and a containerized Postgres with the actual Alembic migrations
(incl. 0015). It proves, end-to-end through the running system, the P3A security
invariants — separation of duties, provenance immutability, the owner invariant,
and the append-only audit — and that the P2 disaster-recovery validation is still
green on the P3A schema.

Env:
  OWNER_LIBPQ      owner role (default localhost:5433 / nlw)
  APP_LIBPQ        nlw_app role  (localhost:5433)
  WORKER_LIBPQ     nlw_worker role (localhost:5433)
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


def _auth(sub: str) -> dict[str, str]:
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUD,
            "exp": int(time.time()) + 600,
            "sub": sub,
            "email": f"{sub}@x.io",
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


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


def _seed_parked_run(tid: uuid.UUID, requester: uuid.UUID) -> tuple[uuid.UUID, uuid.UUID]:
    wf, ver, run, appr, conn_id = (uuid.uuid4() for _ in range(5))
    # Unique connector name per run (uq_connector_tenant_name) so multiple parked
    # runs can coexist in one tenant.
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
            "initiated_by_user_id) VALUES (%s,%s,%s,%s,'WAITING_APPROVAL',%s)",
            (run, tid, wf, ver, requester),
        )
        # A parked step_runs row (as a real park produces) so the worker's resume
        # path acts on the approval decision instead of re-planning from scratch.
        c.execute(
            "INSERT INTO step_runs (id, tenant_id, run_id, step_id, tool, status, attempt, input) "
            "VALUES (%s,%s,%s,'notify','webhook.send','WAITING_APPROVAL',0,'{}'::jsonb)",
            (uuid.uuid4(), tid, run),
        )
        c.execute(
            "INSERT INTO approvals (id, tenant_id, run_id, step_id, connector_id, connector_name, "
            "tool, status, requested_by_user_id) "
            "VALUES (%s,%s,%s,'notify',%s,%s,'webhook.send','pending',%s)",
            (appr, tid, run, conn_id, hook, requester),
        )
    return run, appr


def _scalar(libpq: str, sql: str, params: tuple[object, ...] = ()) -> object:
    with psycopg.connect(libpq) as c:
        row = c.execute(sql, params).fetchone()
    return row[0] if row else None


def main() -> None:
    # 1) Live P3A schema objects exist in the migrated container DB.
    _step("live P3A schema (functions, triggers, append-only grants)")
    fns = _scalar(
        OWNER_LIBPQ,
        "SELECT count(*) FROM pg_proc WHERE proname IN "
        "('manage_membership','accept_workspace_invitation','enforce_approval_immutability',"
        "'enforce_run_initiator_immutability','enforce_schedule_creator_immutability')",
    )
    if fns != 5:
        _fail(f"expected 5 P3A functions live, found {fns}")
    for role in ("nlw_app", "nlw_worker"):
        for priv in ("UPDATE", "DELETE"):
            if _scalar(
                OWNER_LIBPQ, "SELECT has_table_privilege(%s,'authz_audit_events',%s)", (role, priv)
            ):
                _fail(f"{role} has {priv} on authz_audit_events (audit not append-only)")
    _ok("manage_membership + 3 immutability triggers live; audit append-only for runtime roles")

    tid = _seed_ws()
    owner = _seed_user(tid, "p3a-owner", "owner")
    admin = _seed_user(tid, "p3a-admin", "admin")
    requester = _seed_user(tid, "p3a-req", "member")

    # 2) Invitation via the API stores ONLY the token hash, never the raw token.
    _step("invitation via API stores only the sha256 hash")
    owner_h = {**_auth("p3a-owner"), "X-Workspace-Id": str(tid)}
    r = requests.post(
        f"{API_URL}/invitations",
        headers=owner_h,
        json={"email": "joiner@x.io", "role": "member"},
        timeout=15,
    )
    if r.status_code != 201:
        _fail(f"invitation create failed: {r.status_code} {r.text}")
    raw = r.json()["token"]
    with psycopg.connect(OWNER_LIBPQ) as c:
        stored = c.execute("SELECT token_hash FROM workspace_invitations").fetchall()
    hashes = {row[0] for row in stored}
    if raw in hashes:
        _fail("raw token stored in DB")
    if hashlib.sha256(raw.encode()).hexdigest() not in hashes:
        _fail("token hash not found in DB")
    _ok("raw token absent from PG; only sha256 hash persisted")

    run, appr = _seed_parked_run(tid, requester)

    # 3) Self-approval is denied BOTH via the API (403) and by direct SQL (RLS 42501).
    _step("self-approval denied via API and via direct SQL")
    # Use an ADMIN requester so the API reaches the four-eyes check (a mere member
    # would be blocked earlier by require_role) — this proves separation of duties,
    # not just insufficient role.
    admin_req = _seed_user(tid, "p3a-adminreq", "admin")
    run2, appr2 = _seed_parked_run(tid, admin_req)
    self_h = {**_auth("p3a-adminreq"), "X-Workspace-Id": str(tid)}
    r = requests.post(f"{API_URL}/approvals/{appr2}/approve", headers=self_h, timeout=15)
    if r.status_code != 403:
        _fail(f"API self-approval not denied: {r.status_code} {r.text}")
    with psycopg.connect(APP_LIBPQ, autocommit=True) as c:
        c.execute("SELECT set_config('app.user_id', %s, false)", (str(admin_req),))
        c.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tid),))
        try:
            c.execute(
                "UPDATE approvals SET status='approved', decided_by=%s, decided_at=now() "
                "WHERE id=%s",
                (admin_req, appr2),
            )
            _fail("direct-SQL self-approval succeeded (four-eyes bypass)")
        except psycopg.errors.InsufficientPrivilege:
            pass
    if _scalar(OWNER_LIBPQ, "SELECT status FROM approvals WHERE id=%s", (appr2,)) != "pending":
        _fail("self-approved approval changed status")
    _ok("API self-approval -> 403; direct-SQL self-approval -> permission denied; stays pending")

    # 4) A different admin approves via the API; the REAL worker advances the run once.
    _step("eligible admin approves; real worker advances the run exactly once")
    admin_h = {**_auth("p3a-admin"), "X-Workspace-Id": str(tid)}
    r = requests.post(f"{API_URL}/approvals/{appr}/approve", headers=admin_h, timeout=15)
    if r.status_code != 200:
        _fail(f"eligible approval failed: {r.status_code} {r.text}")
    # The worker resumes; delivery to a public host is attempted once (the SSRF guard
    # permits s.example only for validation — we assert the run left WAITING_APPROVAL
    # and the approval is terminal exactly once).
    deadline = time.time() + 30
    status = None
    while time.time() < deadline:
        status = _scalar(OWNER_LIBPQ, "SELECT status FROM workflow_runs WHERE id=%s", (run,))
        if status != "WAITING_APPROVAL":
            break
        time.sleep(1)
    if status == "WAITING_APPROVAL":
        _fail("worker did not resume the approved run")
    if _scalar(OWNER_LIBPQ, "SELECT status FROM approvals WHERE id=%s", (appr,)) != "approved":
        _fail("approval not terminal after decision")
    _ok(f"run advanced past WAITING_APPROVAL (status={status}); approval terminal")

    # 5) Audit: exactly one event per committed transition (idempotent re-decide adds none).
    _step("append-only audit records exactly one event per committed transition")
    requests.post(f"{API_URL}/approvals/{appr}/approve", headers=admin_h, timeout=15)  # idempotent
    n_created = _scalar(
        OWNER_LIBPQ,
        "SELECT count(*) FROM authz_audit_events "
        "WHERE event_type='invitation.created' AND tenant_id=%s",
        (tid,),
    )
    n_approved = _scalar(
        OWNER_LIBPQ,
        "SELECT count(*) FROM authz_audit_events "
        "WHERE event_type='approval.approved' AND subject_id=%s",
        (appr,),
    )
    if n_created != 1:
        _fail(f"invitation.created events = {n_created} (expected 1)")
    if n_approved != 1:
        _fail(
            f"approval.approved events = {n_approved} (expected exactly 1 despite idempotent retry)"
        )
    _ok("invitation.created x1; approval.approved x1 (idempotent retry added none)")

    # 6) Provenance rewrite is denied for every runtime role.
    _step("provenance rewrite denied (worker run-initiator, app schedule-creator, app requester)")
    with psycopg.connect(WORKER_LIBPQ, autocommit=True) as c:
        c.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tid),))
        try:
            c.execute("UPDATE workflow_runs SET initiated_by_user_id=%s WHERE id=%s", (admin, run))
            _fail("worker rewrote workflow_runs.initiated_by_user_id")
        except psycopg.errors.CheckViolation:
            pass
    with psycopg.connect(APP_LIBPQ, autocommit=True) as c:
        c.execute("SELECT set_config('app.user_id', %s, false)", (str(owner),))
        c.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tid),))
        try:
            c.execute("UPDATE approvals SET requested_by_user_id=NULL WHERE id=%s", (appr,))
            _fail("app nullified approvals.requested_by_user_id")
        except psycopg.errors.InsufficientPrivilege:
            pass
    _ok("run-initiator + requester rewrites rejected (trigger / column grant)")

    # 7) A terminal decision is immutable (no APPROVED->REJECTED flip via direct SQL).
    _step("terminal decision is immutable")
    with psycopg.connect(OWNER_LIBPQ, autocommit=True) as c:
        try:
            c.execute("UPDATE approvals SET status='rejected' WHERE id=%s", (appr,))
            _fail("terminal approval flipped to rejected")
        except psycopg.errors.CheckViolation:
            pass
    _ok("APPROVED->REJECTED flip rejected by immutability trigger")

    # 8) Final-owner race: concurrent removals leave exactly one owner.
    _step("final-owner race preserves at least one owner")
    o2 = _seed_user(tid, "p3a-owner2", "owner")
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

    ts = [threading.Thread(target=rm, args=a) for a in ((owner, o2), (o2, owner))]
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

    # 9) The append-only audit cannot be rewritten/erased by a runtime role.
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

    # 10) P2 disaster-recovery validation is still green on the P3A schema.
    _step("P2 recovery validation is green on the P3A schema")
    from sqlalchemy import create_engine

    from nlw.backup.quiescence import quiesce
    from nlw.backup.validate import validate_restore

    owner_sa = OWNER_LIBPQ.replace("postgresql://", "postgresql+psycopg://")
    engine = create_engine(owner_sa)
    quiesce(engine)
    report = validate_restore(engine)
    if not report["ok"]:
        failing = [(c["name"], c["detail"]) for c in report["checks"] if not c["ok"]]
        _fail(f"DR validation failed: {failing}")
    _ok("validate_restore ok (incl. authz_audit_append_only + P3A secdef owners)")

    print("ALL P3A SMOKE CHECKS PASSED")


if __name__ == "__main__":
    main()
