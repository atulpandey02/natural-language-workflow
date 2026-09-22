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
import secrets
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import jwt
import psycopg
import requests

from nlw.tenancy.keys import signer_from_material
from nlw.tenancy.signing import Purpose, SignedContext

OWNER_LIBPQ = os.environ.get("OWNER_LIBPQ", "postgresql://nlw:nlw@localhost:5433/nlw")
APP_LIBPQ = os.environ.get("APP_LIBPQ", "postgresql://nlw_app:nlw_app@localhost:5433/nlw")
WORKER_LIBPQ = os.environ.get(
    "WORKER_LIBPQ", "postgresql://nlw_worker:nlw_worker@localhost:5433/nlw"
)
API_URL = os.environ.get("API_URL", "http://localhost:8000")
# Signed DB context (P3B): the host-side driver signs its direct-SQL probes with
# the SAME dev keys the containers hold (docker/ctx-keys, provisioned by
# scripts/ops/ctx-keys-dev.sh). Purpose/role are fixed per class.
_KEYS_DIR = os.environ.get("NLW_CTX_KEYS_DIR", "docker/ctx-keys")


_CLASS_OF = {
    "api_identity": "api",
    "api_request": "api",
    "worker_execution": "worker",
    "scheduler_reconcile": "scheduler",
}
_DEFAULT_IDS = {"api": "dev-api", "worker": "dev-worker", "scheduler": "dev-scheduler"}


def _key(cls: str) -> tuple[str, str]:
    """(key id, hex material) of a runtime class's CURRENT dev key file."""
    key_id = os.environ.get(f"NLW_CTX_{cls.upper()}_KEY_ID", _DEFAULT_IDS[cls])
    return key_id, Path(_KEYS_DIR, f"{cls}.key").read_text(encoding="ascii").strip()


def _signer(purpose: Purpose, cls: str | None = None) -> object:
    """A signer for ``purpose``. ``cls`` (default: the purpose's own class) lets the
    negative probes deliberately sign with ANOTHER class's key material."""
    key_id, key_hex = _key(cls or _CLASS_OF[str(purpose)])
    return signer_from_material(purpose, key_id, key_hex)


def _apply(conn: psycopg.Connection, ctx: SignedContext) -> None:
    for name, value in ctx.as_gucs().items():
        conn.execute("SELECT set_config(%s, %s, true)", (name, value))


def _as_api(conn: psycopg.Connection, user: uuid.UUID, tenant: uuid.UUID) -> None:
    _apply(conn, _signer(Purpose.API_REQUEST).sign(user_id=user, tenant_id=tenant))  # type: ignore[attr-defined]


def _as_worker(conn: psycopg.Connection, tenant: uuid.UUID, run: uuid.UUID) -> None:
    _apply(conn, _signer(Purpose.WORKER_EXECUTION).sign(tenant_id=tenant, run_id=run))  # type: ignore[attr-defined]


SCHED_LIBPQ = os.environ.get(
    "SCHED_LIBPQ", "postgresql://nlw_scheduler:nlw_scheduler@localhost:5433/nlw"
)
_COMPOSE = ["docker", "compose", "-f", "docker-compose.yml"]
_ECHO_PLAN = '{"steps":[{"id":"a","tool":"fake.echo","args":{"hello":"smoke"}}]}'


def _compose(*args: str, **env: str) -> subprocess.CompletedProcess[str]:
    """Run a Compose command the way the smoke shell does (same env + overrides)."""
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [*_COMPOSE, *args],
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        check=False,
    )


def _count_as(libpq: str, ctx: SignedContext, sql: str, params: tuple[object, ...] = ()) -> int:
    """Row count visible to a signed (or deliberately mis-signed) context."""
    with psycopg.connect(libpq, autocommit=False) as c:
        _apply(c, ctx)
        row = c.execute(sql, params).fetchone()
        c.rollback()
    return int(row[0]) if row else 0


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
    with psycopg.connect(APP_LIBPQ, autocommit=False) as c:
        _as_api(c, requester, tid)  # SIGNED api_request context for the requester
        try:
            c.execute(
                "UPDATE approvals SET status='approved', decided_by=%s, decided_at=now() "
                "WHERE id=%s",
                (requester, appr),
            )
            _fail("direct-SQL self-approval succeeded (four-eyes bypass)")
        except psycopg.errors.InsufficientPrivilege:
            c.rollback()
    # And an UNSIGNED forgery of the same context grants nothing at all: it can
    # neither SEE the approval nor MODIFY it (the UPDATE matches zero rows).
    with psycopg.connect(APP_LIBPQ, autocommit=False) as c:
        c.execute("SELECT set_config('app.user_id', %s, true)", (str(admin),))
        c.execute("SELECT set_config('app.tenant_id', %s, true)", (str(tid),))
        seen = c.execute("SELECT count(*) FROM approvals WHERE id=%s", (appr,)).fetchone()
        cur = c.execute(
            "UPDATE approvals SET status='approved', decided_by=%s, decided_at=now() WHERE id=%s",
            (admin, appr),
        )
        touched = cur.rowcount
        c.rollback()
    if seen is None or seen[0] != 0:
        _fail("unsigned forged context could see tenant data")
    if touched != 0:
        _fail(f"unsigned forged context modified {touched} row(s)")
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
    with psycopg.connect(WORKER_LIBPQ, autocommit=False) as c:
        _as_worker(c, tid, run)  # SIGNED worker_execution context, bound to this run
        try:
            c.execute("UPDATE workflow_runs SET initiated_by_user_id=%s WHERE id=%s", (admin, run))
            _fail("worker rewrote workflow_runs.initiated_by_user_id")
        except psycopg.errors.CheckViolation:
            c.rollback()
    with psycopg.connect(APP_LIBPQ, autocommit=False) as c:
        _as_api(c, admin, tid)
        try:
            c.execute("UPDATE approvals SET requested_by_user_id=NULL WHERE id=%s", (appr,))
            _fail("app nullified approvals.requested_by_user_id")
        except psycopg.errors.InsufficientPrivilege:
            c.rollback()
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
            _as_api(conn, actor, tid)  # SIGNED, transaction-local
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

    # 11) P2 disaster-recovery validation is still green on this schema (read-only
    #     here; the quiescence + recovery-lock proof runs LAST, in step 17, because
    #     quiescing records a restore generation that locks the database).
    _step("P2 recovery validation is green on the P3B schema")
    from sqlalchemy import create_engine

    from nlw.backup.validate import validate_restore

    engine = create_engine(OWNER_LIBPQ.replace("postgresql://", "postgresql+psycopg://"))
    # Four checks describe POST-QUIESCENCE state and can only pass after step 17's
    # quiesce; every schema/role/policy/helper check must already be green here.
    _quiesce_only = {
        "non_terminal_runs_quiesced",
        "no_pending_external_actions",
        "dr_restore_event_recorded",
        "schedules_after_recovery_cutoff",
    }
    report = validate_restore(engine)
    failing = [
        (c["name"], c["detail"])
        for c in report["checks"]
        if not c["ok"] and c["name"] not in _quiesce_only
    ]
    if failing:
        _fail(f"DR validation failed: {failing}")
    names = {c["name"] for c in report["checks"]}
    for want in (
        "pgcrypto_present",
        "ctx_keys_registry_protected",
        "ctx_verifier_functions_hardened",
        "no_policy_trusts_unsigned_context",
    ):
        if want not in names:
            _fail(f"validate_restore lacks the P3B check {want!r}")
    _ok("validate_restore ok (incl. P3A membership + P3B signed-context checks)")

    # ---- P3B signed-context steps (section R 12-17) ----------------------------

    # 12) The REAL scheduler creates a due run under scheduler_reconcile context and
    #     the REAL worker executes it under worker_execution context.
    _step("real scheduler creates a due run (scheduler ctx); real worker completes it (worker ctx)")
    wf, ver, sid = (uuid.uuid4() for _ in range(3))
    with psycopg.connect(OWNER_LIBPQ, autocommit=True) as c:
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'sched')", (wf, tid))
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,%s::jsonb)",
            (ver, tid, wf, _ECHO_PLAN),
        )
        # The due occurrence is derived from the recurrence (latest hh:mm <= now), so
        # pin hh:mm to the CURRENT UTC minute: that occurrence is seconds old and
        # inside the catch-up window; a stale 09:00 would be skipped by design.
        now_utc = datetime.now(UTC)
        c.execute(
            "INSERT INTO schedules (id, tenant_id, workflow_id, workflow_version_id, timezone, "
            "frequency, minute, hour, enabled, next_run_at, created_by) "
            "VALUES (%s,%s,%s,%s,'UTC','daily',%s,%s,true,%s,%s)",
            (sid, tid, wf, ver, now_utc.minute, now_utc.hour, now_utc, admin),
        )
    # A bare (unsigned) scheduler session cannot even see the due schedule.
    with psycopg.connect(SCHED_LIBPQ) as c:
        bare = c.execute("SELECT count(*) FROM schedules WHERE id=%s", (sid,)).fetchone()
    if bare is None or bare[0] != 0:
        _fail("unsigned scheduler session could enumerate schedules")
    sched_run = _wait(
        OWNER_LIBPQ,
        "SELECT status FROM workflow_runs WHERE schedule_id=%s AND status='COMPLETED'",
        (sid,),
        "COMPLETED",
        secs=120,  # scan cadence is 30s; the worker then runs one inline step
    )
    if sched_run != "COMPLETED":
        _fail(f"scheduled run not created/completed by the real scheduler+worker ({sched_run})")
    n_runs = _scalar(OWNER_LIBPQ, "SELECT count(*) FROM workflow_runs WHERE schedule_id=%s", (sid,))
    if n_runs != 1:
        _fail(f"scheduler created {n_runs} runs for one occurrence (expected 1)")
    _ok("unsigned scheduler sees nothing; signed scheduler created 1 run; worker COMPLETED it")

    # 13) The API key cannot be used under the worker/scheduler DB roles (purpose ↔
    #     login role AND key class ↔ purpose are both enforced).
    _step("API key cannot authorize under worker/scheduler DB roles")
    api_ctx = _signer(Purpose.API_REQUEST).sign(user_id=admin, tenant_id=tid)  # type: ignore[attr-defined]
    for libpq, role in ((WORKER_LIBPQ, "nlw_worker"), (SCHED_LIBPQ, "nlw_scheduler")):
        if _count_as(
            libpq, api_ctx, "SELECT count(*) FROM workflow_runs WHERE tenant_id=%s", (tid,)
        ):
            _fail(f"api_request context accepted under {role}")
    # api MATERIAL signing a worker/scheduler-purpose context (class mismatch).
    w_with_api = _signer(Purpose.WORKER_EXECUTION, cls="api").sign(tenant_id=tid, run_id=run)  # type: ignore[attr-defined]
    if _count_as(
        WORKER_LIBPQ, w_with_api, "SELECT count(*) FROM workflow_runs WHERE id=%s", (run,)
    ):
        _fail("worker_execution context signed with the API key was accepted")
    s_with_api = _signer(Purpose.SCHEDULER_RECONCILE, cls="api").sign()  # type: ignore[attr-defined]
    if _count_as(SCHED_LIBPQ, s_with_api, "SELECT count(*) FROM schedules WHERE id=%s", (sid,)):
        _fail("scheduler_reconcile context signed with the API key was accepted")
    _ok("api_request rejected as nlw_worker/nlw_scheduler; api material rejected elsewhere")

    # 14) Worker/scheduler keys cannot authorize human administration.
    _step("worker/scheduler keys cannot authorize human administration")
    for cls in ("worker", "scheduler"):
        human = _signer(Purpose.API_REQUEST, cls=cls).sign(user_id=admin, tenant_id=tid)  # type: ignore[attr-defined]
        if _count_as(
            APP_LIBPQ, human, "SELECT count(*) FROM memberships WHERE workspace_id=%s", (tid,)
        ):
            _fail(f"api_request context signed with the {cls} key could read memberships")
        with psycopg.connect(APP_LIBPQ, autocommit=False) as c:
            _apply(c, human)
            try:
                c.execute("SELECT manage_membership(%s,%s,'change_role','member')", (tid, admin))
                c.rollback()
                _fail(f"manage_membership succeeded under a {cls}-key context")
            except psycopg.Error:
                c.rollback()
    # And the genuine worker/scheduler contexts, under their OWN roles, cannot approve
    # or manage membership either (no EXECUTE / no policy).
    w_ctx = _signer(Purpose.WORKER_EXECUTION).sign(tenant_id=tid, run_id=run)  # type: ignore[attr-defined]
    with psycopg.connect(WORKER_LIBPQ, autocommit=False) as c:
        _apply(c, w_ctx)
        for sql in (
            "UPDATE approvals SET status='approved', decided_by=%s WHERE id=%s",
            "SELECT manage_membership(%s,%s,'remove',NULL)",
        ):
            try:
                cur = c.execute(sql, (admin, appr) if "approvals" in sql else (tid, admin))
                if cur.rowcount and "UPDATE" in sql:
                    _fail("worker context approved an approval")
                if "manage_membership" in sql:
                    _fail("worker context managed membership")
            except psycopg.Error:
                pass
            c.rollback()
    _ok("worker/scheduler material + roles grant no human-administration authority")

    # 15) Rotate the API key with an overlap, move the API onto the new key, then
    #     revoke the old one. (Test-only keys; the SAME installer as production.)
    _step("rotate API key with overlap -> API on new key -> revoke old key")
    old_id, old_hex = _key("api")
    new_id, new_hex = f"{old_id}-rot", secrets.token_hex(32)
    new_path = Path(_KEYS_DIR, "api-rot.key")
    new_path.write_text(new_hex + "\n", encoding="ascii")
    new_path.chmod(0o644)  # dev/test key: container uid 10001 must read it (Linux hosts)
    ins = _compose(
        "run", "--rm", "--no-deps",
        "-v", f"{new_path.resolve()}:/run/nlw/keys/api-rot.key:ro",
        "-e", "NLW_CTX_OPERATOR=smoke-rotation",
        "api", "python", "-m", "nlw.ctxkeys", "install", "--class", "api", "--key-id", new_id,
        "--secret-file", "/run/nlw/keys/api-rot.key", "--insecure-permissions",
    )  # fmt: skip
    if ins.returncode != 0:
        _fail(f"install of rotated key failed: {ins.stderr[-400:]}")
    if new_hex in ins.stdout + ins.stderr:
        _fail("installer printed key material")
    old_ctx = signer_from_material(Purpose.API_REQUEST, old_id, old_hex).sign(
        user_id=admin, tenant_id=tid
    )
    new_ctx = signer_from_material(Purpose.API_REQUEST, new_id, new_hex).sign(
        user_id=admin, tenant_id=tid
    )
    q = "SELECT count(*) FROM memberships WHERE workspace_id=%s"
    if not (_count_as(APP_LIBPQ, old_ctx, q, (tid,)) and _count_as(APP_LIBPQ, new_ctx, q, (tid,))):
        _fail("during the overlap BOTH keys must verify")
    # Move the running API onto the new key: same mount path, new id + material.
    Path(_KEYS_DIR, "api.key").write_text(new_hex + "\n", encoding="ascii")
    up = _compose("up", "-d", "--no-deps", "api", NLW_CTX_API_KEY_ID=new_id)
    if up.returncode != 0:
        _fail(f"api restart on rotated key failed: {up.stderr[-400:]}")
    ready_ok, last = False, "unreachable"
    for _ in range(45):
        try:
            rr = requests.get(f"{API_URL}/health/ready", timeout=5)
            last = f"{rr.status_code} {rr.text[:200]}"
            if rr.status_code == 200 and rr.json().get("checks", {}).get("signed_context") == "ok":
                ready_ok = True
                break
        except requests.RequestException:
            pass
        time.sleep(2)
    if not ready_ok:
        _fail(f"API not ready on the rotated key: {last}")
    rev = _compose(
        "run", "--rm", "--no-deps", "-e", "NLW_CTX_OPERATOR=smoke-rotation",
        "api", "python", "-m", "nlw.ctxkeys", "revoke", "--key-id", old_id,
    )  # fmt: skip
    if rev.returncode != 0:
        _fail(f"revocation failed: {rev.stderr[-400:]}")
    ev = _scalar(
        OWNER_LIBPQ,
        "SELECT count(*) FROM ctx_key_events WHERE key_id=%s AND event='revoked'",
        (old_id,),
    )
    if ev != 1:
        _fail(f"revocation not audited (events={ev})")
    if (
        old_hex
        in _scalar(OWNER_LIBPQ, "SELECT string_agg(actor||event||key_id, ',') FROM ctx_key_events")
        or ""
    ):  # type: ignore[operator]
        _fail("key material in the key audit")
    _ok(f"{new_id} installed (overlap verified) -> API ready on it -> {old_id} revoked + audited")

    # 16) Contexts signed with the revoked key fail; the API keeps working on the new key.
    _step("old-key context fails after revocation; API works on the new key")
    if _count_as(APP_LIBPQ, old_ctx, q, (tid,)):
        _fail("a context signed with the REVOKED key still verifies")
    if not _count_as(APP_LIBPQ, new_ctx, q, (tid,)):
        _fail("the new key stopped verifying")
    r = requests.get(f"{API_URL}/workflows", headers=owner_h, timeout=15)
    if r.status_code != 200:
        _fail(f"API on the rotated key failed a tenant request: {r.status_code} {r.text[:200]}")
    _ok("revoked key -> nothing visible; rotated key -> API tenant request 200")

    # 17) P2 runtime recovery lock still blocks a locked database generation. The
    #     REAL quiescence records a new restore generation (quiesced, NOT validated,
    #     NOT operator-enabled) -> the authoritative DB lock engages for every
    #     runtime, signed context or not.
    _step("P2 quiescence + recovery lock still block a locked restore generation")
    from nlw.backup.quiescence import quiesce

    quiesce(engine)
    report = validate_restore(engine)  # the FULL post-restore validation, now applicable
    if not report["ok"]:
        failing = [(c["name"], c["detail"]) for c in report["checks"] if not c["ok"]]
        _fail(f"post-quiescence DR validation failed: {failing}")
    ev_id = _scalar(
        OWNER_LIBPQ, "SELECT id FROM dr_restore_events ORDER BY restored_at DESC LIMIT 1"
    )
    if ev_id is None:
        _fail("quiesce recorded no restore generation")
    try:
        sc = _compose(
            "run", "--rm", "--no-deps", "-e", "APP_ENV=local",
            "-e", "NLW_RESTORE_DATABASE_URL=postgresql+psycopg://nlw_app:nlw_app@postgres:5432/nlw",
            "api", "python", "-m", "nlw.backup", "startup-check",
        )  # fmt: skip
        if sc.returncode != 6:
            _fail(f"startup-check should exit 6 (locked), got {sc.returncode}: {sc.stderr[-300:]}")
        time.sleep(6)  # > the API's recovery-gate cache TTL (5s)
        rr = requests.get(f"{API_URL}/health/ready", timeout=5)
        if rr.status_code != 503 or rr.json().get("checks", {}).get("recovery") != "locked":
            _fail(f"API not gated by the locked generation: {rr.status_code} {rr.text[:200]}")
        biz = requests.get(f"{API_URL}/workflows", headers=owner_h, timeout=15)
        if biz.status_code != 503:
            _fail(f"business route not gated while locked: {biz.status_code}")
    finally:
        with psycopg.connect(OWNER_LIBPQ, autocommit=True) as c:
            c.execute("DELETE FROM dr_restore_events WHERE id=%s", (ev_id,))
    time.sleep(6)
    rr = requests.get(f"{API_URL}/health/ready", timeout=5)
    if rr.status_code != 200:
        _fail(f"API did not recover after the locked generation was removed: {rr.status_code}")
    _ok(
        "quiesce + full validate_restore ok -> startup-check exit 6, readiness 503 "
        "(recovery=locked), business 503; unlocked again after cleanup"
    )

    print("ALL P3A+P3B SMOKE CHECKS PASSED")


if __name__ == "__main__":
    main()
