"""Append-only authorization audit — grants + one-event-per-transition (M11.5 P3A+).

The ``authz_audit_events`` trail is append-only for every runtime role (nlw_app and
nlw_worker hold INSERT + SELECT but NEITHER UPDATE nor DELETE), so it cannot be
rewritten or erased by an application-role attacker. Each committed authorization
transition writes exactly one event, in the same transaction as the state change,
carrying actor + workspace + event type + target + timestamp — and never a token,
hash, secret, or payload.

Invitation-lifecycle boundary (invitation.expired): invitation expiry is derived
solely from ``expires_at``; the system performs NO database status transition to
'expired' (list/read never mutates), so there is no single committed expiry event
to audit — auditing one during a read would be a misleading, list-driven event.
Accepting an expired/invalid token is REJECTED without an audit event on purpose:
the accept endpoint is reachable by any authenticated user with any token string,
so emitting an event per failed attempt would be attacker-controllable audit spam.
Only committed successful transitions (created / accepted / revoked / membership.* /
approval.*) are recorded. ``test_expired_token_accept_writes_no_audit`` pins this.
"""

import time
import uuid
from collections.abc import Iterator
from types import SimpleNamespace

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

import nlw.api.routers.approvals as approvals_mod
from nlw.api.app import create_app
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

ISSUER = "https://proj.supabase.co/auth/v1"
AUD = "authenticated"
SECRET = "dev-secret-for-tests-32bytes-min-length"


def _auth(sub: str, email: str) -> dict[str, str]:
    token = jwt.encode(
        {"iss": ISSUER, "aud": AUD, "exp": int(time.time()) + 300, "sub": sub, "email": email},
        SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def enqueued(monkeypatch: pytest.MonkeyPatch) -> list[uuid.UUID]:
    captured: list[uuid.UUID] = []
    monkeypatch.setattr(approvals_mod, "_enqueue_advance", lambda _r, rid: captured.append(rid))
    return captured


@pytest.fixture
def client(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    with TestClient(create_app(pg_stack.settings)) as c:
        yield c


def _events(owner_libpq: str, tid: uuid.UUID) -> list[tuple[str, object, object, object]]:
    with psycopg.connect(owner_libpq) as c:
        rows = c.execute(
            "SELECT event_type, actor_user_id, subject_id, detail FROM authz_audit_events "
            "WHERE tenant_id=%s ORDER BY created_at",
            (tid,),
        ).fetchall()
    return [(str(r[0]), r[1], r[2], r[3]) for r in rows]


def _make_owner(client: TestClient, sub: str) -> tuple[dict[str, str], uuid.UUID]:
    h = _auth(sub, f"{sub}@x.com")
    r = client.post("/workspaces", headers=h, json={"name": f"ws-{sub}"})
    assert r.status_code == 201, r.text
    tid = uuid.UUID(r.json()["id"])
    return {**h, "X-Workspace-Id": str(tid)}, tid


def _uid(owner_libpq: str, sub: str) -> uuid.UUID:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute("SELECT id FROM users WHERE auth_provider_id=%s", (sub,)).fetchone()
    assert row is not None
    return uuid.UUID(str(row[0]))


# --- C1: the audit trail is append-only for runtime roles (no UPDATE/DELETE) ---
def test_audit_is_append_only_for_runtime_roles(pg_stack: SimpleNamespace) -> None:
    tid = uuid.uuid4()
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute("INSERT INTO workspaces (id, name, slug) VALUES (%s,'ws',%s)", (tid, f"w-{tid}"))
        c.execute(
            "INSERT INTO authz_audit_events (id, tenant_id, event_type) VALUES (%s,%s,'seed')",
            (uuid.uuid4(), tid),
        )
    # The denial is a GRANT-level fact (no UPDATE/DELETE privilege), independent of
    # any context — signed or otherwise — so no context is established here.
    for libpq in (pg_stack.app_libpq, pg_stack.worker_libpq):
        with psycopg.connect(libpq, autocommit=True) as c:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(
                    "UPDATE authz_audit_events SET event_type='tampered' WHERE tenant_id=%s", (tid,)
                )
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute("DELETE FROM authz_audit_events WHERE tenant_id=%s", (tid,))
    # The seed row is intact.
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT count(*) FROM authz_audit_events WHERE tenant_id=%s AND event_type='seed'",
            (tid,),
        ).fetchone()
    assert row is not None and row[0] == 1


# --- C2: membership admin (via manage_membership) emits one event, no secret ---
def test_membership_admin_emits_one_event(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member("owner")
    target = pg_stack.add_membership(m.tenant_id, "member")
    for sql in (
        "SELECT manage_membership(%s,%s,'set_role','admin')",
        "SELECT manage_membership(%s,%s,'remove',NULL)",
    ):
        pg_stack.run_as(
            pg_stack.app_libpq,
            Purpose.API_REQUEST,
            sql,
            (m.tenant_id, target),
            user_id=m.user_id,
            tenant_id=m.tenant_id,
        )
    evs = _events(pg_stack.owner_libpq, m.tenant_id)
    types = [e[0] for e in evs]
    assert types == ["membership.role_changed", "membership.removed"]
    role_ev = evs[0]
    assert uuid.UUID(str(role_ev[1])) == m.user_id  # actor
    assert uuid.UUID(str(role_ev[2])) == target  # subject
    assert role_ev[3] == "admin"  # detail is a role name, never a secret


# --- C3: invitation lifecycle emits create + revoke; no token/hash recorded ---
def test_invitation_lifecycle_audit(client: TestClient, pg_stack: SimpleNamespace) -> None:
    owner_h, tid = _make_owner(client, "audit_inv")
    inv = client.post(
        "/invitations", headers=owner_h, json={"email": "x@y.com", "role": "member"}
    ).json()
    assert client.post(f"/invitations/{inv['id']}/revoke", headers=owner_h).status_code == 204
    evs = _events(pg_stack.owner_libpq, tid)
    types = [e[0] for e in evs]
    assert types == ["invitation.created", "invitation.revoked"]
    raw = inv["token"]
    # No event detail/subject exposes the raw token or its hash.
    for _t, _actor, subject, detail in evs:
        assert detail != raw
        assert str(subject) != raw
        assert detail is None or ("token" not in str(detail).lower())


# --- C4: acceptance emits membership.added + invitation.accepted (one transition) ---
def test_accept_emits_membership_and_acceptance(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    owner_h, tid = _make_owner(client, "audit_acc")
    inv = client.post(
        "/invitations", headers=owner_h, json={"email": "joiner@y.com", "role": "member"}
    ).json()
    bh = _auth("joiner", "joiner@y.com")
    assert (
        client.post("/invitations/accept", headers=bh, json={"token": inv["token"]}).status_code
        == 200
    )
    types = [e[0] for e in _events(pg_stack.owner_libpq, tid)]
    # Same-transaction events share a now() timestamp, so assert the multiset (one
    # each, no duplicates), not an order.
    assert sorted(types) == ["invitation.accepted", "invitation.created", "membership.added"]


# --- C5: an approval decision emits one event; idempotent re-decide adds none ---
def test_approval_decision_emits_one_event(
    client: TestClient, pg_stack: SimpleNamespace, enqueued: list[uuid.UUID]
) -> None:
    owner_h, tid = _make_owner(client, "audit_dec")
    # A second admin (the eligible decider) + a member requester.
    req = pg_stack.add_membership(tid, "member")
    # Seed a parked approval whose requester is the member (four-eyes: owner != req).
    wf, ver, run, appr, conn_id = (uuid.uuid4() for _ in range(5))
    plan = '{"steps":[{"id":"notify","tool":"webhook.send","args":{},"connector":"hook"}]}'
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
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
            (run, tid, wf, ver, req),
        )
        c.execute(
            "INSERT INTO approvals (id, tenant_id, run_id, step_id, connector_id, connector_name, "
            "tool, status, requested_by_user_id) "
            "VALUES (%s,%s,%s,'notify',%s,'hook','webhook.send','pending',%s)",
            (appr, tid, run, conn_id, req),
        )
    assert client.post(f"/approvals/{appr}/approve", headers=owner_h).status_code == 200
    # Idempotent re-approve does not add another event.
    assert client.post(f"/approvals/{appr}/approve", headers=owner_h).status_code == 200
    decisions = [e for e in _events(pg_stack.owner_libpq, tid) if e[0].startswith("approval.")]
    assert [e[0] for e in decisions] == ["approval.approved"]
    assert uuid.UUID(str(decisions[0][2])) == appr  # subject is the approval id


def _seed_invitee_and_invitation(
    pg_stack: SimpleNamespace, *, expires: str = "now() + interval '72 hours'"
) -> tuple[uuid.UUID, uuid.UUID, str]:
    """Seed a tenant+owner, an un-membered invitee user, and a pending invitation
    (known token hash) for that invitee's email. Returns (tenant, invitee, hash)."""
    from nlw.authz.invitations import hash_token

    tid, owner_uid, invitee = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    inv_id = uuid.uuid4()
    token_hash = hash_token("raw-" + inv_id.hex)
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute("INSERT INTO workspaces (id, name, slug) VALUES (%s,'ws',%s)", (tid, f"w-{tid}"))
        c.execute(
            "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s),(%s,%s,%s)",
            (owner_uid, f"o-{tid}", f"o-{tid}@x.io", invitee, f"i-{tid}", f"i-{tid}@x.io"),
        )
        c.execute(
            "INSERT INTO memberships (id, user_id, workspace_id, role) VALUES (%s,%s,%s,'owner')",
            (uuid.uuid4(), owner_uid, tid),
        )
        c.execute(
            "INSERT INTO workspace_invitations "
            "(id, tenant_id, email, role, invited_by, token_hash, status, expires_at) "
            f"VALUES (%s,%s,%s,'member',%s,%s,'pending',{expires})",
            (inv_id, tid, f"i-{tid}@x.io", owner_uid, token_hash),
        )
    return tid, invitee, token_hash


# --- C6: accept is atomic — a rollback removes BOTH the membership and the audit ---
def test_accept_atomic_rollback_removes_state_and_audit(pg_stack: SimpleNamespace) -> None:
    tid, invitee, token_hash = _seed_invitee_and_invitation(pg_stack)
    # Call the accept function as nlw_app WITHOUT committing, then roll back.
    with psycopg.connect(pg_stack.app_libpq, autocommit=False) as c:
        pg_stack.apply_ctx(c, pg_stack.sign(Purpose.API_IDENTITY, user_id=invitee))
        c.execute("SELECT accept_workspace_invitation(%s)", (token_hash,))
        c.rollback()
    with psycopg.connect(pg_stack.owner_libpq) as c:
        n_mem = c.execute(
            "SELECT count(*) FROM memberships WHERE workspace_id=%s AND user_id=%s", (tid, invitee)
        ).fetchone()
        n_audit = c.execute(
            "SELECT count(*) FROM authz_audit_events WHERE tenant_id=%s", (tid,)
        ).fetchone()
    assert n_mem and n_mem[0] == 0, "rolled-back membership persisted"
    assert n_audit and n_audit[0] == 0, "rolled-back audit event persisted"
    # A committed accept then writes exactly one membership.added + invitation.accepted.
    with psycopg.connect(pg_stack.app_libpq, autocommit=False) as c:
        pg_stack.apply_ctx(c, pg_stack.sign(Purpose.API_IDENTITY, user_id=invitee))
        c.execute("SELECT accept_workspace_invitation(%s)", (token_hash,))
        c.commit()
    types = [e[0] for e in _events(pg_stack.owner_libpq, tid)]
    assert sorted(types) == ["invitation.accepted", "membership.added"]


# --- C7: concurrent duplicate accepts -> exactly one committed transition set ---
def test_concurrent_double_accept_one_transition_set(pg_stack: SimpleNamespace) -> None:
    tid, invitee, token_hash = _seed_invitee_and_invitation(pg_stack)
    import threading

    barrier = threading.Barrier(2)
    results: list[str] = []
    lock = threading.Lock()

    def accept() -> None:
        with psycopg.connect(pg_stack.app_libpq, autocommit=False) as c:
            pg_stack.apply_ctx(c, pg_stack.sign(Purpose.API_IDENTITY, user_id=invitee))
            barrier.wait()
            try:
                c.execute("SELECT accept_workspace_invitation(%s)", (token_hash,))
                c.commit()
                out = "ok"
            except Exception:
                c.rollback()
                out = "fail"
        with lock:
            results.append(out)

    ts = [threading.Thread(target=accept) for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    # Exactly one commits; the loser sees the invitation already accepted (invalid).
    assert sorted(results) == ["fail", "ok"]
    types = [e[0] for e in _events(pg_stack.owner_libpq, tid)]
    assert sorted(types) == ["invitation.accepted", "membership.added"]  # one set, no dupes


# --- C8: accepting an expired/invalid token writes NO audit event (no spam) ---
def test_expired_token_accept_writes_no_audit(pg_stack: SimpleNamespace) -> None:
    tid, invitee, token_hash = _seed_invitee_and_invitation(
        pg_stack, expires="now() - interval '1 hour'"
    )
    with psycopg.connect(pg_stack.app_libpq, autocommit=False) as c:
        pg_stack.apply_ctx(c, pg_stack.sign(Purpose.API_IDENTITY, user_id=invitee))
        with pytest.raises(psycopg.errors.Error):
            c.execute("SELECT accept_workspace_invitation(%s)", (token_hash,))
        c.rollback()
    with psycopg.connect(pg_stack.owner_libpq) as c:
        n = c.execute(
            "SELECT count(*) FROM authz_audit_events WHERE tenant_id=%s", (tid,)
        ).fetchone()
    assert n and n[0] == 0, "an expired-token accept must not produce audit spam"
