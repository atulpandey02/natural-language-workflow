"""Append-only authorization audit — grants + one-event-per-transition (M11.5 P3A+).

The ``authz_audit_events`` trail is append-only for every runtime role (nlw_app and
nlw_worker hold INSERT + SELECT but NEITHER UPDATE nor DELETE), so it cannot be
rewritten or erased by an application-role attacker. Each committed authorization
transition writes exactly one event, in the same transaction as the state change,
carrying actor + workspace + event type + target + timestamp — and never a token,
hash, secret, or payload.
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
    for libpq, sets_user in ((pg_stack.app_libpq, True), (pg_stack.worker_libpq, False)):
        with psycopg.connect(libpq, autocommit=True) as c:
            if sets_user:
                c.execute("SELECT set_config('app.user_id', %s, false)", (str(uuid.uuid4()),))
            c.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tid),))
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
    with psycopg.connect(pg_stack.app_libpq, autocommit=True) as c:
        c.execute("SELECT set_config('app.user_id', %s, false)", (str(m.user_id),))
        c.execute("SELECT set_config('app.tenant_id', %s, false)", (str(m.tenant_id),))
        c.execute("SELECT manage_membership(%s,%s,'set_role','admin')", (m.tenant_id, target))
        c.execute("SELECT manage_membership(%s,%s,'remove',NULL)", (m.tenant_id, target))
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
    assert types == ["invitation.created", "membership.added", "invitation.accepted"]


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
