"""Membership, invitations, owner-invariant adversarial tests (M11.5 P3A).

Real PostgreSQL (pg_stack) + the API. Covers invite lifecycle, single-use/expiry/
revoke, email binding, member-cannot-invite, duplicate-membership, final-owner
preservation, and concurrency for acceptance + owner removal.
"""

import threading
import time
import uuid
from collections.abc import Iterator
from types import SimpleNamespace

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

from nlw.api.app import create_app
from nlw.authz.invitations import hash_token

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
def client(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    with TestClient(create_app(pg_stack.settings)) as c:
        yield c


def _make_owner(client: TestClient, sub: str, email: str) -> tuple[dict[str, str], uuid.UUID]:
    """Authenticate as a brand-new user and create a workspace (owner membership)."""
    h = _auth(sub, email)
    r = client.post("/workspaces", headers=h, json={"name": f"ws-{sub}"})
    assert r.status_code == 201, r.text
    tid = uuid.UUID(r.json()["id"])
    return {**h, "X-Workspace-Id": str(tid)}, tid


def _invite(
    client: TestClient, owner_h: dict[str, str], email: str, role: str = "member"
) -> dict[str, object]:
    r = client.post("/invitations", headers=owner_h, json={"email": email, "role": role})
    assert r.status_code == 201, r.text
    result: dict[str, object] = r.json()
    return result


def _user_id(owner_libpq: str, sub: str) -> uuid.UUID:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute("SELECT id FROM users WHERE auth_provider_id=%s", (sub,)).fetchone()
    assert row is not None
    return uuid.UUID(str(row[0]))


# --- 1: owner invites, correct verified user accepts ---
def test_owner_invites_and_correct_user_accepts(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    owner_h, tid = _make_owner(client, "own1", "own1@x.com")
    inv = _invite(client, owner_h, "invitee@x.com")
    assert "token" in inv and inv["role"] == "member"

    accept = client.post(
        "/invitations/accept", headers=_auth("inv1", "invitee@x.com"), json={"token": inv["token"]}
    )
    assert accept.status_code == 200, accept.text
    assert uuid.UUID(accept.json()["workspace_id"]) == tid
    # The invitee is now a member and can resolve the workspace.
    who = client.get(
        "/workspaces/current",
        headers={**_auth("inv1", "invitee@x.com"), "X-Workspace-Id": str(tid)},
    )
    assert who.status_code == 200 and who.json()["role"] == "member"


# --- 2: wrong email cannot accept ---
def test_wrong_email_cannot_accept(client: TestClient, pg_stack: SimpleNamespace) -> None:
    owner_h, tid = _make_owner(client, "own2", "own2@x.com")
    inv = _invite(client, owner_h, "invitee2@x.com")
    r = client.post(
        "/invitations/accept",
        headers=_auth("wrong", "someone-else@x.com"),
        json={"token": inv["token"]},
    )
    assert r.status_code == 400 and r.json()["error"]["message"] == "invitation is not valid"


# --- 3: expired invitation cannot be accepted ---
def test_expired_invitation_cannot_be_accepted(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    owner_h, tid = _make_owner(client, "own3", "own3@x.com")
    inv = _invite(client, owner_h, "invitee3@x.com")
    # Force it expired (operator/clock).
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute(
            "UPDATE workspace_invitations SET expires_at = now() - interval '1 hour' WHERE id=%s",
            (inv["id"],),
        )
    r = client.post(
        "/invitations/accept",
        headers=_auth("inv3", "invitee3@x.com"),
        json={"token": inv["token"]},
    )
    assert r.status_code == 400


# --- 4: revoked invitation cannot be accepted ---
def test_revoked_invitation_cannot_be_accepted(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    owner_h, tid = _make_owner(client, "own4", "own4@x.com")
    inv = _invite(client, owner_h, "invitee4@x.com")
    assert client.post(f"/invitations/{inv['id']}/revoke", headers=owner_h).status_code == 204
    r = client.post(
        "/invitations/accept",
        headers=_auth("inv4", "invitee4@x.com"),
        json={"token": inv["token"]},
    )
    assert r.status_code == 400


# --- 5: used invitation cannot be reused ---
def test_used_invitation_cannot_be_reused(client: TestClient, pg_stack: SimpleNamespace) -> None:
    owner_h, tid = _make_owner(client, "own5", "own5@x.com")
    inv = _invite(client, owner_h, "invitee5@x.com")
    ih = _auth("inv5", "invitee5@x.com")
    assert (
        client.post("/invitations/accept", headers=ih, json={"token": inv["token"]}).status_code
        == 200
    )
    again = client.post("/invitations/accept", headers=ih, json={"token": inv["token"]})
    assert again.status_code == 400


# --- 7: raw token absent from DB, and only the hash is stored ---
def test_raw_token_absent_from_database(client: TestClient, pg_stack: SimpleNamespace) -> None:
    owner_h, tid = _make_owner(client, "own7", "own7@x.com")
    inv = _invite(client, owner_h, "invitee7@x.com")
    raw = str(inv["token"])
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT token_hash FROM workspace_invitations WHERE id=%s", (inv["id"],)
        ).fetchone()
        # No column anywhere stores the raw token.
        any_raw = c.execute(
            "SELECT count(*) FROM workspace_invitations WHERE token_hash = %s", (raw,)
        ).fetchone()
    assert row is not None and row[0] == hash_token(raw)
    assert any_raw is not None and any_raw[0] == 0  # raw is never stored as-is
    # The list/create responses never expose the hash.
    listed = client.get("/invitations", headers=owner_h).json()
    assert all("token_hash" not in i and "token" not in i for i in listed)


# --- 8: member cannot invite; --- 9: admin can invite ---
def test_member_cannot_invite_admin_can(client: TestClient, pg_stack: SimpleNamespace) -> None:
    owner_h, tid = _make_owner(client, "own8", "own8@x.com")
    # Invite a MEMBER and an ADMIN.
    m_inv = _invite(client, owner_h, "member8@x.com", "member")
    a_inv = _invite(client, owner_h, "admin8@x.com", "admin")
    mh = _auth("mem8", "member8@x.com")
    ah = _auth("adm8", "admin8@x.com")
    assert (
        client.post("/invitations/accept", headers=mh, json={"token": m_inv["token"]}).status_code
        == 200
    )
    assert (
        client.post("/invitations/accept", headers=ah, json={"token": a_inv["token"]}).status_code
        == 200
    )
    m_ctx = {**mh, "X-Workspace-Id": str(tid)}
    a_ctx = {**ah, "X-Workspace-Id": str(tid)}
    # Member cannot invite; admin can.
    assert (
        client.post(
            "/invitations", headers=m_ctx, json={"email": "x@x.com", "role": "member"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/invitations", headers=a_ctx, json={"email": "y@x.com", "role": "member"}
        ).status_code
        == 201
    )


# --- 10: duplicate active membership prevented (accept twice into same ws) ---
def test_duplicate_membership_prevented(client: TestClient, pg_stack: SimpleNamespace) -> None:
    owner_h, tid = _make_owner(client, "own10", "own10@x.com")
    inv1 = _invite(client, owner_h, "dup@x.com")
    ih = _auth("dup", "dup@x.com")
    assert (
        client.post("/invitations/accept", headers=ih, json={"token": inv1["token"]}).status_code
        == 200
    )
    # A second pending invite for the same email, accepted again -> still one membership.
    inv2 = _invite(client, owner_h, "dup@x.com")
    r = client.post("/invitations/accept", headers=ih, json={"token": inv2["token"]})
    assert r.status_code == 200  # idempotent membership
    with psycopg.connect(pg_stack.owner_libpq) as c:
        n = c.execute(
            "SELECT count(*) FROM memberships WHERE workspace_id=%s AND user_id=%s",
            (tid, _user_id(pg_stack.owner_libpq, "dup")),
        ).fetchone()
    assert n is not None and n[0] == 1


# --- 6 + 12: concurrency ---
def _set_ctx(conn: psycopg.Connection, uid: uuid.UUID, tid: uuid.UUID | None = None) -> None:
    conn.execute("SELECT set_config('app.user_id', %s, false)", (str(uid),))
    if tid is not None:
        conn.execute("SELECT set_config('app.tenant_id', %s, false)", (str(tid),))


def test_concurrent_double_acceptance_creates_one_membership(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    owner_h, tid = _make_owner(client, "own6", "own6@x.com")
    inv = _invite(client, owner_h, "conc@x.com")
    # Provision the invitee user first (so both threads see it committed).
    client.get("/me", headers=_auth("conc", "conc@x.com"))
    uid = _user_id(pg_stack.owner_libpq, "conc")
    token_hash = hash_token(str(inv["token"]))

    results: list[str] = []
    barrier = threading.Barrier(2)

    def worker() -> None:
        with psycopg.connect(pg_stack.app_libpq, autocommit=False) as conn:
            _set_ctx(conn, uid)
            barrier.wait()
            try:
                conn.execute("SELECT accept_workspace_invitation(%s)", (token_hash,))
                conn.commit()
                results.append("ok")
            except Exception:
                conn.rollback()
                results.append("fail")

    ts = [threading.Thread(target=worker) for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sorted(results) == ["fail", "ok"]  # exactly one accepted
    with psycopg.connect(pg_stack.owner_libpq) as c:
        n = c.execute(
            "SELECT count(*) FROM memberships WHERE workspace_id=%s AND user_id=%s", (tid, uid)
        ).fetchone()
    assert n is not None and n[0] == 1


# --- 11: final owner cannot be removed or demoted ---
def test_final_owner_cannot_be_removed_or_demoted(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    owner_h, tid = _make_owner(client, "own11", "own11@x.com")
    uid = _user_id(pg_stack.owner_libpq, "own11")
    # Demote the sole owner -> blocked (409, workspace must keep an owner).
    r = client.patch(f"/members/{uid}", headers=owner_h, json={"role": "member"})
    assert r.status_code == 409
    # Remove the sole owner -> blocked.
    r2 = client.delete(f"/members/{uid}", headers=owner_h)
    assert r2.status_code == 409
    with psycopg.connect(pg_stack.owner_libpq) as c:
        n = c.execute(
            "SELECT count(*) FROM memberships WHERE workspace_id=%s AND role='owner'", (tid,)
        ).fetchone()
    assert n is not None and n[0] == 1  # still exactly one owner


def test_concurrent_owner_removal_keeps_one_owner(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    owner_h, tid = _make_owner(client, "own12a", "own12a@x.com")
    # Add a SECOND owner via invite(admin) then promote to owner.
    inv = _invite(client, owner_h, "own12b@x.com", "admin")
    bh = _auth("own12b", "own12b@x.com")
    client.post("/invitations/accept", headers=bh, json={"token": inv["token"]})
    b_uid = _user_id(pg_stack.owner_libpq, "own12b")
    a_uid = _user_id(pg_stack.owner_libpq, "own12a")
    assert (
        client.patch(f"/members/{b_uid}", headers=owner_h, json={"role": "owner"}).status_code
        == 200
    )

    # Concurrently: A removes B, B removes A — via the function-only mutation path
    # (nlw_app has NO direct DELETE). The advisory-lock-first serialization inside
    # manage_membership must let at most one succeed (a workspace always keeps an
    # owner). See test_owner_race.py for the full deterministic barrier suite.
    results: list[str] = []
    barrier = threading.Barrier(2)

    def remove(actor: uuid.UUID, target: uuid.UUID) -> None:
        with psycopg.connect(pg_stack.app_libpq, autocommit=False) as conn:
            _set_ctx(conn, actor, tid)
            barrier.wait()
            try:
                conn.execute("SELECT manage_membership(%s,%s,'remove',NULL)", (tid, target))
                conn.commit()
                results.append("ok")
            except Exception:
                conn.rollback()
                results.append("fail")

    t1 = threading.Thread(target=remove, args=(a_uid, b_uid))
    t2 = threading.Thread(target=remove, args=(b_uid, a_uid))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    assert "fail" in results  # they cannot BOTH succeed
    with psycopg.connect(pg_stack.owner_libpq) as c:
        n = c.execute(
            "SELECT count(*) FROM memberships WHERE workspace_id=%s AND role='owner'", (tid,)
        ).fetchone()
    assert n is not None and n[0] >= 1  # an owner always remains
