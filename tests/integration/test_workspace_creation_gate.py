"""B01: founding a workspace requires an operator grant (migration 0022).

These tests run WITHOUT the harness auto-grant, so every grant is issued
explicitly. They prove that an arbitrary authenticated identity cannot bootstrap
a tenant through the API or through raw SQL as ``nlw_app``, that a grant is
single-use and email-bound, and that the audit trail records provisioning and
creation.
"""

import time
import uuid
from collections.abc import Iterator
from types import SimpleNamespace

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

from nlw.api.app import create_app
from nlw.ops import grants
from nlw.tenancy.signing import Purpose

pytestmark = [pytest.mark.integration, pytest.mark.workspace_grants_enforced]

ISSUER = "https://proj.supabase.co/auth/v1"
SECRET = "dev-secret-for-tests-32bytes-min-length"


def _auth(sub: str, email: str) -> dict[str, str]:
    payload = {
        "iss": ISSUER,
        "aud": "authenticated",
        "exp": int(time.time()) + 300,
        "sub": sub,
        "email": email,
    }
    return {"Authorization": f"Bearer {jwt.encode(payload, SECRET, algorithm='HS256')}"}


@pytest.fixture
def client(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    with TestClient(create_app(pg_stack.settings)) as c:
        yield c


def _count(pg_stack: SimpleNamespace, sql: str, *params: object) -> int:
    with psycopg.connect(pg_stack.owner_libpq) as conn:
        row = conn.execute(sql, params).fetchone()
    assert row is not None
    return int(row[0])


def _workspaces(pg_stack: SimpleNamespace) -> int:
    return _count(pg_stack, "SELECT count(*) FROM workspaces")


def test_fresh_identity_without_grant_is_provisioned_but_cannot_found_a_workspace(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    h = _auth(f"sub-{uuid.uuid4()}", "stranger@example.com")
    me = client.get("/me", headers=h)
    assert me.status_code == 200  # identity provisioning itself is still allowed
    user_id = uuid.UUID(me.json()["id"])
    before = _workspaces(pg_stack)

    r = client.post("/workspaces", json={"name": "Mine"}, headers=h)

    assert r.status_code == 403
    assert r.json()["error"]["code"] == "WORKSPACE_CREATION_NOT_GRANTED"
    assert _workspaces(pg_stack) == before
    assert client.get("/workspaces", headers=h).json() == []
    assert (
        _count(
            pg_stack,
            "SELECT count(*) FROM authz_audit_events "
            "WHERE event_type='identity.provisioned' AND subject_id=%s AND tenant_id IS NULL",
            user_id,
        )
        == 1
    )
    assert (
        _count(
            pg_stack,
            "SELECT count(*) FROM authz_audit_events WHERE event_type='workspace.created'",
        )
        == 0
    )


def test_identity_provisioned_event_is_written_once(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    h = _auth(f"sub-{uuid.uuid4()}", "once@example.com")
    uid = client.get("/me", headers=h).json()["id"]
    client.get("/me", headers=h)
    client.get("/workspaces", headers=h)
    assert (
        _count(
            pg_stack,
            "SELECT count(*) FROM authz_audit_events "
            "WHERE event_type='identity.provisioned' AND subject_id=%s",
            uid,
        )
        == 1
    )


def test_grant_allows_exactly_one_workspace_and_is_consumed_and_audited(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    email = "founder@example.com"
    h = _auth(f"sub-{uuid.uuid4()}", email)
    gid = pg_stack.grant_workspace_creation("  Founder@Example.com ")  # normalised

    r = client.post("/workspaces", json={"name": "Acme"}, headers=h)
    assert r.status_code == 201, r.text
    ws = uuid.UUID(r.json()["id"])
    assert r.json()["role"] == "owner"

    with psycopg.connect(pg_stack.owner_libpq) as conn:
        row = conn.execute(
            "SELECT consumed_at IS NOT NULL, consumed_workspace_id, consumed_by_user_id "
            "FROM workspace_creation_grants WHERE id=%s",
            (gid,),
        ).fetchone()
        audit = conn.execute(
            "SELECT tenant_id, detail FROM authz_audit_events "
            "WHERE event_type='workspace.created' AND subject_id=%s",
            (ws,),
        ).fetchall()
    assert row is not None and row[0] is True and row[1] == ws and row[2] is not None
    assert audit == [(ws, str(gid))]

    second = client.post("/workspaces", json={"name": "Acme 2"}, headers=h)
    assert second.status_code == 403
    assert second.json()["error"]["code"] == "WORKSPACE_CREATION_NOT_GRANTED"
    assert [w["id"] for w in client.get("/workspaces", headers=h).json()] == [str(ws)]


def test_grant_for_another_email_expired_or_revoked_is_refused(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    before = _workspaces(pg_stack)

    pg_stack.grant_workspace_creation("someone-else@example.com")
    other = _auth(f"sub-{uuid.uuid4()}", "not-granted@example.com")
    assert client.post("/workspaces", json={"name": "X"}, headers=other).status_code == 403

    pg_stack.grant_workspace_creation("late@example.com", expires="-1 hour")
    late = _auth(f"sub-{uuid.uuid4()}", "late@example.com")
    assert client.post("/workspaces", json={"name": "X"}, headers=late).status_code == 403

    gid = pg_stack.grant_workspace_creation("revoked@example.com")
    with psycopg.connect(pg_stack.owner_libpq) as conn:
        grants.revoke_grant(conn, grant_id=gid, revoked_by="test-operator")
    revoked = _auth(f"sub-{uuid.uuid4()}", "revoked@example.com")
    assert client.post("/workspaces", json={"name": "X"}, headers=revoked).status_code == 403

    assert _workspaces(pg_stack) == before


def test_closed_mode_refuses_even_a_granted_email(pg_stack: SimpleNamespace) -> None:
    settings = pg_stack.settings.model_copy(update={"workspace_creation_mode": "closed"})
    gid = pg_stack.grant_workspace_creation("closed@example.com")
    with TestClient(create_app(settings)) as c:
        r = c.post(
            "/workspaces",
            json={"name": "X"},
            headers=_auth(f"sub-{uuid.uuid4()}", "closed@example.com"),
        )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "WORKSPACE_CREATION_CLOSED"
    assert (
        _count(
            pg_stack,
            "SELECT count(*) FROM workspace_creation_grants WHERE id=%s AND consumed_at IS NULL",
            gid,
        )
        == 1
    )


def test_raw_sql_as_nlw_app_cannot_bootstrap_or_touch_grants(pg_stack: SimpleNamespace) -> None:
    user = pg_stack.seed_user()
    ctx = pg_stack.sign(Purpose.API_IDENTITY, user_id=user)

    with psycopg.connect(pg_stack.app_libpq) as conn:
        pg_stack.apply_ctx(conn, ctx)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT create_workspace_for_current_user('x', 'x-slug')")
    for stmt in (
        "SELECT count(*) FROM workspace_creation_grants",
        "INSERT INTO workspace_creation_grants (id, email_normalized, granted_by, expires_at) "
        "VALUES (gen_random_uuid(), 'a@b.co', 'me', now() + interval '1 day')",
        "UPDATE workspace_creation_grants SET revoked_at = now()",
    ):
        with psycopg.connect(pg_stack.app_libpq) as conn:
            pg_stack.apply_ctx(conn, ctx)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(stmt)
    for role in ("nlw_app", "nlw_worker", "nlw_scheduler"):
        assert (
            _count(
                pg_stack,
                "SELECT count(*) FROM information_schema.role_table_grants "
                "WHERE table_name='workspace_creation_grants' AND grantee=%s",
                role,
            )
            == 0
        )


def test_raw_sql_with_a_grant_consumes_it_in_the_database(pg_stack: SimpleNamespace) -> None:
    user = pg_stack.seed_user()  # email is f"{uid}@example.com"
    gid = pg_stack.grant_workspace_creation(f"{user}@example.com")
    with psycopg.connect(pg_stack.app_libpq) as conn:
        pg_stack.apply_ctx(conn, pg_stack.sign(Purpose.API_IDENTITY, user_id=user))
        assert conn.execute("SELECT has_workspace_creation_grant()").fetchone() == (True,)
        ws = conn.execute("SELECT create_workspace_for_current_user('x', %s)", (f"x-{gid}",))
        workspace_id = ws.fetchone()
        assert conn.execute("SELECT has_workspace_creation_grant()").fetchone() == (False,)
        conn.commit()
    assert workspace_id is not None
    assert (
        _count(
            pg_stack,
            "SELECT count(*) FROM workspace_creation_grants "
            "WHERE id=%s AND consumed_workspace_id=%s",
            gid,
            workspace_id[0],
        )
        == 1
    )


def test_no_ungated_bootstrap_overload_and_owner_is_bootstrap_role(
    pg_stack: SimpleNamespace,
) -> None:
    with psycopg.connect(pg_stack.owner_libpq) as conn:
        rows = conn.execute(
            "SELECT pg_get_function_identity_arguments(p.oid), r.rolname, p.prosecdef, p.prosrc "
            "FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
            "WHERE p.proname = 'create_workspace_for_current_user'"
        ).fetchall()
        helper = conn.execute(
            "SELECT r.rolname, p.prosecdef, has_function_privilege('public', p.oid, 'EXECUTE') "
            "FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
            "WHERE p.proname = 'has_workspace_creation_grant'"
        ).fetchall()
    assert len(rows) == 1
    args, owner, secdef, src = rows[0]
    assert (args, owner, secdef) == ("p_name text, p_slug text", "nlw_workspace_bootstrap", True)
    assert "workspace_creation_grants" in src and "42501" in src
    assert helper == [("nlw_workspace_bootstrap", True, False)]


def test_one_open_grant_per_email_and_operator_helpers(pg_stack: SimpleNamespace) -> None:
    from datetime import timedelta

    with psycopg.connect(pg_stack.owner_libpq) as conn:
        gid = grants.add_grant(
            conn, email="Ops@Example.com", expires_in=timedelta(hours=72), granted_by="op"
        )
        with pytest.raises(grants.GrantError):
            grants.add_grant(
                conn, email="ops@example.com", expires_in=timedelta(hours=1), granted_by="op"
            )
        listed = grants.list_grants(conn, include_closed=False)
        assert [(r[0], r[1], r[5]) for r in listed] == [(gid, "ops@example.com", "open")]
        grants.revoke_grant(conn, grant_id=gid, revoked_by="op")
        with pytest.raises(grants.GrantError):
            grants.revoke_grant(conn, grant_id=gid, revoked_by="op")
        assert grants.list_grants(conn, include_closed=False) == []
        assert [r[5] for r in grants.list_grants(conn, include_closed=True)] == ["revoked"]
        # A new grant after revocation is allowed (the unique index covers open grants only).
        grants.add_grant(
            conn, email="ops@example.com", expires_in=timedelta(hours=1), granted_by="op"
        )


def test_invitation_path_is_unaffected_by_the_gate(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    """Joining an existing workspace needs an invitation, not a creation grant."""
    pg_stack.grant_workspace_creation("inviter@example.com")
    owner = _auth(f"sub-{uuid.uuid4()}", "inviter@example.com")
    ws = client.post("/workspaces", json={"name": "Team"}, headers=owner).json()["id"]
    owner["X-Workspace-Id"] = ws
    inv = client.post(
        "/invitations",
        json={"email": "joiner@example.com", "role": "member"},
        headers=owner,
    )
    assert inv.status_code == 201, inv.text
    joiner = _auth(f"sub-{uuid.uuid4()}", "joiner@example.com")
    acc = client.post("/invitations/accept", json={"token": inv.json()["token"]}, headers=joiner)
    assert acc.status_code == 200, acc.text
    assert acc.json()["workspace_id"] == ws
    # ...and joining did not grant the right to found a new tenant.
    assert client.post("/workspaces", json={"name": "Mine"}, headers=joiner).status_code == 403
