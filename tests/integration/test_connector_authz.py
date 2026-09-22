"""Connector mutation authorization (M11.5 P1A).

A secret alias identifies a secret; it never grants authority to attach it.
Members may read safe connector metadata but only admins/owners may create a
connector and attach a credential reference. Enforced in BOTH the API
(``require_role``) and PostgreSQL RLS (the ``connectors_app_insert`` policy now
requires ``is_current_user_admin_or_owner``), so a direct request that bypasses
the API still fails at the database.
"""

import time
import uuid
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

from nlw.api.app import create_app
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

ISSUER = "https://proj.supabase.co/auth/v1"
AUD = "authenticated"
SECRET = "dev-secret-for-tests-32bytes-min-length"

_STATIC = {"type": "static", "name": "demo", "config": {"label": "x"}, "secret_ref": "STATIC_DEMO"}


def _one(cur: Any) -> tuple[Any, ...]:
    row = cur.fetchone()
    assert row is not None
    return row  # type: ignore[no-any-return]


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


def _owner_workspace(client: TestClient) -> tuple[str, dict[str, str]]:
    owner = _auth(f"owner-{uuid.uuid4()}", "owner@example.com")
    ws = str(client.post("/workspaces", json={"name": "W"}, headers=owner).json()["id"])
    return ws, {**owner, "X-Workspace-Id": ws}


def _principal_in(pg_stack: SimpleNamespace, tenant_id: str, role: str) -> dict[str, str]:
    """Add a fresh user with ``role`` to an existing workspace; return auth headers."""
    uid = pg_stack.add_membership(uuid.UUID(tenant_id), role)
    return {**_auth(f"sub-{uid}", f"{uid}@example.com"), "X-Workspace-Id": tenant_id}


def _set_ctx(
    pg_stack: SimpleNamespace, conn: Any, user_id: uuid.UUID, tenant_id: uuid.UUID
) -> None:
    """SIGNED api_request context (P3B): the user/tenant pair is authenticated by
    the fixture's api key; a forged pair simply verifies to no membership."""
    pg_stack.apply_ctx(
        conn, pg_stack.sign(Purpose.API_REQUEST, user_id=user_id, tenant_id=tenant_id)
    )


def _insert_connector_sql(
    tenant_id: uuid.UUID, name: str, alias: str
) -> tuple[str, tuple[Any, ...]]:
    return (
        "INSERT INTO connectors (id, tenant_id, type, name, config, secret_ref, status) "
        "VALUES (%s,%s,'static',%s,'{}'::jsonb,%s,'unchecked')",
        (uuid.uuid4(), tenant_id, name, alias),
    )


# --------------------------------------------------------------- API layer ---


def test_member_can_list_connector_metadata(client: TestClient, pg_stack: SimpleNamespace) -> None:
    ws, owner_h = _owner_workspace(client)
    assert client.post("/connectors", json=_STATIC, headers=owner_h).status_code == 201
    member_h = _principal_in(pg_stack, ws, "member")
    listed = client.get("/connectors", headers=member_h)
    assert listed.status_code == 200
    assert [c["name"] for c in listed.json()] == ["demo"]
    assert client.get("/tools", headers=member_h).status_code == 200


def test_member_cannot_create_connector(client: TestClient, pg_stack: SimpleNamespace) -> None:
    ws, _ = _owner_workspace(client)
    member_h = _principal_in(pg_stack, ws, "member")
    resp = client.post("/connectors", json=_STATIC, headers=member_h)
    assert resp.status_code == 403


def test_member_cannot_attach_known_alias(client: TestClient, pg_stack: SimpleNamespace) -> None:
    # Even knowing a valid tenant alias, a member cannot attach it.
    ws, owner_h = _owner_workspace(client)
    client.post("/connectors", json=_STATIC, headers=owner_h)
    member_h = _principal_in(pg_stack, ws, "member")
    resp = client.post(
        "/connectors",
        json={
            "type": "static",
            "name": "sneaky",
            "config": {"label": "y"},
            "secret_ref": "STATIC_DEMO",
        },
        headers=member_h,
    )
    assert resp.status_code == 403


def test_admin_can_create_connector(client: TestClient, pg_stack: SimpleNamespace) -> None:
    ws, _ = _owner_workspace(client)
    admin_h = _principal_in(pg_stack, ws, "admin")
    resp = client.post("/connectors", json=_STATIC, headers=admin_h)
    assert resp.status_code == 201
    assert resp.json()["has_secret"] is True


def test_owner_can_create_connector(client: TestClient) -> None:
    _, owner_h = _owner_workspace(client)
    resp = client.post("/connectors", json=_STATIC, headers=owner_h)
    assert resp.status_code == 201


def test_connector_responses_never_leak_secret_ref(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    ws, owner_h = _owner_workspace(client)
    created = client.post("/connectors", json=_STATIC, headers=owner_h)
    assert "secret_ref" not in created.json() and "secret" not in created.json()
    member_h = _principal_in(pg_stack, ws, "member")
    for c in client.get("/connectors", headers=member_h).json():
        assert "secret_ref" not in c and "secret" not in c
        assert set(c.keys()) <= {"id", "type", "name", "config", "status", "has_secret"}


# --------------------------------------------------------- database layer ---


def test_db_blocks_member_insert_even_if_api_bypassed(pg_stack: SimpleNamespace) -> None:
    member = pg_stack.seed_member(role="member")
    sql, params = _insert_connector_sql(member.tenant_id, "m", "ALIAS")
    # An RLS WITH CHECK violation is SQLSTATE 42501 (insufficient_privilege).
    with (
        psycopg.connect(pg_stack.app_libpq) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        _set_ctx(pg_stack, c, member.user_id, member.tenant_id)
        c.execute(sql, params)  # RLS WITH CHECK requires admin/owner -> violation


def test_db_allows_admin_insert(pg_stack: SimpleNamespace) -> None:
    admin = pg_stack.seed_member(role="admin")
    sql, params = _insert_connector_sql(admin.tenant_id, "a", "ALIAS")
    with psycopg.connect(pg_stack.app_libpq) as c:
        _set_ctx(pg_stack, c, admin.user_id, admin.tenant_id)
        c.execute(sql, params)  # admin/owner passes the RLS WITH CHECK
        c.commit()
    # Verify authoritatively as the owner (SET LOCAL GUCs reset at commit).
    with psycopg.connect(pg_stack.owner_libpq) as c:
        n = _one(
            c.execute("SELECT count(*) FROM connectors WHERE tenant_id = %s", (admin.tenant_id,))
        )[0]
    assert n == 1


def test_member_cannot_mutate_or_disable_connector_no_grant(pg_stack: SimpleNamespace) -> None:
    # nlw_app holds neither UPDATE nor DELETE on connectors: config/destination
    # mutation and disable are impossible for ANY app caller (defence in depth;
    # no such endpoint exists either). Prove the privilege is absent.
    admin = pg_stack.seed_member(role="admin")
    sql, params = _insert_connector_sql(admin.tenant_id, "a", "ALIAS")
    with psycopg.connect(pg_stack.app_libpq) as c:
        _set_ctx(pg_stack, c, admin.user_id, admin.tenant_id)
        c.execute(sql, params)
        c.commit()
    with psycopg.connect(pg_stack.owner_libpq) as c:
        cid = _one(c.execute("SELECT id FROM connectors WHERE tenant_id = %s", (admin.tenant_id,)))[
            0
        ]
    for stmt, args in [
        ("UPDATE connectors SET status='disabled' WHERE id=%s", (cid,)),
        ("UPDATE connectors SET config='{\"x\":1}'::jsonb WHERE id=%s", (cid,)),
        ("DELETE FROM connectors WHERE id=%s", (cid,)),
    ]:
        with (
            psycopg.connect(pg_stack.app_libpq) as c,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            _set_ctx(pg_stack, c, admin.user_id, admin.tenant_id)
            c.execute(stmt, args)


def test_cross_tenant_read_and_mutation_fail(pg_stack: SimpleNamespace) -> None:
    a = pg_stack.seed_member(role="admin")
    b = pg_stack.seed_member(role="admin")
    # a's admin creates a connector in tenant A.
    sql, params = _insert_connector_sql(a.tenant_id, "a", "ALIAS")
    with psycopg.connect(pg_stack.app_libpq) as c:
        _set_ctx(pg_stack, c, a.user_id, a.tenant_id)
        c.execute(sql, params)
        c.commit()
    # b (admin of B) cannot see A's connector even with A's tenant GUC forged,
    # and cannot insert into A.
    with psycopg.connect(pg_stack.app_libpq) as c:
        _set_ctx(pg_stack, c, b.user_id, a.tenant_id)  # forged tenant = A
        visible = _one(
            c.execute("SELECT count(*) FROM connectors WHERE tenant_id = %s", (a.tenant_id,))
        )[0]
        c.rollback()
    assert visible == 0
    sql2, params2 = _insert_connector_sql(a.tenant_id, "x", "ALIAS")
    with (
        psycopg.connect(pg_stack.app_libpq) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        _set_ctx(pg_stack, c, b.user_id, a.tenant_id)
        c.execute(sql2, params2)


def test_same_alias_string_isolated_across_tenants(pg_stack: SimpleNamespace) -> None:
    a = pg_stack.seed_member(role="admin")
    b = pg_stack.seed_member(role="admin")
    for principal in (a, b):
        sql, params = _insert_connector_sql(principal.tenant_id, "shared", "SHARED_ALIAS")
        with psycopg.connect(pg_stack.app_libpq) as c:
            _set_ctx(pg_stack, c, principal.user_id, principal.tenant_id)
            c.execute(sql, params)
            c.commit()
    # Each tenant has exactly its own connector with the same alias string; a
    # tenant only ever resolves its own (SecretStore namespaces by tenant hex).
    for principal in (a, b):
        with psycopg.connect(pg_stack.app_libpq) as c:
            _set_ctx(pg_stack, c, principal.user_id, principal.tenant_id)
            rows = c.execute(
                "SELECT tenant_id, secret_ref FROM connectors WHERE name='shared'"
            ).fetchall()
            c.rollback()
        assert rows == [(principal.tenant_id, "SHARED_ALIAS")]


def test_worker_can_still_read_connector_secret_ref(pg_stack: SimpleNamespace) -> None:
    # The worker resolution path must keep reading secret_ref (preserved grant).
    admin = pg_stack.seed_member(role="admin")
    sql, params = _insert_connector_sql(admin.tenant_id, "a", "ALIAS")
    with psycopg.connect(pg_stack.app_libpq) as c:
        _set_ctx(pg_stack, c, admin.user_id, admin.tenant_id)
        c.execute(sql, params)
        c.commit()
    with psycopg.connect(pg_stack.worker_libpq) as c:
        pg_stack.apply_ctx(
            c,
            pg_stack.sign(Purpose.WORKER_EXECUTION, tenant_id=admin.tenant_id, run_id=uuid.uuid4()),
        )
        got = _one(
            c.execute("SELECT secret_ref FROM connectors WHERE tenant_id = %s", (admin.tenant_id,))
        )
        c.rollback()
    assert got[0] == "ALIAS"
