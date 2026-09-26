"""Invitation & membership failures must be classified PRECISELY (final audit).

Expected business outcomes keep their intended, non-enumerating responses;
infrastructure failures (connection loss, unrelated integrity/permission errors,
unexpected exceptions) become sanitized 5xx responses — never a misleading
"duplicate invitation" / "workspace must keep an owner" / "invitation is not
valid". No response ever carries SQL, constraint internals, connection strings,
tokens, email addresses or driver text, and nothing partial is committed.

Real PostgreSQL (pg_stack) + the API. Infrastructure faults are injected at the
repository boundary (controlled fault injection — no real outage needed).
"""

import time
import uuid
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any

import jwt
import psycopg
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

import nlw.api.routers.members as members_mod
from nlw.api.app import create_app
from nlw.db.repositories import AuditRepository, InvitationRepository, MembershipRepository

pytestmark = pytest.mark.integration

# Same seeded-auth helpers as test_membership_invitations (tests are not a package).
_ISSUER = "https://proj.supabase.co/auth/v1"
_AUD = "authenticated"
_SECRET = "dev-secret-for-tests-32bytes-min-length"


def _auth(sub: str, email: str) -> dict[str, str]:
    token = jwt.encode(
        {"iss": _ISSUER, "aud": _AUD, "exp": int(time.time()) + 300, "sub": sub, "email": email},
        _SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def _make_owner(client: TestClient, sub: str, email: str) -> tuple[dict[str, str], uuid.UUID]:
    h = _auth(sub, email)
    r = client.post("/workspaces", headers=h, json={"name": f"ws-{sub}"})
    assert r.status_code == 201, r.text
    tid = uuid.UUID(r.json()["id"])
    return {**h, "X-Workspace-Id": str(tid)}, tid


def _invite(
    client: TestClient, owner_h: dict[str, str], email: str, role: str = "member"
) -> dict[str, Any]:
    r = client.post("/invitations", headers=owner_h, json={"email": email, "role": role})
    assert r.status_code == 201, r.text
    result: dict[str, Any] = r.json()
    return result


def _user_id(owner_libpq: str, sub: str) -> uuid.UUID:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute("SELECT id FROM users WHERE auth_provider_id=%s", (sub,)).fetchone()
    assert row is not None
    return uuid.UUID(str(row[0]))


_LEAK_MARKERS = (
    "postgres",
    "psycopg",
    "sqlalchemy",
    "connection",
    "constraint",
    "uq_invitation",
    "manage_membership",
    "accept_workspace_invitation",
    "INSERT",
    "SELECT",
    "password",
    "@x.com",
    "Traceback",
)


class _FakeDriverError(Exception):
    """A DB-API ``orig`` carrying only the attributes the classifier may read."""

    def __init__(self, sqlstate: str | None, constraint: str | None = None) -> None:
        super().__init__("driver text that must never be echoed: password=hunter2 host=db")
        self.sqlstate = sqlstate
        self.diag = SimpleNamespace(constraint_name=constraint)


def _integrity(sqlstate: str, constraint: str | None) -> IntegrityError:
    return IntegrityError(
        "INSERT INTO secret_table ...", {}, _FakeDriverError(sqlstate, constraint)
    )


def _dbapi(sqlstate: str) -> DBAPIError:
    return DBAPIError("SELECT secret_fn()", {}, _FakeDriverError(sqlstate))


def _connection_lost() -> OperationalError:
    return OperationalError("SELECT 1", {}, _FakeDriverError(None))


def _raiser(exc: BaseException) -> Callable[..., Any]:
    async def _boom(*args: object, **kwargs: object) -> None:
        raise exc

    return _boom


@pytest.fixture
def client(pg_stack: SimpleNamespace) -> Iterator[TestClient]:
    # 5xx paths return the opaque handler response instead of re-raising in-test.
    with TestClient(create_app(pg_stack.settings), raise_server_exceptions=False) as c:
        yield c


def _assert_sanitized(body: str) -> None:
    lowered = body.lower()
    for marker in _LEAK_MARKERS:
        assert marker.lower() not in lowered, f"response leaks {marker!r}: {body}"


def _count(owner_libpq: str, sql: str, *params: object) -> int:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute(sql, params).fetchone()
    assert row is not None
    return int(row[0])


# --- invitation creation ---------------------------------------------------------


def test_real_duplicate_pending_invitation_is_409(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    owner_h, _tid = _make_owner(client, "cls1", "cls1@x.com")
    _invite(client, owner_h, "dup-cls1@x.com")
    r = client.post(
        "/invitations", headers=owner_h, json={"email": "dup-cls1@x.com", "role": "member"}
    )
    assert r.status_code == 409, r.text
    assert r.json()["error"]["message"] == "a pending invitation for this email already exists"
    _assert_sanitized(r.text)


def test_unrelated_integrity_failure_is_not_a_duplicate(
    client: TestClient, pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Injected at the session FLUSH (where the repository used to swallow every
    error and report None -> "duplicate"), so the historical misclassification is
    exercised on the real code path."""
    owner_h, tid = _make_owner(client, "cls2", "cls2@x.com")
    for exc in (
        _integrity("23505", "uq_invitation_token_hash"),  # a DIFFERENT unique index
        _integrity("23503", "fk_something"),  # foreign-key failure
        _integrity("23514", "ck_invitation_role"),  # check failure
    ):
        monkeypatch.setattr(AsyncSession, "flush", _raiser(exc))
        r = client.post(
            "/invitations", headers=owner_h, json={"email": "new@x.com", "role": "member"}
        )
        assert r.status_code == 500, r.text
        assert r.json()["error"] == {"code": "internal_error", "message": "internal server error"}
        _assert_sanitized(r.text)
    assert (
        _count(
            pg_stack.owner_libpq,
            "SELECT count(*) FROM workspace_invitations WHERE tenant_id=%s",
            tid,
        )
        == 0
    )


def test_connection_failure_during_invitation_create_is_503(
    client: TestClient, pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner_h, tid = _make_owner(client, "cls3", "cls3@x.com")
    for exc in (_connection_lost(), _dbapi("08006"), _dbapi("57P01"), _dbapi("53300")):
        # At the flush (historically swallowed into "duplicate").
        monkeypatch.setattr(AsyncSession, "flush", _raiser(exc))
        r = client.post(
            "/invitations", headers=owner_h, json={"email": "new@x.com", "role": "member"}
        )
        assert r.status_code == 503, r.text
        assert r.json()["error"]["code"] == "service_unavailable"
        assert r.headers.get("retry-after")
        _assert_sanitized(r.text)
    assert (
        _count(
            pg_stack.owner_libpq,
            "SELECT count(*) FROM workspace_invitations WHERE tenant_id=%s",
            tid,
        )
        == 0
    )


def test_policy_denial_during_invitation_create_is_403(
    client: TestClient, pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner_h, _tid = _make_owner(client, "cls4", "cls4@x.com")
    monkeypatch.setattr(InvitationRepository, "create", _raiser(_dbapi("42501")))
    r = client.post("/invitations", headers=owner_h, json={"email": "new@x.com", "role": "member"})
    assert r.status_code == 403, r.text
    _assert_sanitized(r.text)


def test_invitation_create_is_atomic_with_its_audit_event(
    client: TestClient, pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The invitation row is inserted BEFORE the audit event; if the audit write
    fails, the whole transaction rolls back — no invitation without its event."""
    owner_h, tid = _make_owner(client, "cls5", "cls5@x.com")
    monkeypatch.setattr(AuditRepository, "emit", _raiser(_connection_lost()))
    r = client.post(
        "/invitations", headers=owner_h, json={"email": "atomic@x.com", "role": "member"}
    )
    assert r.status_code == 503, r.text
    assert (
        _count(
            pg_stack.owner_libpq,
            "SELECT count(*) FROM workspace_invitations WHERE tenant_id=%s",
            tid,
        )
        == 0
    )
    assert (
        _count(
            pg_stack.owner_libpq,
            "SELECT count(*) FROM authz_audit_events "
            "WHERE tenant_id=%s AND event_type='invitation.created'",
            tid,
        )
        == 0
    )


# --- membership management -------------------------------------------------------


def test_recognized_authorization_denial_is_403(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    """An admin touching an OWNER row is refused by manage_membership (42501)."""
    owner_h, tid = _make_owner(client, "cls6", "cls6@x.com")
    inv = _invite(client, owner_h, "adm-cls6@x.com", "admin")
    ah = _auth("adm-cls6", "adm-cls6@x.com")
    assert (
        client.post("/invitations/accept", headers=ah, json={"token": inv["token"]}).status_code
        == 200
    )
    owner_uid = _user_id(pg_stack.owner_libpq, "cls6")
    admin_ctx = {**ah, "X-Workspace-Id": str(tid)}
    r = client.patch(f"/members/{owner_uid}", headers=admin_ctx, json={"role": "member"})
    assert r.status_code == 403, r.text
    assert r.json()["error"]["message"] == "role change not allowed"
    _assert_sanitized(r.text)
    r2 = client.delete(f"/members/{owner_uid}", headers=admin_ctx)
    assert r2.status_code == 403, r2.text


def test_recognized_final_owner_protection_is_409(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    owner_h, _tid = _make_owner(client, "cls7", "cls7@x.com")
    uid = _user_id(pg_stack.owner_libpq, "cls7")
    r = client.patch(f"/members/{uid}", headers=owner_h, json={"role": "member"})
    assert r.status_code == 409, r.text
    assert r.json()["error"]["message"] == "role change not allowed (workspace must keep an owner)"
    _assert_sanitized(r.text)


def test_unexpected_membership_failures_are_sanitized_5xx(
    client: TestClient, pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner_h, tid = _make_owner(client, "cls8", "cls8@x.com")
    inv = _invite(client, owner_h, "mem-cls8@x.com")
    mh = _auth("mem-cls8", "mem-cls8@x.com")
    assert (
        client.post("/invitations/accept", headers=mh, json={"token": inv["token"]}).status_code
        == 200
    )
    target = _user_id(pg_stack.owner_libpq, "mem-cls8")

    cases: list[tuple[BaseException, int]] = [
        (_connection_lost(), 503),
        (_dbapi("08006"), 503),
        (_dbapi("40P01"), 503),  # deadlock: transient, retryable
        (_dbapi("XX000"), 500),  # internal error: unexpected
        (RuntimeError("bug"), 500),
        (HTTPException(503, "signed database context unavailable"), 503),
    ]
    for exc, expected in cases:
        monkeypatch.setattr(MembershipRepository, "set_role", _raiser(exc))
        monkeypatch.setattr(MembershipRepository, "remove", _raiser(exc))
        r = client.patch(f"/members/{target}", headers=owner_h, json={"role": "admin"})
        assert r.status_code == expected, (type(exc).__name__, r.text)
        assert "owner" not in r.text  # never the owner-retention business message
        _assert_sanitized(r.text)
        r2 = client.delete(f"/members/{target}", headers=owner_h)
        assert r2.status_code == expected, (type(exc).__name__, r2.text)
    # Nothing changed.
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT role FROM memberships WHERE workspace_id=%s AND user_id=%s", (tid, target)
        ).fetchone()
    assert row is not None and row[0] == "member"


# --- invitation acceptance -------------------------------------------------------


def test_invalid_token_responses_remain_uniform(
    client: TestClient, pg_stack: SimpleNamespace
) -> None:
    """Expired, used, wrong-user and unknown tokens are indistinguishable (no
    enumeration oracle) — and remain 400, never a 5xx."""
    owner_h, _tid = _make_owner(client, "cls9", "cls9@x.com")
    expired = _invite(client, owner_h, "exp-cls9@x.com")
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        c.execute(
            "UPDATE workspace_invitations SET expires_at = now() - interval '1 hour' WHERE id=%s",
            (expired["id"],),
        )
    used = _invite(client, owner_h, "used-cls9@x.com")
    uh = _auth("used-cls9", "used-cls9@x.com")
    assert (
        client.post("/invitations/accept", headers=uh, json={"token": used["token"]}).status_code
        == 200
    )
    wrong = _invite(client, owner_h, "right-cls9@x.com")

    bodies = {
        "expired": client.post(
            "/invitations/accept",
            headers=_auth("e9", "exp-cls9@x.com"),
            json={"token": expired["token"]},
        ),
        "used": client.post("/invitations/accept", headers=uh, json={"token": used["token"]}),
        "wrong-user": client.post(
            "/invitations/accept",
            headers=_auth("w9", "other-cls9@x.com"),
            json={"token": wrong["token"]},
        ),
        "unknown": client.post(
            "/invitations/accept", headers=_auth("u9", "u9@x.com"), json={"token": uuid.uuid4().hex}
        ),
    }
    for name, r in bodies.items():
        assert r.status_code == 400, (name, r.text)
        _assert_sanitized(r.text)
    assert len({r.text for r in bodies.values()}) == 1  # byte-identical bodies


def test_infrastructure_failure_during_accept_is_not_an_invalid_invitation(
    client: TestClient, pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner_h, tid = _make_owner(client, "cls10", "cls10@x.com")
    inv = _invite(client, owner_h, "acc-cls10@x.com")
    ih = _auth("acc-cls10", "acc-cls10@x.com")
    for exc, expected in (
        (_connection_lost(), 503),
        (_dbapi("57014"), 503),  # statement timeout: transient
        (_dbapi("P0001"), 500),  # the function's own guard tripped: a bug, not a bad token
        (RuntimeError("bug"), 500),
    ):
        monkeypatch.setattr(InvitationRepository, "accept", _raiser(exc))
        r = client.post("/invitations/accept", headers=ih, json={"token": inv["token"]})
        assert r.status_code == expected, (type(exc).__name__, r.text)
        assert "invitation is not valid" not in r.text
        _assert_sanitized(r.text)
    # The invitation is still pending and usable: nothing was consumed.
    monkeypatch.undo()
    assert (
        _count(pg_stack.owner_libpq, "SELECT count(*) FROM memberships WHERE workspace_id=%s", tid)
        == 1
    )
    ok = client.post("/invitations/accept", headers=ih, json={"token": inv["token"]})
    assert ok.status_code == 200, ok.text


def test_accept_rolls_back_membership_and_audit_on_a_later_failure(
    client: TestClient, pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The SECURITY DEFINER accept inserts the membership + audit rows inside the
    request transaction; a failure after it must roll ALL of it back."""
    owner_h, tid = _make_owner(client, "cls11", "cls11@x.com")
    inv = _invite(client, owner_h, "atomic-cls11@x.com")
    ih = _auth("atomic-cls11", "atomic-cls11@x.com")
    monkeypatch.setattr(MembershipRepository, "get", _raiser(_connection_lost()))
    r = client.post("/invitations/accept", headers=ih, json={"token": inv["token"]})
    assert r.status_code == 503, r.text
    monkeypatch.undo()
    assert (
        _count(pg_stack.owner_libpq, "SELECT count(*) FROM memberships WHERE workspace_id=%s", tid)
        == 1
    )
    assert (
        _count(
            pg_stack.owner_libpq,
            "SELECT count(*) FROM authz_audit_events WHERE tenant_id=%s "
            "AND event_type IN ('membership.added','invitation.accepted')",
            tid,
        )
        == 0
    )
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT status FROM workspace_invitations WHERE id=%s", (inv["id"],)
        ).fetchone()
    assert row is not None and row[0] == "pending"  # still single-use-able


def test_members_module_has_no_catch_all_business_translation() -> None:
    """Guard against regression: no bare ``except Exception`` may translate an
    arbitrary failure into a business response in the members router."""
    import inspect

    src = inspect.getsource(members_mod)
    assert "except Exception" not in src
