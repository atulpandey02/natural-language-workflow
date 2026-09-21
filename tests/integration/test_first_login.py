"""First-login resolution via the minimal SECURITY DEFINER bootstrap (M11.5 P1A).

``resolve_or_create_user`` returns ONLY the internal ``uuid``: it inserts a
missing identity race-safely and does NOTHING to an existing one. It never
returns or mutates another user's email/``auth_provider_id``. Email
synchronization is a separate self-scoped app operation (see
``test_users_rls`` for the policy-level proof and ``test_identity_api`` for the
end-to-end path).

Distinguish:
- DIRECT function-call guarantee (proved here): a nlw_app caller cannot read or
  change another user's record through the function.
- Deferred: protection against a caller that can FORGE a complete authenticated
  DB context (arbitrary ``app.user_id``) — the signed-GUC item (ADR-003).
"""

import threading
import uuid
from types import SimpleNamespace
from typing import Any

import psycopg
import pytest

pytestmark = pytest.mark.integration


def _one(cur: Any) -> tuple[Any, ...]:
    row = cur.fetchone()
    assert row is not None
    return row  # type: ignore[no-any-return]


def _resolve(url: str, sub: str, email: str) -> uuid.UUID:
    """Call the bootstrap as nlw_app; it returns only the internal uuid."""
    with psycopg.connect(url, autocommit=True) as c:
        return _one(c.execute("SELECT resolve_or_create_user(%s, %s)", (sub, email)))[0]  # type: ignore[no-any-return]


def _updated_at(owner_libpq: str, sub: str) -> Any:
    with psycopg.connect(owner_libpq) as c:
        return _one(c.execute("SELECT updated_at FROM users WHERE auth_provider_id = %s", (sub,)))[
            0
        ]


def test_new_identity_creates_exactly_one_user(pg_stack: SimpleNamespace) -> None:
    uid = _resolve(pg_stack.app_libpq, "sub-new", "new@example.com")
    assert isinstance(uid, uuid.UUID)
    with psycopg.connect(pg_stack.owner_libpq) as c:
        n = _one(c.execute("SELECT count(*) FROM users WHERE auth_provider_id = 'sub-new'"))[0]
    assert n == 1


def test_existing_identity_resolves_to_same_uuid(pg_stack: SimpleNamespace) -> None:
    first = _resolve(pg_stack.app_libpq, "sub-x", "x@example.com")
    again = _resolve(pg_stack.app_libpq, "sub-x", "x@example.com")
    assert first == again


def test_function_returns_only_a_uuid_not_a_record(pg_stack: SimpleNamespace) -> None:
    # The result is a single scalar uuid column — never email/auth_provider_id.
    _resolve(pg_stack.app_libpq, "sub-x", "x@example.com")
    with psycopg.connect(pg_stack.app_libpq, autocommit=True) as c:
        cur = c.execute("SELECT * FROM resolve_or_create_user('sub-x', 'x@example.com')")
        assert cur.description is not None
        colnames = [d.name for d in cur.description]
    assert colnames == ["resolve_or_create_user"]  # one anonymous uuid column


def test_function_does_not_disclose_or_change_another_users_email(
    pg_stack: SimpleNamespace,
) -> None:
    # Seed B, then an attacker supplies B's auth_provider_id with a different
    # email. The function returns only B's uuid and does NOT change B's email.
    _resolve(pg_stack.app_libpq, "sub-B", "b@example.com")
    returned = _resolve(pg_stack.app_libpq, "sub-B", "attacker@evil.com")
    with psycopg.connect(pg_stack.owner_libpq) as c:
        real_id, real_email = _one(
            c.execute("SELECT id, email FROM users WHERE auth_provider_id = 'sub-B'")
        )
    assert returned == real_id  # at most the id is revealed
    assert real_email == "b@example.com"  # email NOT modified, NOT disclosed via a row


def test_function_never_changes_auth_provider_id(pg_stack: SimpleNamespace) -> None:
    uid = _resolve(pg_stack.app_libpq, "sub-x", "x@example.com")
    # Repeated calls (even with a different email) never rewrite the stable id.
    _resolve(pg_stack.app_libpq, "sub-x", "different@example.com")
    with psycopg.connect(pg_stack.owner_libpq) as c:
        rows = c.execute("SELECT id, auth_provider_id FROM users WHERE id = %s", (uid,)).fetchall()
    assert rows == [(uid, "sub-x")]


def test_unchanged_established_login_performs_no_write(pg_stack: SimpleNamespace) -> None:
    _resolve(pg_stack.app_libpq, "sub-x", "x@example.com")
    before = _updated_at(pg_stack.owner_libpq, "sub-x")
    _resolve(pg_stack.app_libpq, "sub-x", "x@example.com")  # established -> no write
    after = _updated_at(pg_stack.owner_libpq, "sub-x")
    assert before == after


def test_concurrent_first_login_produces_one_row(pg_stack: SimpleNamespace) -> None:
    sub = f"race-{uuid.uuid4()}"
    results: list[uuid.UUID] = []
    errors: list[Exception] = []

    def once() -> None:
        try:
            results.append(_resolve(pg_stack.app_libpq, sub, "race@example.com"))
        except Exception as exc:  # pragma: no cover - recorded for assertion
            errors.append(exc)

    threads = [threading.Thread(target=once) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert len(set(results)) == 1  # all callers converged on one id
    with psycopg.connect(pg_stack.owner_libpq) as c:
        n = _one(c.execute("SELECT count(*) FROM users WHERE auth_provider_id = %s", (sub,)))[0]
    assert n == 1


def test_blank_identity_fails_closed(pg_stack: SimpleNamespace) -> None:
    with psycopg.connect(pg_stack.app_libpq, autocommit=True) as c:
        for bad in [("", "x@example.com"), ("sub", "")]:
            with pytest.raises(psycopg.errors.RaiseException):
                c.execute("SELECT resolve_or_create_user(%s, %s)", bad).fetchone()
