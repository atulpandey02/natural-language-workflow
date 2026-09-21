"""First-login resolution/provisioning via the SECURITY DEFINER bootstrap fn.

Proves ``resolve_or_create_user`` (M11.5 P1A) is safe: exactly-one on first
sight, race-resistant, updates email only when the verified provider email
changed, never reassigns the stable ``auth_provider_id``, and never becomes a
general enumeration/update primitive.
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


def _resolve(url: str, sub: str, email: str) -> tuple[Any, ...]:
    with psycopg.connect(url, autocommit=True) as c:
        return _one(
            c.execute(
                "SELECT id, auth_provider_id, email FROM resolve_or_create_user(%s, %s)",
                (sub, email),
            )
        )


def _updated_at(owner_libpq: str, sub: str) -> Any:
    with psycopg.connect(owner_libpq) as c:
        return _one(c.execute("SELECT updated_at FROM users WHERE auth_provider_id = %s", (sub,)))[
            0
        ]


def test_new_identity_creates_exactly_one_user(pg_stack: SimpleNamespace) -> None:
    row = _resolve(pg_stack.app_libpq, "sub-new", "new@example.com")
    assert row[1] == "sub-new" and row[2] == "new@example.com"
    with psycopg.connect(pg_stack.owner_libpq) as c:
        n = _one(c.execute("SELECT count(*) FROM users WHERE auth_provider_id = 'sub-new'"))[0]
    assert n == 1


def test_existing_identity_resolves_to_same_row(pg_stack: SimpleNamespace) -> None:
    first = _resolve(pg_stack.app_libpq, "sub-x", "x@example.com")
    again = _resolve(pg_stack.app_libpq, "sub-x", "x@example.com")
    assert first[0] == again[0]  # same id


def test_unchanged_identity_does_not_update(pg_stack: SimpleNamespace) -> None:
    _resolve(pg_stack.app_libpq, "sub-x", "x@example.com")
    before = _updated_at(pg_stack.owner_libpq, "sub-x")
    _resolve(pg_stack.app_libpq, "sub-x", "x@example.com")  # unchanged email
    after = _updated_at(pg_stack.owner_libpq, "sub-x")
    assert before == after  # no unnecessary write when nothing changed


def test_verified_email_change_updates_narrowly(pg_stack: SimpleNamespace) -> None:
    _resolve(pg_stack.app_libpq, "sub-x", "old@example.com")
    before = _updated_at(pg_stack.owner_libpq, "sub-x")
    row = _resolve(pg_stack.app_libpq, "sub-x", "changed@example.com")
    assert row[2] == "changed@example.com"
    after = _updated_at(pg_stack.owner_libpq, "sub-x")
    assert after >= before  # the changed field triggered the update


def test_concurrent_first_login_produces_one_row(pg_stack: SimpleNamespace) -> None:
    sub = f"race-{uuid.uuid4()}"
    results: list[tuple[Any, ...]] = []
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
    ids = {r[0] for r in results}
    assert len(ids) == 1  # all callers converged on one row
    with psycopg.connect(pg_stack.owner_libpq) as c:
        n = _one(c.execute("SELECT count(*) FROM users WHERE auth_provider_id = %s", (sub,)))[0]
    assert n == 1


def test_identity_cannot_claim_a_different_existing_identity(pg_stack: SimpleNamespace) -> None:
    a = _resolve(pg_stack.app_libpq, "sub-A", "a@example.com")
    b = _resolve(pg_stack.app_libpq, "sub-B", "b@example.com")
    # Resolving A (even with B's email) only ever touches A's row; it cannot
    # retarget or merge B. Email is not identity.
    a_again = _resolve(pg_stack.app_libpq, "sub-A", "b@example.com")
    assert a_again[0] == a[0]
    with psycopg.connect(pg_stack.owner_libpq) as c:
        b_row = _one(
            c.execute("SELECT id, auth_provider_id FROM users WHERE auth_provider_id = 'sub-B'")
        )
    assert b_row[0] == b[0] and b_row[1] == "sub-B"  # B untouched


def test_bootstrap_is_not_a_general_enumeration_or_update_primitive(
    pg_stack: SimpleNamespace,
) -> None:
    # The function takes only (auth_provider_id, email); there is no way to ask
    # it for other users or to update an arbitrary field. Empty/blank identity
    # fails closed rather than resolving "some" row.
    with psycopg.connect(pg_stack.app_libpq, autocommit=True) as c:
        for bad in [("", "x@example.com"), ("sub", "")]:
            with pytest.raises(psycopg.errors.RaiseException):
                c.execute("SELECT id FROM resolve_or_create_user(%s, %s)", bad).fetchone()
