"""Adversarial RLS/grant tests for the ``users`` identity table (M11.5 P1A).

Before P1A, ``nlw_app`` had broad SELECT/INSERT/UPDATE on ``users`` with no RLS,
so the runtime role could enumerate every identity and rewrite unrelated identity
mappings (including the stable ``auth_provider_id``). These tests drive raw SQL as
the real runtime login roles and prove the boundary now holds.
"""

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


def _seed_user(owner_libpq: str, sub: str, email: str) -> uuid.UUID:
    uid = uuid.uuid4()
    with psycopg.connect(owner_libpq, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s)",
            (uid, sub, email),
        )
    return uid


def test_user_can_read_only_their_own_row(pg_stack: SimpleNamespace) -> None:
    a = _seed_user(pg_stack.owner_libpq, "sub-A", "a@example.com")
    _seed_user(pg_stack.owner_libpq, "sub-B", "b@example.com")
    with psycopg.connect(pg_stack.app_libpq) as c:
        c.execute("SELECT set_config('app.user_id', %s, true)", (str(a),))
        rows = c.execute("SELECT id FROM users").fetchall()
        c.rollback()
    assert rows == [(a,)]


def test_user_cannot_select_another_user(pg_stack: SimpleNamespace) -> None:
    a = _seed_user(pg_stack.owner_libpq, "sub-A", "a@example.com")
    b = _seed_user(pg_stack.owner_libpq, "sub-B", "b@example.com")
    with psycopg.connect(pg_stack.app_libpq) as c:
        c.execute("SELECT set_config('app.user_id', %s, true)", (str(a),))
        got = _one(c.execute("SELECT count(*) FROM users WHERE id = %s", (b,)))
        c.rollback()
    assert got[0] == 0


def test_user_cannot_enumerate_all_emails(pg_stack: SimpleNamespace) -> None:
    a = _seed_user(pg_stack.owner_libpq, "sub-A", "a@example.com")
    for i in range(5):
        _seed_user(pg_stack.owner_libpq, f"sub-{i}", f"user{i}@example.com")
    with psycopg.connect(pg_stack.app_libpq) as c:
        c.execute("SELECT set_config('app.user_id', %s, true)", (str(a),))
        emails = c.execute("SELECT email FROM users").fetchall()
        c.rollback()
    assert emails == [("a@example.com",)]  # only self, never the platform roster


def test_user_cannot_update_another_users_email(pg_stack: SimpleNamespace) -> None:
    a = _seed_user(pg_stack.owner_libpq, "sub-A", "a@example.com")
    b = _seed_user(pg_stack.owner_libpq, "sub-B", "b@example.com")
    # nlw_app holds no UPDATE grant at all -> fails at privilege level (stronger
    # than an RLS "0 rows updated"): defence in depth.
    with (
        psycopg.connect(pg_stack.app_libpq) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute("SELECT set_config('app.user_id', %s, true)", (str(a),))
        c.execute("UPDATE users SET email = 'hijack@evil.com' WHERE id = %s", (b,))
    # The row is unchanged.
    with psycopg.connect(pg_stack.owner_libpq) as c:
        email = _one(c.execute("SELECT email FROM users WHERE id = %s", (b,)))[0]
    assert email == "b@example.com"


def test_user_cannot_modify_another_users_auth_provider_id(pg_stack: SimpleNamespace) -> None:
    a = _seed_user(pg_stack.owner_libpq, "sub-A", "a@example.com")
    b = _seed_user(pg_stack.owner_libpq, "sub-B", "b@example.com")
    with (
        psycopg.connect(pg_stack.app_libpq) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute("SELECT set_config('app.user_id', %s, true)", (str(a),))
        c.execute("UPDATE users SET auth_provider_id = 'stolen' WHERE id = %s", (b,))
    with psycopg.connect(pg_stack.owner_libpq) as c:
        sub = _one(c.execute("SELECT auth_provider_id FROM users WHERE id = %s", (b,)))[0]
    assert sub == "sub-B"


def test_user_cannot_modify_their_own_auth_provider_id(pg_stack: SimpleNamespace) -> None:
    a = _seed_user(pg_stack.owner_libpq, "sub-A", "a@example.com")
    with (
        psycopg.connect(pg_stack.app_libpq) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute("SELECT set_config('app.user_id', %s, true)", (str(a),))
        c.execute("UPDATE users SET auth_provider_id = 'renamed' WHERE id = %s", (a,))
    with psycopg.connect(pg_stack.owner_libpq) as c:
        sub = _one(c.execute("SELECT auth_provider_id FROM users WHERE id = %s", (a,)))[0]
    assert sub == "sub-A"  # stable identity is immutable to the app role


def test_absent_context_fails_closed(pg_stack: SimpleNamespace) -> None:
    _seed_user(pg_stack.owner_libpq, "sub-A", "a@example.com")
    with psycopg.connect(pg_stack.app_libpq) as c:
        # No app.user_id set -> NULLIF(...,'')::uuid is NULL -> deny.
        got = _one(c.execute("SELECT count(*) FROM users"))
        c.rollback()
    assert got[0] == 0


def test_user_cannot_insert_arbitrary_user(pg_stack: SimpleNamespace) -> None:
    a = _seed_user(pg_stack.owner_libpq, "sub-A", "a@example.com")
    with (
        psycopg.connect(pg_stack.app_libpq) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute("SELECT set_config('app.user_id', %s, true)", (str(a),))
        c.execute(
            "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s)",
            (uuid.uuid4(), "forged", "forged@evil.com"),
        )


def test_worker_cannot_enumerate_users(pg_stack: SimpleNamespace) -> None:
    _seed_user(pg_stack.owner_libpq, "sub-A", "a@example.com")
    # nlw_worker has no grant on users at all.
    with (
        psycopg.connect(pg_stack.worker_libpq) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute("SELECT id, email FROM users")


def test_scheduler_cannot_enumerate_users(pg_stack: SimpleNamespace) -> None:
    _seed_user(pg_stack.owner_libpq, "sub-A", "a@example.com")
    with (
        psycopg.connect(pg_stack.scheduler_libpq) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute("SELECT id, email FROM users")


def test_public_cannot_execute_bootstrap_helper(pg_stack: SimpleNamespace) -> None:
    # Neither worker nor scheduler nor PUBLIC may execute the bootstrap function.
    with psycopg.connect(pg_stack.owner_libpq) as c:
        for role in ("public", "nlw_worker", "nlw_scheduler"):
            allowed = _one(
                c.execute(
                    "SELECT has_function_privilege(%s, "
                    "'resolve_or_create_user(text,text)', 'EXECUTE')",
                    (role,),
                )
            )[0]
            assert allowed is False, f"{role} must not execute the bootstrap helper"
        app_allowed = _one(
            c.execute(
                "SELECT has_function_privilege(%s, 'resolve_or_create_user(text,text)', 'EXECUTE')",
                ("nlw_app",),
            )
        )[0]
    assert app_allowed is True


def test_worker_and_scheduler_cannot_execute_bootstrap(pg_stack: SimpleNamespace) -> None:
    _seed_user(pg_stack.owner_libpq, "sub-A", "a@example.com")
    for url in (pg_stack.worker_libpq, pg_stack.scheduler_libpq):
        with psycopg.connect(url) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT id FROM resolve_or_create_user('x','x@example.com')")
