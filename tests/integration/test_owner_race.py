"""Owner-preservation correctness under concurrency (M11.5 P3A+ section B).

Membership mutation is FUNCTION-ONLY: nlw_app has no direct UPDATE/DELETE on
``memberships``; every change goes through ``manage_membership``, which serializes
on the workspace identity (transaction-scoped advisory lock taken FIRST) and then
re-reads ownership under the lock. This makes the ">= 1 owner" invariant correct by
construction — not merely trigger-guarded — with no READ COMMITTED write skew.

These tests drive two real connections with a ``Barrier`` so both calls contend for
the same workspace at once, and assert the deterministic outcome: at most one of a
pair of owner-losing mutations commits, and an owner always remains. They also prove
direct mutation is denied, admins cannot touch owner rows, the final owner cannot be
removed, and cross-tenant mutation is refused.
"""

import threading
import uuid
from types import SimpleNamespace

import psycopg
import pytest

from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration


def _seed_ws(owner_libpq: str) -> uuid.UUID:
    tid = uuid.uuid4()
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute("INSERT INTO workspaces (id, name, slug) VALUES (%s,'ws',%s)", (tid, f"w-{tid}"))
    return tid


def _seed_user(owner_libpq: str, tid: uuid.UUID, role: str) -> uuid.UUID:
    uid = uuid.uuid4()
    with psycopg.connect(owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO users (id, auth_provider_id, email) VALUES (%s,%s,%s)",
            (uid, f"sub-{uid}", f"{uid}@x.com"),
        )
        c.execute(
            "INSERT INTO memberships (id, user_id, workspace_id, role) VALUES (%s,%s,%s,%s)",
            (uuid.uuid4(), uid, tid, role),
        )
    return uid


def _owner_count(owner_libpq: str, tid: uuid.UUID) -> int:
    with psycopg.connect(owner_libpq) as c:
        row = c.execute(
            "SELECT count(*) FROM memberships WHERE workspace_id=%s AND role='owner'", (tid,)
        ).fetchone()
    return int(row[0]) if row else -1


def _run_pair(
    pg_stack: SimpleNamespace,
    tid: uuid.UUID,
    op_a: tuple[uuid.UUID, str, str | None, uuid.UUID],
    op_b: tuple[uuid.UUID, str, str | None, uuid.UUID],
) -> list[str]:
    """Run two manage_membership calls concurrently, released together by a barrier.
    Each op is (actor, action, new_role, target). Returns ['ok'|'fail', ...]."""
    results: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(2)

    def worker(actor: uuid.UUID, action: str, new_role: str | None, target: uuid.UUID) -> None:
        with psycopg.connect(pg_stack.app_libpq, autocommit=False) as conn:
            # SIGNED api_request context for the actor (transaction-local).
            pg_stack.apply_ctx(
                conn, pg_stack.sign(Purpose.API_REQUEST, user_id=actor, tenant_id=tid)
            )
            barrier.wait()
            try:
                conn.execute(
                    "SELECT manage_membership(%s,%s,%s,%s)", (tid, target, action, new_role)
                )
                conn.commit()
                outcome = "ok"
            except Exception:
                conn.rollback()
                outcome = "fail"
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=worker, args=op) for op in (op_a, op_b)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return sorted(results)


# --- B1: two owners concurrently remove each other -> exactly one, owner remains ---
def test_concurrent_mutual_owner_removal(pg_stack: SimpleNamespace) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    a = _seed_user(pg_stack.owner_libpq, tid, "owner")
    b = _seed_user(pg_stack.owner_libpq, tid, "owner")
    results = _run_pair(pg_stack, tid, (a, "remove", None, b), (b, "remove", None, a))
    assert results == ["fail", "ok"]  # deterministic: exactly one commits
    assert _owner_count(pg_stack.owner_libpq, tid) == 1


# --- B2: two owners concurrently demote each other -> exactly one, owner remains ---
def test_concurrent_mutual_owner_demotion(pg_stack: SimpleNamespace) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    a = _seed_user(pg_stack.owner_libpq, tid, "owner")
    b = _seed_user(pg_stack.owner_libpq, tid, "owner")
    results = _run_pair(pg_stack, tid, (a, "set_role", "member", b), (b, "set_role", "member", a))
    assert results == ["fail", "ok"]
    assert _owner_count(pg_stack.owner_libpq, tid) == 1


# --- B3: remove-vs-demote race on the last two owners -> owner remains ---
def test_delete_vs_demote_race(pg_stack: SimpleNamespace) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    a = _seed_user(pg_stack.owner_libpq, tid, "owner")
    b = _seed_user(pg_stack.owner_libpq, tid, "owner")
    # A removes B; B demotes A. Only one can win; an owner always survives.
    results = _run_pair(pg_stack, tid, (a, "remove", None, b), (b, "set_role", "member", a))
    assert results == ["fail", "ok"]
    assert _owner_count(pg_stack.owner_libpq, tid) == 1


# --- B4: addition racing removal -> never zero owners ---
def test_addition_racing_removal_keeps_owner(pg_stack: SimpleNamespace) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    a = _seed_user(pg_stack.owner_libpq, tid, "owner")
    b = _seed_user(pg_stack.owner_libpq, tid, "admin")
    # A promotes B to owner; concurrently the OTHER owner-removal cannot run because
    # there is only one owner (A) — A demoting itself while promoting B must still
    # leave an owner. Promote B, then (racing) demote A: serialized, owner remains.
    results = _run_pair(pg_stack, tid, (a, "set_role", "owner", b), (a, "set_role", "member", a))
    # Promotion of B always succeeds; the self-demotion of A succeeds only after B is
    # an owner (serialized). Either way an owner remains and both may commit.
    assert "ok" in results
    assert _owner_count(pg_stack.owner_libpq, tid) >= 1


# --- B5: direct table mutation by nlw_app is denied (function is the only path) ---
def test_direct_membership_mutation_denied(pg_stack: SimpleNamespace) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    _a = _seed_user(pg_stack.owner_libpq, tid, "owner")
    victim = _seed_user(pg_stack.owner_libpq, tid, "member")
    for sql in (
        "UPDATE memberships SET role='owner' WHERE workspace_id=%s AND user_id=%s",
        "DELETE FROM memberships WHERE workspace_id=%s AND user_id=%s",
    ):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            pg_stack.run_as(
                pg_stack.app_libpq,
                Purpose.API_REQUEST,
                sql,
                (tid, victim),
                user_id=_a,
                tenant_id=tid,
            )


# --- B6: an admin cannot mutate an owner row (owner-only) ---
def test_admin_cannot_mutate_owner(pg_stack: SimpleNamespace) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    owner = _seed_user(pg_stack.owner_libpq, tid, "owner")
    admin = _seed_user(pg_stack.owner_libpq, tid, "admin")
    # Admin demoting the owner / promoting anyone to owner -> not authorized.
    for target, role in ((owner, "member"), (admin, "owner")):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            pg_stack.run_as(
                pg_stack.app_libpq,
                Purpose.API_REQUEST,
                "SELECT manage_membership(%s,%s,'set_role',%s)",
                (tid, target, role),
                user_id=admin,
                tenant_id=tid,
            )
    assert _owner_count(pg_stack.owner_libpq, tid) == 1


# --- B7: the final owner cannot remove/demote itself ---
def test_final_owner_cannot_self_remove(pg_stack: SimpleNamespace) -> None:
    tid = _seed_ws(pg_stack.owner_libpq)
    owner = _seed_user(pg_stack.owner_libpq, tid, "owner")
    for sql in (
        "SELECT manage_membership(%s,%s,'remove',NULL)",
        "SELECT manage_membership(%s,%s,'set_role','member')",
    ):
        with pytest.raises(psycopg.errors.CheckViolation):
            pg_stack.run_as(
                pg_stack.app_libpq,
                Purpose.API_REQUEST,
                sql,
                (tid, owner),
                user_id=owner,
                tenant_id=tid,
            )
    assert _owner_count(pg_stack.owner_libpq, tid) == 1


# --- B8: cross-tenant mutation is refused (actor not a member of the target ws) ---
def test_cross_tenant_mutation_denied(pg_stack: SimpleNamespace) -> None:
    tid_a = _seed_ws(pg_stack.owner_libpq)
    victim = _seed_user(pg_stack.owner_libpq, tid_a, "member")
    tid_b = _seed_ws(pg_stack.owner_libpq)
    outsider = _seed_user(pg_stack.owner_libpq, tid_b, "owner")
    # Owner of B presents a SIGNED B context but targets A's workspace/member:
    # manage_membership now also cross-checks the signed tenant against the arg.
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        pg_stack.run_as(
            pg_stack.app_libpq,
            Purpose.API_REQUEST,
            "SELECT manage_membership(%s,%s,'remove',NULL)",
            (tid_a, victim),
            user_id=outsider,
            tenant_id=tid_b,
        )
    with psycopg.connect(pg_stack.owner_libpq) as c:
        row = c.execute(
            "SELECT count(*) FROM memberships WHERE workspace_id=%s AND user_id=%s",
            (tid_a, victim),
        ).fetchone()
    assert row is not None and row[0] == 1  # untouched
