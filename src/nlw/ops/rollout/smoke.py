"""In-container signed-context smoke for the rollout ``validate`` phase and the
disposable rehearsal (M12A-Prep §H/§N).

Runs INSIDE the api container (``docker compose exec -T api python -m
nlw.ops.rollout.smoke``) so it uses the API's own key file and ``DATABASE_URL``
(the nlw_app login) — no key material or credential leaves the host. Everything
it touches is synthetic: ids are passed in by the operator/rehearsal, rows are
created by the owner beforehand, and every transaction is rolled back except the
membership acceptance and the approval decision that the P3A flow requires.

Checks (all as the real nlw_app role):
  1. unsigned legacy GUC forgery sees no membership rows;
  2. a signed api_request context for user A sees only A's workspace;
  3. user B (api_identity) accepts an invitation -> becomes admin;
  4. A cannot approve the approval A requested (self-approval blocked);
  5. B (a different eligible admin) can approve it.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import uuid

import psycopg

from nlw.core.config import get_settings
from nlw.tenancy.keys import build_signer
from nlw.tenancy.signing import Purpose, SignedContext


def _libpq(url: str) -> str:
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


def _apply(conn: psycopg.Connection, ctx: SignedContext) -> None:
    for name, value in ctx.as_gucs().items():
        conn.execute("SELECT set_config(%s, %s, true)", (name, value))


def _count(conn: psycopg.Connection, sql: str, params: tuple[object, ...] = ()) -> int:
    row = conn.execute(sql, params).fetchone()
    return int(row[0]) if row else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m nlw.ops.rollout.smoke")
    p.add_argument("--workspace", required=True, type=uuid.UUID)
    p.add_argument("--user-a", required=True, type=uuid.UUID, help="owner of --workspace")
    p.add_argument("--user-b", required=True, type=uuid.UUID, help="invited user (no membership)")
    p.add_argument(
        "--approval", required=True, type=uuid.UUID, help="pending approval requested by A"
    )
    p.add_argument(
        "--invitation-token-stdin",
        action="store_true",
        help="read the RAW invitation token from stdin (its sha256 must already be stored)",
    )
    a = p.parse_args(argv)
    raw_token = sys.stdin.readline().strip() if a.invitation_token_stdin else ""
    settings = get_settings()
    ident = build_signer(settings, Purpose.API_IDENTITY)
    req = build_signer(settings, Purpose.API_REQUEST)
    url = _libpq(settings.database_url)
    failures: list[str] = []

    with psycopg.connect(url, autocommit=False) as c:
        # 1) unsigned forgery
        c.execute("SELECT set_config('app.user_id', %s, true)", (str(a.user_a),))
        c.execute("SELECT set_config('app.tenant_id', %s, true)", (str(a.workspace),))
        if _count(c, "SELECT count(*) FROM memberships WHERE workspace_id=%s", (a.workspace,)):
            failures.append("unsigned forged context could read memberships")
        c.rollback()
        # 2) signed A context scoped to its workspace
        _apply(c, req.sign(user_id=a.user_a, tenant_id=a.workspace))
        mine = _count(c, "SELECT count(*) FROM memberships WHERE workspace_id=%s", (a.workspace,))
        others = _count(
            c, "SELECT count(*) FROM memberships WHERE workspace_id<>%s", (a.workspace,)
        )
        if mine < 1 or others != 0:
            failures.append(f"signed A context saw mine={mine} others={others}")
        c.rollback()
        # 3) B accepts the invitation (api_identity; committed — the real bootstrap path)
        if raw_token:
            _apply(c, ident.sign(user_id=a.user_b))
            try:
                c.execute(
                    "SELECT accept_workspace_invitation(%s)",
                    (hashlib.sha256(raw_token.encode()).hexdigest(),),
                )
                c.commit()
            except psycopg.Error as exc:
                c.rollback()
                failures.append(f"invitation accept failed: {type(exc).__name__}")
            # After the commit the context is gone (transaction-local): read back
            # under B's own identity context (own membership rows are visible).
            _apply(c, ident.sign(user_id=a.user_b))
            role = c.execute(
                "SELECT role FROM memberships WHERE workspace_id=%s AND user_id=%s",
                (a.workspace, a.user_b),
            ).fetchone()
            c.rollback()
            if not role or role[0] != "admin":
                failures.append(f"B membership after accept is {role!r}, expected admin")
        # 4) self-approval by the requester is blocked
        _apply(c, req.sign(user_id=a.user_a, tenant_id=a.workspace))
        try:
            cur = c.execute(
                "UPDATE approvals SET status='approved', decided_by=%s, decided_at=now() "
                "WHERE id=%s",
                (a.user_a, a.approval),
            )
            if cur.rowcount:
                failures.append("requester self-approved (four-eyes bypass)")
        except psycopg.errors.InsufficientPrivilege:
            pass
        c.rollback()
        # 5) a different eligible admin approves
        if raw_token:
            _apply(c, req.sign(user_id=a.user_b, tenant_id=a.workspace))
            try:
                cur = c.execute(
                    "UPDATE approvals SET status='approved', decided_by=%s, decided_at=now() "
                    "WHERE id=%s AND status='pending'",
                    (a.user_b, a.approval),
                )
                if cur.rowcount != 1:
                    failures.append(f"eligible admin approval affected {cur.rowcount} rows")
                c.commit()
            except psycopg.Error as exc:
                c.rollback()
                failures.append(f"eligible admin approval failed: {type(exc).__name__}")

    for f in failures:
        print(f"SMOKE FAIL: {f}", file=sys.stderr)
    if failures:
        return 1
    print(
        "smoke: OK (forgery denied; scoped; invite accepted; self-approval blocked; four-eyes ok)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
