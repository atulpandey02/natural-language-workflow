"""A successful mutation response is sent only AFTER its transaction commits.

FastAPI exits a request-scoped yield dependency only after the response has
been sent. ``get_session`` commits on exit, so a client could get a 2xx for a
row that was not yet committed (the pilot harness read a list without the
connector it had just created), and a commit failure still answered 2xx with
nothing saved. ``get_session`` is now function-scoped everywhere.

These tests call the real application over ASGI and look at Postgres, from a
separate connection, at the exact moment the response STARTS
(``http.response.start``): deterministic, no sleeps, no retries. A commit
failure is a real COMMIT-time error (a deferred constraint trigger)."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import time
import uuid
from collections.abc import Callable, MutableMapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jwt
import psycopg
import pytest
from fastapi import FastAPI

import nlw.api.routers.approvals as approvals_mod
import nlw.api.routers.dataset_uploads as uploads_mod
import nlw.api.routers.workflows as workflows_mod
from nlw.api.app import create_app

pytestmark = pytest.mark.integration

ISSUER = "https://proj.supabase.co/auth/v1"
SECRET = "dev-secret-for-tests-32bytes-min-length"

_APPROVALS = Path(__file__).with_name("test_approvals_api.py")
_spec = importlib.util.spec_from_file_location("_approval_seeds", _APPROVALS)
assert _spec and _spec.loader
approval_seeds = sys.modules.get("_approval_seeds") or importlib.util.module_from_spec(_spec)
if "_approval_seeds" not in sys.modules:
    sys.modules["_approval_seeds"] = approval_seeds
    _spec.loader.exec_module(approval_seeds)


def _token(sub: str, email: str | None = None) -> dict[str, str]:
    claims = {
        "iss": ISSUER,
        "aud": "authenticated",
        "exp": int(time.time()) + 300,
        "sub": sub,
        "email": email or f"{sub}@example.com",
    }
    return {"Authorization": f"Bearer {jwt.encode(claims, SECRET, algorithm='HS256')}"}


def _member(user_id: uuid.UUID, tenant: uuid.UUID, **extra: str) -> dict[str, str]:
    return {
        **_token(f"sub-{user_id}", f"{user_id}@example.com"),
        "X-Workspace-Id": str(tenant),
        **extra,
    }


# --- calling the app and observing the moment the response starts -------------------------


class Reply(SimpleNamespace):
    status: int
    body: bytes
    seen_at_start: Any
    raised: str | None

    def json(self) -> Any:
        return json.loads(self.body)


async def _call(
    app: FastAPI,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    at_start: Callable[[], Any] | None,
) -> Reply:
    """One ASGI request. ``at_start`` runs when the app sends
    ``http.response.start`` -- before any later code in the app could run."""
    delivered = False
    hold = asyncio.Event()  # the client never disconnects mid-request

    async def receive() -> MutableMapping[str, Any]:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        await hold.wait()
        return {"type": "http.disconnect"}

    reply = Reply(status=0, body=b"", seen_at_start=None, raised=None)

    async def send(message: MutableMapping[str, Any]) -> None:
        if message["type"] == "http.response.start":
            reply.status = message["status"]
            if at_start is not None:
                reply.seen_at_start = at_start()
        elif message["type"] == "http.response.body":
            reply.body += message.get("body", b"")

    raw = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()]
    if body:
        raw += [(b"content-length", str(len(body)).encode())]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": raw,
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    try:
        await app(scope, receive, send)
    except Exception as exc:
        # Starlette's ServerErrorMiddleware sends the 500 and then re-raises for
        # the server to log (uvicorn does). Anything raised before a response
        # started is a real failure of the test itself.
        if reply.status == 0:
            raise
        reply.raised = type(exc).__name__
    return reply


def _run(app: FastAPI, requests: list[tuple[str, str, dict[str, str], Any, Any]]) -> list[Reply]:
    """Run requests in order inside the app's lifespan. Each is
    (method, path, headers, json-or-bytes-or-None, at_start)."""

    async def main() -> list[Reply]:
        out = []
        async with app.router.lifespan_context(app):
            for method, path, headers, payload, at_start in requests:
                if isinstance(payload, bytes):
                    body, hdrs = payload, headers
                elif payload is None:
                    body, hdrs = b"", headers
                else:
                    body = json.dumps(payload).encode()
                    hdrs = {**headers, "Content-Type": "application/json"}
                out.append(await _call(app, method, path, hdrs, body, at_start))
        return out

    return asyncio.run(main())


def _one(owner: str, sql: str, params: tuple[Any, ...] = ()) -> Any:
    with psycopg.connect(owner, autocommit=True) as c:
        row = c.execute(sql, params).fetchone()
    return None if row is None else row[0]


def _fail_at_commit(owner: str, table: str, event: str = "INSERT") -> None:
    """A real COMMIT-time failure: a deferred constraint trigger that raises
    when the transaction commits, after every statement succeeded."""
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute(
            "CREATE OR REPLACE FUNCTION zz_fail_at_commit() RETURNS trigger LANGUAGE plpgsql "
            "AS $$BEGIN RAISE EXCEPTION 'forced failure at COMMIT'; END$$"
        )
        c.execute(
            f"CREATE CONSTRAINT TRIGGER zz_fail_at_commit AFTER {event} ON {table} "
            "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION zz_fail_at_commit()"
        )


_CONNECTOR = {
    "type": "static",
    "name": "demo",
    "config": {"label": "x"},
    "secret_ref": "STATIC_DEMO",
}


# --- 1. after a successful response, another transaction reads the committed record ------


def test_a_first_sight_user_is_committed_before_the_200(pg_stack: SimpleNamespace) -> None:
    """GET /me provisions the user (get_current_user) in the request session."""
    sub = f"first-{uuid.uuid4().hex[:8]}"
    (me,) = _run(
        create_app(pg_stack.settings),
        [
            (
                "GET",
                "/me",
                _token(sub),
                None,
                lambda: _one(
                    pg_stack.owner_libpq, "SELECT id FROM users WHERE auth_provider_id=%s", (sub,)
                ),
            )
        ],
    )
    assert me.status == 200
    assert me.seen_at_start is not None and str(me.seen_at_start) == me.json()["id"]


def test_a_created_connector_is_committed_and_listed_immediately(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    h = _member(m.user_id, m.tenant_id)
    created, listed = _run(
        create_app(pg_stack.settings),
        [
            (
                "POST",
                "/connectors",
                h,
                _CONNECTOR,
                lambda: _one(
                    pg_stack.owner_libpq,
                    "SELECT count(*) FROM connectors WHERE tenant_id=%s AND name=%s",
                    (m.tenant_id, "demo"),
                ),
            ),
            ("GET", "/connectors", h, None, None),  # the very next request, a new transaction
        ],
    )
    assert created.status == 201 and created.seen_at_start == 1
    assert listed.status == 200 and [c["name"] for c in listed.json()] == ["demo"]


def test_a_created_workspace_is_committed_whole_before_the_201(pg_stack: SimpleNamespace) -> None:
    sub, email = f"ws-{uuid.uuid4().hex[:8]}", f"ws-{uuid.uuid4().hex[:8]}@example.com"
    pg_stack.grant_workspace_creation(email)

    def committed() -> tuple[Any, ...]:
        return (
            _one(pg_stack.owner_libpq, "SELECT count(*) FROM workspaces WHERE name='Committed'"),
            _one(
                pg_stack.owner_libpq,
                "SELECT count(*) FROM memberships m JOIN users u "
                "ON u.id = m.user_id WHERE u.auth_provider_id=%s",
                (sub,),
            ),
            _one(
                pg_stack.owner_libpq,
                "SELECT count(*) FROM workspace_creation_grants "
                "WHERE email_normalized=%s AND consumed_at IS NOT NULL",
                (email,),
            ),
            _one(
                pg_stack.owner_libpq,
                "SELECT count(*) FROM authz_audit_events WHERE event_type='workspace.created'",
            ),
        )

    (ws,) = _run(
        create_app(pg_stack.settings),
        [("POST", "/workspaces", _token(sub, email), {"name": "Committed"}, committed)],
    )
    assert ws.status == 201 and ws.seen_at_start == (1, 1, 1, 1)


# --- 2 and 3. a commit failure is never a 2xx and leaves nothing behind --------------------


def test_a_failed_commit_on_a_connector_is_a_500_with_no_row(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    _fail_at_commit(pg_stack.owner_libpq, "connectors")
    (r,) = _run(
        create_app(pg_stack.settings),
        [("POST", "/connectors", _member(m.user_id, m.tenant_id), _CONNECTOR, None)],
    )
    assert r.status == 500 and b"forced failure" not in r.body  # opaque, no SQL detail
    assert _one(pg_stack.owner_libpq, "SELECT count(*) FROM connectors") == 0


def test_a_failed_commit_on_a_workspace_leaves_no_row_event_or_consumed_grant(
    pg_stack: SimpleNamespace,
) -> None:
    sub, email = f"ws-{uuid.uuid4().hex[:8]}", f"ws-{uuid.uuid4().hex[:8]}@example.com"
    pg_stack.grant_workspace_creation(email)
    _fail_at_commit(pg_stack.owner_libpq, "workspaces")
    (r,) = _run(
        create_app(pg_stack.settings),
        [("POST", "/workspaces", _token(sub, email), {"name": "Ghost"}, None)],
    )
    assert not 200 <= r.status < 300 and r.status >= 500
    o = pg_stack.owner_libpq
    assert _one(o, "SELECT count(*) FROM workspaces WHERE name='Ghost'") == 0
    assert (
        _one(
            o,
            "SELECT count(*) FROM memberships m JOIN users u ON u.id = m.user_id "
            "WHERE u.auth_provider_id=%s",
            (sub,),
        )
        == 0
    )
    assert (
        _one(o, "SELECT count(*) FROM authz_audit_events WHERE event_type='workspace.created'") == 0
    )
    assert (
        _one(
            o,
            "SELECT count(*) FROM workspace_creation_grants WHERE email_normalized=%s "
            "AND consumed_at IS NULL",
            (email,),
        )
        == 1
    )  # the grant is still open


# --- 4. queue publications happen only after commit; a failed commit publishes nothing ----


def test_a_manual_run_is_committed_before_it_is_enqueued(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Any] = []
    monkeypatch.setattr(
        workflows_mod,
        "_enqueue_advance",
        lambda run_id: seen.append(
            _one(pg_stack.owner_libpq, "SELECT status FROM workflow_runs WHERE id=%s", (run_id,))
        ),
    )
    m = pg_stack.seed_member()
    wf = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    h = _member(m.user_id, m.tenant_id, **{"Idempotency-Key": "commit-order-1"})
    (r,) = _run(create_app(pg_stack.settings), [("POST", f"/workflows/{wf}/runs", h, None, None)])
    assert r.status == 201 and seen == ["PENDING"]  # committed when the message was sent


def test_a_run_whose_commit_fails_is_never_enqueued(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Any] = []
    monkeypatch.setattr(workflows_mod, "_enqueue_advance", seen.append)
    m = pg_stack.seed_member()
    wf = _seed_workflow(pg_stack.owner_libpq, m.tenant_id)
    _fail_at_commit(pg_stack.owner_libpq, "workflow_runs")
    h = _member(m.user_id, m.tenant_id, **{"Idempotency-Key": "commit-order-2"})
    (r,) = _run(create_app(pg_stack.settings), [("POST", f"/workflows/{wf}/runs", h, None, None)])
    assert r.status >= 500 and seen == []
    assert _one(pg_stack.owner_libpq, "SELECT count(*) FROM workflow_runs") == 0


def _decider(pg_stack: SimpleNamespace) -> tuple[uuid.UUID, dict[str, str]]:
    tenant = approval_seeds._seed_workspace(pg_stack.owner_libpq)
    approval = approval_seeds._seed_parked_action(pg_stack.owner_libpq, tenant)
    sub = f"admin-{uuid.uuid4().hex[:8]}"
    approval_seeds._seed_user_member(pg_stack.owner_libpq, tenant, sub, "admin")
    return approval, {**_token(sub), "X-Workspace-Id": str(tenant)}


def test_an_approval_is_committed_before_the_run_is_resumed(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    approval, h = _decider(pg_stack)
    seen: list[Any] = []
    monkeypatch.setattr(
        approvals_mod,
        "_enqueue_advance",
        lambda _req, _run_id: seen.append(
            _one(pg_stack.owner_libpq, "SELECT status FROM approvals WHERE id=%s", (approval,))
        ),
    )
    (r,) = _run(
        create_app(pg_stack.settings), [("POST", f"/approvals/{approval}/approve", h, None, None)]
    )
    assert r.status == 200 and seen == ["approved"]


def test_an_approval_whose_commit_fails_leaves_no_decision_event_or_resume(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    approval, h = _decider(pg_stack)
    seen: list[Any] = []
    monkeypatch.setattr(approvals_mod, "_enqueue_advance", lambda _req, run_id: seen.append(run_id))
    _fail_at_commit(pg_stack.owner_libpq, "approvals", "UPDATE")
    (r,) = _run(
        create_app(pg_stack.settings), [("POST", f"/approvals/{approval}/approve", h, None, None)]
    )
    assert r.status >= 500 and seen == []
    o = pg_stack.owner_libpq
    assert _one(o, "SELECT status FROM approvals WHERE id=%s", (approval,)) == "pending"
    assert (
        _one(
            o, "SELECT count(*) FROM authz_audit_events WHERE starts_with(event_type, 'approval.')"
        )
        == 0
    )


def _datasets_app(pg_stack: SimpleNamespace, root: Path) -> FastAPI:
    settings = pg_stack.settings.model_copy(
        update={
            "datasets_api_enabled": True,
            "dataset_storage_backend": "local",
            "dataset_storage_root": str(root),
        }
    )
    return create_app(settings)


_CSV = b"region,amount\nnorth,1\nsouth,2\n"


def _upload_steps(
    pg_stack: SimpleNamespace,
    at_dispatch: Callable[[Any], Any],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[list[Reply], list[Any]]:
    seen: list[Any] = []
    monkeypatch.setattr(
        uploads_mod, "_enqueue", lambda envelope: seen.append(at_dispatch(envelope))
    )
    m = pg_stack.seed_member("owner")
    h = _member(m.user_id, m.tenant_id)
    app = _datasets_app(pg_stack, tmp_path / "store")

    async def flow() -> list[Reply]:
        out = []
        async with app.router.lifespan_context(app):

            def js(p: Any) -> bytes:
                return json.dumps(p).encode()

            j = {**h, "Content-Type": "application/json"}
            d = await _call(app, "POST", "/datasets", j, js({"name": "Sales"}), None)
            did = d.json()["id"]
            v = await _call(
                app,
                "POST",
                f"/datasets/{did}/versions",
                {**j, "Idempotency-Key": uuid.uuid4().hex},
                js({"original_filename": "s.csv", "declared_size_bytes": len(_CSV)}),
                None,
            )
            vid = v.json()["id"]
            put = await _call(
                app,
                "PUT",
                f"/datasets/{did}/versions/{vid}/content",
                {**h, "Content-Type": "text/csv"},
                _CSV,
                None,
            )
            out += [d, v, put]
        return out

    return asyncio.run(flow()), seen


def test_a_dataset_processing_request_is_committed_before_it_is_enqueued(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def committed(envelope: Any) -> Any:
        return _one(
            pg_stack.owner_libpq,
            "SELECT count(*) FROM dataset_processing_requests WHERE version_id=%s",
            (envelope.version_id,),
        )

    (d, v, put), seen = _upload_steps(pg_stack, committed, monkeypatch, tmp_path)
    assert (d.status, v.status, put.status) == (201, 201, 202), put.body
    assert seen == [1]


def test_a_dataset_upload_whose_commit_fails_is_never_enqueued(
    pg_stack: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _fail_at_commit(pg_stack.owner_libpq, "dataset_processing_requests")
    (d, v, put), seen = _upload_steps(pg_stack, lambda e: e, monkeypatch, tmp_path)
    assert (d.status, v.status) == (201, 201) and put.status >= 500 and seen == []
    assert _one(pg_stack.owner_libpq, "SELECT count(*) FROM dataset_processing_requests") == 0


# --- 5. read-only endpoints and rollback behave as before -----------------------------------


def test_reads_are_unchanged_and_write_nothing(pg_stack: SimpleNamespace) -> None:
    m = pg_stack.seed_member()
    h = _member(m.user_id, m.tenant_id)
    before = _one(pg_stack.owner_libpq, "SELECT count(*) FROM users")
    me, ws, conns = _run(
        create_app(pg_stack.settings),
        [
            ("GET", "/me", h, None, None),
            ("GET", "/workspaces", h, None, None),
            ("GET", "/connectors", h, None, None),
        ],
    )
    assert (me.status, ws.status, conns.status) == (200, 200, 200)
    assert me.json()["id"] == str(m.user_id)
    assert [w["id"] for w in ws.json()] == [str(m.tenant_id)] and conns.json() == []
    assert _one(pg_stack.owner_libpq, "SELECT count(*) FROM users") == before


def test_a_refused_request_still_rolls_back_what_it_wrote(pg_stack: SimpleNamespace) -> None:
    """A first-sight user is provisioned inside the request transaction; the
    workspace check then refuses (403) and the whole transaction rolls back."""
    stranger = pg_stack.seed_member()
    sub = f"stranger-{uuid.uuid4().hex[:8]}"
    h = {**_token(sub), "X-Workspace-Id": str(stranger.tenant_id)}
    (r,) = _run(create_app(pg_stack.settings), [("GET", "/connectors", h, None, None)])
    assert r.status == 403
    assert (
        _one(pg_stack.owner_libpq, "SELECT count(*) FROM users WHERE auth_provider_id=%s", (sub,))
        == 0
    )


def _seed_workflow(owner: str, tenant: uuid.UUID) -> uuid.UUID:
    wf, ver = uuid.uuid4(), uuid.uuid4()
    plan = {"steps": [{"id": "a", "tool": "fake.echo", "args": {}}]}
    with psycopg.connect(owner, autocommit=True) as c:
        c.execute("INSERT INTO workflows (id, tenant_id, name) VALUES (%s,%s,'wf')", (wf, tenant))
        c.execute(
            "INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) "
            "VALUES (%s,%s,%s,1,%s::jsonb)",
            (ver, tenant, wf, json.dumps(plan)),
        )
        c.execute("UPDATE workflows SET current_version_id=%s WHERE id=%s", (ver, wf))
    return wf
