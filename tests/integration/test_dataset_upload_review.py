"""Adversarial review of the upload API on the ingest boundary (PR #56).

Drives the REAL ASGI app with hand-built messages where the HTTP client would
hide the case (fragmented, chunked, lying or malformed ``Content-Length``,
disconnects, simultaneous bodies), and covers the filesystem/database failure
boundaries, replays after every terminal state, the recovery lock and the
bounded operator sweep. The ingest side is the real ingest runtime as
``nlw_ingest`` (``ingest_runtime``); the API never processes."""

import asyncio
import contextlib
import hashlib
import json
import time
import uuid
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from nlw.api.app import create_app
from nlw.datasets import service as svc
from nlw.datasets.deletion_log import LocalFakeDeletionLog
from nlw.ops import datasets as ops
from nlw.storage.blob import LocalBlobStore

pytestmark = pytest.mark.integration

_SECRET = "dev-secret-for-tests-32bytes-min-length"
CSV = b"region,amount\n" + b"".join(f"r{i % 3},{i}\n".encode() for i in range(30))
OTHER = b"region,amount\n" + b"".join(f"x{i % 3},{i}\n".encode() for i in range(30))
CAP = len(CSV)  # the app's upload limit in these tests: CSV is exactly at it


def _token(user_id: uuid.UUID) -> str:
    return jwt.encode(
        {
            "iss": "https://proj.supabase.co/auth/v1",
            "aud": "authenticated",
            "exp": int(time.time()) + 300,
            "sub": f"sub-{user_id}",
            "email": f"{user_id}@example.com",
        },
        _SECRET,
        algorithm="HS256",
    )


def _hdr(user_id: uuid.UUID, tenant_id: uuid.UUID) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(user_id)}", "X-Workspace-Id": str(tenant_id)}


@pytest.fixture
def up(
    pg_stack: SimpleNamespace,
    tmp_path: Path,
    ingest_runtime: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[SimpleNamespace]:
    settings = pg_stack.settings.model_copy(
        update={
            "datasets_api_enabled": True,
            "dataset_storage_backend": "local",
            "dataset_storage_root": str(tmp_path / "datasets"),
            "dataset_max_upload_bytes": CAP,
            "recovery_gate_ttl_s": 0.1,
        }
    )
    m = pg_stack.seed_member("owner")
    app = create_app(settings)
    with TestClient(app) as c:
        rt = ingest_runtime.attach(app, monkeypatch)
        yield SimpleNamespace(
            c=c, rt=rt, h=_hdr(m.user_id, m.tenant_id), tenant=m.tenant_id, user=m.user_id,
            pg=pg_stack, store=app.state.dataset_store, root=tmp_path / "datasets",
        )  # fmt: skip


def _dataset(up: SimpleNamespace) -> str:
    r = up.c.post("/datasets", headers=up.h, json={"name": f"d-{uuid.uuid4().hex[:6]}"})
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def _initiate(up: SimpleNamespace, did: str, size: int = len(CSV)) -> str:
    r = up.c.post(
        f"/datasets/{did}/versions",
        headers={**up.h, "Idempotency-Key": uuid.uuid4().hex},
        json={"original_filename": "a.csv", "declared_size_bytes": size},
    )
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def _rows(pg: SimpleNamespace, sql: str, *args: Any) -> list[tuple[Any, ...]]:
    with psycopg.connect(pg.owner_libpq) as c:
        return c.execute(sql, args).fetchall()


def _version_row(up: SimpleNamespace, vid: str) -> tuple[Any, ...]:
    (row,) = _rows(
        up.pg,
        "SELECT status, content_sha256, storage_object_key IS NOT NULL, "
        "(SELECT count(*) FROM dataset_processing_requests r WHERE r.version_id = v.id), "
        "(SELECT count(*) FROM dataset_profiles p WHERE p.version_id = v.id) "
        "FROM dataset_versions v WHERE id = %s",
        vid,
    )
    return row


def _files(up: SimpleNamespace) -> list[str]:
    """Every file under the store root (objects AND partial uploads)."""
    return sorted(str(p.relative_to(up.root)) for p in up.root.rglob("*") if p.is_file())


def _events(up: SimpleNamespace, vid: str) -> list[str]:
    rows = _rows(
        up.pg,
        "SELECT event_type FROM dataset_events WHERE version_id = %s ORDER BY created_at, id",
        vid,
    )
    return [r[0] for r in rows]


Hook = Callable[[int], Awaitable[None]]


async def _asgi(
    app: Any,
    path: str,
    headers: list[tuple[bytes, bytes]],
    chunks: list[bytes],
    *,
    method: str = "PUT",
    disconnect: bool = False,
    hook: Hook | None = None,
) -> tuple[int, dict[str, Any]]:
    """One request against the ASGI app with exact control over the messages.
    ``hook(i)`` runs before chunk ``i`` is handed over."""
    pending = list(chunks)
    index = 0
    finished = False
    out: dict[str, Any] = {"status": 0, "body": b""}

    async def receive() -> dict[str, Any]:
        nonlocal index, finished
        if pending:
            if hook is not None:
                await hook(index)
            index += 1
            return {"type": "http.request", "body": pending.pop(0), "more_body": True}
        if disconnect:
            return {"type": "http.disconnect"}
        if not finished:
            finished = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.Event().wait()  # a connected client that sends nothing more
        raise AssertionError("unreachable")

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            out["status"] = message["status"]
        elif message["type"] == "http.response.body":
            out["body"] += message.get("body", b"")

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
        "headers": [(b"host", b"testserver"), *headers],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    # The server error middleware re-raises after sending its 500.
    with contextlib.suppress(Exception):
        await app(scope, receive, send)
    body = out["body"]
    return out["status"], (json.loads(body) if body.startswith(b"{") else {})


def _put(
    up: SimpleNamespace,
    did: str,
    vid: str,
    chunks: list[bytes],
    *,
    length: str | None = "auto",
    extra: list[tuple[bytes, bytes]] | None = None,
    **kw: Any,
) -> tuple[int, dict[str, Any]]:
    headers = [(k.lower().encode(), v.encode()) for k, v in up.h.items()]
    if length == "auto":
        headers.append((b"content-length", str(sum(map(len, chunks))).encode()))
    elif length is not None:
        headers.append((b"content-length", length.encode("latin-1")))
    headers += extra or []
    path = f"/datasets/{did}/versions/{vid}/content"
    result: tuple[int, dict[str, Any]] = up.c.portal.call(
        lambda: _asgi(up.c.app, path, headers, chunks, **kw)
    )
    return result


def _code(body: dict[str, Any]) -> str | None:
    err = body.get("error")
    return err.get("code") if isinstance(err, dict) else None


# --- 3. streaming and resource bounds -------------------------------------------------------


def test_exact_limit_succeeds_and_one_byte_over_is_refused_while_reading(
    up: SimpleNamespace,
) -> None:
    did = _dataset(up)
    exact = _initiate(up, did, CAP)
    status, _ = _put(up, did, exact, [CSV[i : i + 7] for i in range(0, CAP, 7)])  # fragmented
    assert status == 202
    assert _version_row(up, exact)[:2] == ("PROFILED", hashlib.sha256(CSV).hexdigest())

    # One byte over: an honest Content-Length is refused before any byte is read.
    over = _initiate(up, did, CAP)
    status, body = _put(up, did, over, [CSV + b"x"])
    assert (status, _code(body)) == (413, "CONTENT_TOO_LARGE")
    # Chunked (no Content-Length) or a LYING one: the streamed cap refuses it.
    for length in (None, str(CAP), "1"):
        status, body = _put(up, did, over, [CSV, b"x"], length=length)
        assert (status, _code(body)) == (413, "CONTENT_SIZE_MISMATCH"), length
    assert _version_row(up, over)[:4] == ("QUARANTINED", None, False, 0)
    assert [f for f in _files(up) if over.replace("-", "") in f.replace("-", "")] == []


def test_content_length_is_never_authoritative(up: SimpleNamespace) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)
    # A superscript digit passes str.isdigit() but not int(): never a 500.
    for bogus in ("²", "-1", "abc", "99999999999999999999999999"):
        status, body = _put(up, did, vid, [CSV[:5]], length=bogus)
        assert status in (413, 422) and _code(body), (bogus, status)
    # A smaller Content-Length than the body: the actual bytes decide.
    status, _ = _put(up, did, vid, [CSV[:10], CSV[10:]], length="3")
    assert status == 202
    assert _version_row(up, vid)[1] == hashlib.sha256(CSV).hexdigest()


def test_duplicate_content_length_headers_cannot_lift_the_cap(up: SimpleNamespace) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)
    status, body = _put(
        up, did, vid, [CSV, CSV], length="1", extra=[(b"content-length", b"999999999")]
    )
    assert (status, _code(body)) == (413, "CONTENT_SIZE_MISMATCH")
    assert _version_row(up, vid)[:3] == ("QUARANTINED", None, False)


def test_empty_and_short_bodies_record_nothing_and_keep_no_bytes(up: SimpleNamespace) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)
    for chunks in ([], [b""], [CSV[:-1]]):
        status, body = _put(up, did, vid, chunks)
        assert (status, _code(body)) == (422, "CONTENT_SIZE_MISMATCH"), chunks
    assert _version_row(up, vid)[:4] == ("QUARANTINED", None, False, 0)
    assert _files(up) == []  # no object, no partial upload


def test_a_client_disconnect_mid_stream_records_nothing_and_leaves_no_partial(
    up: SimpleNamespace,
) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)
    _put(up, did, vid, [CSV[:10], CSV[10:20]], disconnect=True)
    assert _version_row(up, vid)[:4] == ("QUARANTINED", None, False, 0)
    assert _files(up) == []
    assert up.rt.sent == []
    status, _ = _put(up, did, vid, [CSV])  # the client simply uploads again
    assert status == 202 and _version_row(up, vid)[0] == "PROFILED"


def test_simultaneous_bodies_for_one_version_commit_exactly_one(up: SimpleNamespace) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)
    headers = [(k.lower().encode(), v.encode()) for k, v in up.h.items()]
    path = f"/datasets/{did}/versions/{vid}/content"

    async def both() -> list[tuple[int, dict[str, Any]]]:
        slow = [CSV[i : i + 50] for i in range(0, len(CSV), 50)]
        other = [OTHER[i : i + 50] for i in range(0, len(OTHER), 50)]

        async def tick(_: int) -> None:
            await asyncio.sleep(0.01)  # interleave the two streams

        return list(
            await asyncio.gather(
                _asgi(up.c.app, path, headers, slow, hook=tick),
                _asgi(up.c.app, path, headers, other, hook=tick),
            )
        )

    results = up.c.portal.call(both)
    statuses = sorted(s for s, _ in results)
    assert statuses == [202, 409], results
    status, sha, has_key, requests, profiles = _version_row(up, vid)
    winner = CSV if sha == hashlib.sha256(CSV).hexdigest() else OTHER
    assert sha == hashlib.sha256(winner).hexdigest() and has_key
    assert (requests, profiles, status) == (1, 1, "PROFILED")


# --- 5. filesystem/database failure boundaries ----------------------------------------------


def test_storage_failure_before_or_during_writing_leaks_nothing(
    up: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)
    secret_path = "/var/lib/nlw/datasets/secret-host-path"

    def broken(*_: Any, **__: Any) -> Any:
        raise OSError(28, f"No space left on device: {secret_path}")

    with monkeypatch.context() as mp:
        mp.setattr(LocalBlobStore, "put_stream", broken)
        status, body = _put(up, did, vid, [CSV])
    assert status == 500 and secret_path not in json.dumps(body) and "space" not in json.dumps(body)
    assert _version_row(up, vid)[:4] == ("QUARANTINED", None, False, 0)
    status, _ = _put(up, did, vid, [CSV])  # the retry succeeds
    assert status == 202


def test_object_finalized_but_the_database_fails_then_the_identical_retry_adopts_it(
    up: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)
    real = svc.record_content

    async def db_down(*_: Any, **__: Any) -> Any:
        raise OperationalError("UPDATE dataset_versions", {}, Exception("password=hunter2"))

    with monkeypatch.context() as mp:
        mp.setattr(svc, "record_content", db_down)
        status, body = _put(up, did, vid, [CSV])
    assert (
        status == 500
        and "hunter2" not in json.dumps(body)
        and "dataset_versions" not in (json.dumps(body))
    )
    assert svc.record_content is real
    # The object exists but nothing points at it: the operator can see it ...
    with psycopg.connect(up.pg.owner_libpq, autocommit=True) as c:
        assert ops.verify_objects(c, up.store)["unaccounted_objects"] == [vid]
    assert _version_row(up, vid)[:4] == ("QUARANTINED", None, False, 0)
    # ... different bytes can never replace it, the identical retry adopts it.
    status, body = _put(up, did, vid, [OTHER])
    assert (status, _code(body)) == (409, "CONTENT_CONFLICT")
    status, _ = _put(up, did, vid, [CSV])
    assert status == 202
    assert _version_row(up, vid)[3:] == (1, 1)  # one request, one profile
    with psycopg.connect(up.pg.owner_libpq, autocommit=True) as c:
        assert ops.verify_objects(c, up.store) == {
            "missing_objects": [], "digest_mismatches": [], "unaccounted_objects": [],
            "noncurrent_versions": [],
        }  # fmt: skip


def test_a_lost_response_after_commit_or_after_enqueue_is_safe_to_retry(
    up: SimpleNamespace,
) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)
    up.rt.auto = False
    assert _put(up, did, vid, [CSV])[0] == 202  # the client never saw this response
    (first,) = up.rt.sent
    # Retry 1 (response of the enqueue lost): the SAME request, re-sent.
    assert _put(up, did, vid, [CSV])[0] == 202
    assert [e.request_id for e in up.rt.sent] == [first.request_id] * 2
    # Both copies are delivered: one profile, one event sequence.
    results = [up.rt.process(e.to_json()) for e in up.rt.sent]
    assert results[0] == "profiled" and results[1] != "profiled"
    assert _version_row(up, vid)[3:] == (1, 1)
    assert _events(up, vid) == ["VERSION_CREATED", "VERSION_PROFILING_STARTED", "VERSION_PROFILED"]
    # Retry 2 after processing: nothing is re-requested or re-sent.
    assert _put(up, did, vid, [CSV])[0] == 202
    assert len(up.rt.sent) == 2 and _version_row(up, vid)[3:] == (1, 1)


def test_deletion_while_streaming_refuses_the_record_and_purge_removes_the_bytes(
    up: SimpleNamespace,
) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)

    async def delete_dataset(i: int) -> None:
        # Runs on the app's loop before chunk i; the DELETE goes through a thread.
        if i == 1:
            r = await asyncio.to_thread(up.c.delete, f"/datasets/{did}", headers=up.h)
            assert r.status_code == 202

    status, body = _put(up, did, vid, [CSV[:20], CSV[20:]], hook=delete_dataset)
    assert (status, _code(body)) == (409, "DATASET_NOT_ACTIVE")
    assert _version_row(up, vid)[:4] == ("DELETING", None, False, 0)  # nothing recorded
    assert up.rt.sent == []
    with psycopg.connect(up.pg.owner_libpq, autocommit=True) as c:
        assert ops.verify_objects(c, up.store)["unaccounted_objects"] == [vid]
        log = LocalFakeDeletionLog(up.root.parent / "receipts.jsonl")
        ops.purge(c, up.store, log, dataset_id=uuid.UUID(did), operator="op", environment="local")
        assert ops.verify_objects(c, up.store)["unaccounted_objects"] == []
    assert _files(up) == []
    # The deleted dataset accepts neither content nor processing requests.
    assert _put(up, did, vid, [CSV])[0] in (404, 409)
    r = up.c.post(f"/datasets/{did}/versions/{vid}/process", headers=up.h)
    assert r.status_code in (202, 404, 409) and _version_row(up, vid)[3] == 0
    assert up.rt.sent == []


def test_membership_removed_while_streaming_records_nothing(up: SimpleNamespace) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)
    admin = up.pg.add_membership(up.tenant, "admin")
    headers = [(k.lower().encode(), v.encode()) for k, v in _hdr(admin, up.tenant).items()]

    async def demote(i: int) -> None:
        if i == 1:
            await asyncio.to_thread(
                _rows_exec, up.pg, "UPDATE memberships SET role = 'member' WHERE user_id = %s",
                admin,
            )  # fmt: skip

    path = f"/datasets/{did}/versions/{vid}/content"
    status, body = up.c.portal.call(
        lambda: _asgi(up.c.app, path, headers, [CSV[:20], CSV[20:]], hook=demote)
    )
    assert status in (403, 404) and _code(body) != "INTERNAL", (status, body)
    assert _version_row(up, vid)[:4] == ("QUARANTINED", None, False, 0)
    # A current admin's identical upload adopts the bytes and proceeds.
    assert _put(up, did, vid, [CSV])[0] == 202
    assert _version_row(up, vid)[0] == "PROFILED"


def _rows_exec(pg: SimpleNamespace, sql: str, *args: Any) -> None:
    with psycopg.connect(pg.owner_libpq, autocommit=True) as c:
        c.execute(sql, args)


# --- 6. replays after every state -----------------------------------------------------------


@pytest.mark.parametrize("state", ["PROFILED", "ACTIVE", "DELETING", "REJECTED"])
def test_replays_and_redispatch_after_a_settled_state_change_nothing(
    up: SimpleNamespace, state: str
) -> None:
    did = _dataset(up)
    data = b"a,a\n1,2\n" if state == "REJECTED" else CSV
    vid = _initiate(up, did, len(data))
    assert _put(up, did, vid, [data])[0] == 202
    (env,) = up.rt.sent
    if state == "ACTIVE":
        cols = [
            {"name": "region", "label": "Region", "semantic_type": "category",
             "role": "dimension", "analysis_allowed": True},
            {"name": "amount", "label": "Amount", "semantic_type": "amount",
             "role": "measure", "analysis_allowed": True},
        ]  # fmt: skip
        sem = up.c.post(
            f"/datasets/{did}/versions/{vid}/semantics", headers=up.h, json={"columns": cols}
        )
        assert sem.status_code == 201, sem.text
        assert (
            up.c.post(f"/datasets/{did}/versions/{vid}/activate", headers=up.h).status_code == 200
        )
    if state == "DELETING":
        assert up.c.delete(f"/datasets/{did}/versions/{vid}", headers=up.h).status_code == 202
    before = (_version_row(up, vid), _events(up, vid))
    assert before[0][0] == state
    # The original message, delivered again, changes nothing ...
    assert up.rt.process(env.to_json()) != "profiled"
    # ... nor does a re-dispatch (no new request, nothing sent) or a re-upload.
    r = up.c.post(f"/datasets/{did}/versions/{vid}/process", headers=up.h)
    assert r.status_code == 202 and r.json()["status"] == state
    assert len(up.rt.sent) == 1
    _put(up, did, vid, [data])
    assert len(up.rt.sent) == 1
    assert (_version_row(up, vid), _events(up, vid)) == before
    active = _rows(
        up.pg, "SELECT count(*) FROM dataset_versions WHERE dataset_id = %s AND status = 'ACTIVE'",
        did,
    )  # fmt: skip
    assert active == [(1 if state == "ACTIVE" else 0,)]


def test_redispatch_of_another_workspaces_version_is_not_found(up: SimpleNamespace) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)
    up.rt.fail = True
    _put(up, did, vid, [CSV])  # a committed request whose enqueue was lost
    up.rt.fail = False
    other = up.pg.seed_member("owner")
    h = _hdr(other.user_id, other.tenant_id)
    for path in (f"/datasets/{did}/versions/{vid}/process", f"/datasets/{did}/versions"):
        r = up.c.post(path, headers={**h, "Idempotency-Key": uuid.uuid4().hex},
                      json={"original_filename": "a.csv", "declared_size_bytes": 3})  # fmt: skip
        assert r.status_code == 404, (path, r.text)
    assert up.rt.sent == [] and _version_row(up, vid)[3] == 1


# --- 7. operator sweep: bounded, ordered, exclusive -----------------------------------------


class _Broker:
    def __init__(self) -> None:
        self.sent: list[Any] = []

    def enqueue(self, message: Any, *, delay: int | None = None) -> Any:
        self.sent.append(message)
        return message


def test_the_sweep_is_bounded_ordered_and_exclusive(up: SimpleNamespace) -> None:
    did = _dataset(up)
    up.rt.fail = True
    waiting = []
    for _ in range(3):
        vid = _initiate(up, did)
        _put(up, did, vid, [CSV])
        waiting.append(vid)
    up.rt.fail = False
    broker = _Broker()
    with psycopg.connect(up.pg.owner_libpq, autocommit=True) as c:
        first = ops.dispatch_pending(c, broker, dry_run=False, limit=2)
        assert (first["enqueued"], first["more"]) == (2, 1)
        sent = [json.loads(m.args[0])["version_id"] for m in broker.sent]
        assert sent == waiting[:2]  # oldest first
        with pytest.raises(ValueError):
            ops.dispatch_pending(c, broker, dry_run=True, limit=0)
        # A concurrent sweep (another session holding the lock) sends nothing.
        with psycopg.connect(up.pg.owner_libpq, autocommit=True) as other:
            other.execute(ops._SQL_SWEEP_LOCK)
            assert ops.dispatch_pending(c, broker, dry_run=False)["busy"] == 1
            other.execute(ops._SQL_SWEEP_UNLOCK)
        assert len(broker.sent) == 2
        # Overlapping deliveries of everything still yield one profile each.
        ops.dispatch_pending(c, broker, dry_run=False)
    for m in broker.sent:
        up.rt.process(m.args[0])
    for vid in waiting:
        assert _version_row(up, vid)[0] == "PROFILED" and _version_row(up, vid)[3:] == (1, 1)
    with psycopg.connect(up.pg.owner_libpq, autocommit=True) as c:
        assert ops.dispatch_pending(c, broker, dry_run=True)["pending"] == 0


def test_a_broker_failure_mid_sweep_changes_no_database_state(up: SimpleNamespace) -> None:
    did = _dataset(up)
    up.rt.fail = True
    vid = _initiate(up, did)
    _put(up, did, vid, [CSV])
    up.rt.fail = False
    before = (_version_row(up, vid), _events(up, vid))

    class Down:
        def enqueue(self, *_: Any, **__: Any) -> Any:
            raise ConnectionError("redis unavailable")

    with psycopg.connect(up.pg.owner_libpq, autocommit=True) as c:
        with pytest.raises(ConnectionError):
            ops.dispatch_pending(c, Down(), dry_run=False)
        assert ops.dispatch_pending(c, _Broker(), dry_run=True)["busy"] == 0  # lock released
    assert (_version_row(up, vid), _events(up, vid)) == before


# --- 12. recovery lock ----------------------------------------------------------------------


def test_the_recovery_lock_gates_uploads_and_queued_work(up: SimpleNamespace) -> None:
    from nlw.backup.recovery_lock import RecoveryLocked

    did = _dataset(up)
    vid = _initiate(up, did)
    restore = uuid.uuid4()
    _rows_exec(up.pg, "INSERT INTO dr_restore_events (id, cutoff_at) VALUES (%s, now())", restore)
    time.sleep(0.3)  # past the gate's cache
    status, body = _put(up, did, vid, [CSV])
    assert status == 503 and body == {
        "error": {"code": "service_unavailable", "message": "service temporarily unavailable"}
    }
    r = up.c.post(f"/datasets/{did}/versions/{vid}/process", headers=up.h)
    assert r.status_code == 503
    assert _version_row(up, vid)[:4] == ("QUARANTINED", None, False, 0) and _files(up) == []
    _rows_exec(
        up.pg,
        "UPDATE dr_restore_events SET validation_completed_at = now(), "
        "runtime_enabled_at = now() WHERE id = %s",
        restore,
    )
    time.sleep(0.3)
    # Work queued, then a restore lands: the ingest runtime changes nothing.
    up.rt.auto = False
    assert _put(up, did, vid, [CSV])[0] == 202
    (env,) = up.rt.sent
    _rows_exec(up.pg, "INSERT INTO dr_restore_events (id, cutoff_at) VALUES (%s, now())",
               uuid.uuid4())  # fmt: skip
    with pytest.raises(RecoveryLocked):
        up.rt.process(env.to_json())
    assert _version_row(up, vid)[0] == "QUARANTINED" and _version_row(up, vid)[4] == 0
    _rows_exec(
        up.pg,
        "UPDATE dr_restore_events SET validation_completed_at = now(), "
        "runtime_enabled_at = now() WHERE runtime_enabled_at IS NULL",
    )
    assert up.rt.process(env.to_json()) == "profiled"  # the message is retried later


# --- 9. inputs and error hygiene ------------------------------------------------------------


def test_hostile_initiation_inputs_get_closed_codes(up: SimpleNamespace) -> None:
    did = _dataset(up)
    path = f"/datasets/{did}/versions"
    key = {"Idempotency-Key": uuid.uuid4().hex}
    good = {"original_filename": "a.csv", "declared_size_bytes": 10}
    cases: list[tuple[dict[str, str], Any, int]] = [
        ({**key, "Content-Type": "application/json"}, b"{not json", 422),
        ({**key, "Content-Type": "text/plain"}, json.dumps(good).encode(), 422),
        ({**key}, {**good, "media_type": "text/plain"}, 422),
        ({**key}, {**good, "storage_key": "datasets/x"}, 422),
        ({**key}, {**good, "declared_size_bytes": 0}, 422),
        ({**key}, {**good, "declared_size_bytes": 25_000_001}, 422),
        ({**key}, {**good, "original_filename": "x" * 301}, 422),
        ({"Idempotency-Key": "short"}, good, 422),
        ({"Idempotency-Key": "k" * 129}, good, 422),
        ({"Idempotency-Key": "../../etc/passwd-0000"}, good, 422),
        ({}, good, 400),
    ]
    for extra, body, expected in cases:
        kw: dict[str, Any] = {"content": body} if isinstance(body, bytes) else {"json": body}
        r = up.c.post(path, headers={**up.h, **extra}, **kw)
        assert r.status_code == expected, (extra, body, r.text)
        text = r.text
        assert "Traceback" not in text and "psycopg" not in text and len(text) < 4096
    assert _rows(up.pg, "SELECT count(*) FROM dataset_versions WHERE dataset_id = %s", did) == [
        (0,)
    ]


def test_recorded_content_can_never_be_replaced_by_the_service(up: SimpleNamespace) -> None:
    """The service-level write-once guard on its own (the object store and the
    database trigger are separate layers with their own tests)."""
    from nlw.datasets import ingestion
    from nlw.tenancy.context import Role, TenantContext
    from nlw.tenancy.signing import Purpose

    did = _dataset(up)
    vid = _initiate(up, did)
    assert _put(up, did, vid, [CSV])[0] == 202
    ctx = TenantContext(user_id=up.user, tenant_id=up.tenant, role=Role.OWNER)
    signer = up.pg.signers[Purpose.API_REQUEST]
    d, v = uuid.UUID(did), uuid.UUID(vid)

    async def replace(sha: str) -> Any:
        return await ingestion.in_context(
            up.c.app.state.sessionmaker, signer, ctx,
            lambda s: svc.record_content(
                s, up.tenant, d, v, content_sha256=sha, storage_object_key="quarantine/x/y"
            ),
        )  # fmt: skip

    same = up.c.portal.call(replace, hashlib.sha256(CSV).hexdigest())
    assert same.content_sha256 == hashlib.sha256(CSV).hexdigest()  # an idempotent replay
    with pytest.raises(svc.DatasetConflict) as exc:
        up.c.portal.call(replace, hashlib.sha256(OTHER).hexdigest())
    assert exc.value.code == "CONTENT_CONFLICT"
    assert _version_row(up, vid)[1] == hashlib.sha256(CSV).hexdigest()


# --- 2. the complete permission matrix ------------------------------------------------------

MAPPING = {
    "columns": [
        {"name": "region", "label": "Region", "semantic_type": "category",
         "role": "dimension", "analysis_allowed": True},
        {"name": "amount", "label": "Amount", "semantic_type": "amount",
         "role": "measure", "analysis_allowed": True},
    ]
}  # fmt: skip


def _routes(did: str, vid: str) -> list[tuple[str, str, dict[str, Any], int]]:
    """(method, path, kwargs, admin's expected status), in a valid order."""
    v = f"/datasets/{did}/versions/{vid}"
    return [
        ("post", f"/datasets/{did}/versions",
         {"json": {"original_filename": "b.csv", "declared_size_bytes": len(CSV)},
          "key": True}, 201),
        ("put", f"{v}/content", {"content": CSV}, 202),
        ("post", f"{v}/process", {}, 202),
        ("get", f"{v}/profile", {}, 200),
        ("get", f"{v}/semantics", {}, 200),
        ("post", f"{v}/semantics", {"json": MAPPING}, 201),
        ("post", f"{v}/activate", {}, 200),
        ("delete", v, {}, 202),
        ("delete", f"/datasets/{did}", {}, 202),
    ]  # fmt: skip


def _call(
    up: SimpleNamespace, method: str, path: str, kw: dict[str, Any], h: dict[str, str]
) -> Any:
    kw = dict(kw)
    headers = {**h, **({"Idempotency-Key": uuid.uuid4().hex} if kw.pop("key", False) else {})}
    return getattr(up.c, method)(path, headers=headers, **kw)


def test_every_route_admits_exactly_admins_and_owners_of_the_workspace(
    up: SimpleNamespace,
) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)  # a real version every probe aims at
    assert _put(up, did, vid, [CSV])[0] == 202
    member = up.pg.add_membership(up.tenant, "member")
    removed = up.pg.add_membership(up.tenant, "admin")
    _rows_exec(up.pg, "DELETE FROM memberships WHERE user_id = %s", removed)
    outsider = up.pg.seed_member("owner")  # an owner, of ANOTHER workspace
    denied = {
        "anonymous": ({"X-Workspace-Id": str(up.tenant)}, 401),
        "member": (_hdr(member, up.tenant), 403),
        "removed admin": (_hdr(removed, up.tenant), 403),
        "non-member owner": (_hdr(outsider.user_id, up.tenant), 403),
        "forged bearer": ({"Authorization": "Bearer x.y.z", "X-Workspace-Id": str(up.tenant)},
                          401),
    }  # fmt: skip
    before = (_version_row(up, vid), _events(up, vid), len(up.rt.sent))
    for who, (h, expected) in denied.items():
        for method, path, kw, _ in _routes(did, vid):
            r = _call(up, method, path, kw, h)
            assert r.status_code == expected, (who, method, path, r.status_code)
    assert (_version_row(up, vid), _events(up, vid), len(up.rt.sent)) == before
    assert _rows(up.pg, "SELECT status FROM datasets WHERE id = %s", did) == [("ACTIVE",)]

    # Admins and owners: the whole lifecycle, each on its own dataset.
    admin = up.pg.add_membership(up.tenant, "admin")
    for h in (_hdr(admin, up.tenant), up.h):
        d = _dataset(up)
        v = _initiate(up, d)
        for method, path, kw, expected in _routes(d, v):
            r = _call(up, method, path, kw, h)
            assert r.status_code == expected, (method, path, r.text)


def test_identifiers_cannot_be_swapped_between_datasets_or_workspaces(up: SimpleNamespace) -> None:
    a, b = _dataset(up), _dataset(up)
    va = _initiate(up, a)
    assert _put(up, a, va, [CSV])[0] == 202
    before = (_version_row(up, va), _events(up, va), len(up.rt.sent))
    # A's version under B's id (same workspace), and random ids: all 404.
    for d, v in ((b, va), (a, str(uuid.uuid4())), (str(uuid.uuid4()), va)):
        for method, path, kw, _ in _routes(d, v)[1:-1]:
            r = _call(up, method, path, kw, up.h)
            assert r.status_code == 404, (d == b, method, path, r.status_code)
            assert "quarantine" not in r.text and str(up.tenant) not in r.text
    assert (_version_row(up, va), _events(up, va), len(up.rt.sent)) == before
