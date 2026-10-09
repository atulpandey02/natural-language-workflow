"""The upload API on the ingest boundary (ADR-031): durable processing requests,
commit-before-enqueue, recovery of a lost enqueue, harmless redelivery and
response hygiene. The API never processes; ``ingest_runtime`` stands in for
the queue and the dedicated ingest runtime (``nlw_ingest``)."""

import asyncio
import json
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from nlw.api.app import create_app
from nlw.datasets import ingestion, processing_requests
from nlw.datasets import service as svc
from nlw.datasets.envelope import WorkEnvelope
from nlw.ops import datasets as ops
from nlw.storage.blob import LocalBlobStore, TenantScopedBlobStore
from nlw.tenancy.context import Role, TenantContext
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

_SECRET = "dev-secret-for-tests-32bytes-min-length"
CSV = b"region,amount\n" + b"".join(f"r{i % 3},{i}\n".encode() for i in range(30))


def _hdr(user_id: uuid.UUID, tenant_id: uuid.UUID, **extra: str) -> dict[str, str]:
    token = jwt.encode(
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
    return {"Authorization": f"Bearer {token}", "X-Workspace-Id": str(tenant_id), **extra}


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
        }
    )
    m = pg_stack.seed_member("owner")
    with TestClient(create_app(settings)) as c:
        rt = ingest_runtime.attach(c.app, monkeypatch)
        yield SimpleNamespace(c=c, rt=rt, h=_hdr(m.user_id, m.tenant_id), tenant=m.tenant_id,
                              user=m.user_id, pg=pg_stack)  # fmt: skip


def _dataset(up: SimpleNamespace) -> str:
    r = up.c.post("/datasets", headers=up.h, json={"name": f"d-{uuid.uuid4().hex[:6]}"})
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def _initiate(up: SimpleNamespace, did: str, data: bytes = CSV, **kw: Any) -> str:
    r = up.c.post(
        f"/datasets/{did}/versions",
        headers={**up.h, "Idempotency-Key": uuid.uuid4().hex},
        json={"original_filename": kw.get("filename", "a.csv"), "declared_size_bytes": len(data)},
    )
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def _owner_rows(pg: SimpleNamespace, sql: str, *args: Any) -> list[tuple[Any, ...]]:
    with psycopg.connect(pg.owner_libpq) as c:
        return c.execute(sql, args).fetchall()


def _requests(pg: SimpleNamespace, vid: str) -> list[uuid.UUID]:
    rows = _owner_rows(
        pg,
        "SELECT id FROM dataset_processing_requests WHERE version_id = %s ORDER BY requested_at",
        vid,
    )
    return [r[0] for r in rows]


def _status(up: SimpleNamespace, did: str, vid: str) -> str:
    r = up.c.get(f"/datasets/{did}/versions/{vid}", headers=up.h)
    assert r.status_code == 200
    return str(r.json()["status"])


# --- commit before enqueue; recovery of a lost enqueue -------------------------------------


def test_a_failed_enqueue_keeps_the_request_and_a_retried_upload_recovers_it(
    up: SimpleNamespace,
) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)
    up.rt.fail = True  # the broker is down
    put = up.c.put(f"/datasets/{did}/versions/{vid}/content", headers=up.h, content=CSV)
    assert put.status_code == 503 and put.json()["error"]["code"] == "PROCESSING_NOT_QUEUED"
    assert _status(up, did, vid) == "QUARANTINED"
    requests = _requests(up.pg, vid)
    assert len(requests) == 1  # the content and its request committed together
    up.rt.fail = False
    retry = up.c.put(f"/datasets/{did}/versions/{vid}/content", headers=up.h, content=CSV)
    assert retry.status_code == 202, retry.text
    assert [e.request_id for e in up.rt.sent] == requests  # the SAME request, re-sent
    assert _status(up, did, vid) == "PROFILED"


def test_a_redispatch_never_processes_and_reuses_or_renews_the_request(
    up: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)
    up.rt.auto = False  # messages are queued, nobody consumes yet
    assert (
        up.c.put(f"/datasets/{did}/versions/{vid}/content", headers=up.h, content=CSV).status_code
        == 202
    )
    assert _status(up, did, vid) == "QUARANTINED"  # the API did NOT process
    r = up.c.post(f"/datasets/{did}/versions/{vid}/process", headers=up.h)
    assert r.status_code == 202 and r.json()["status"] == "QUARANTINED"
    assert len(_requests(up.pg, vid)) == 1 and len(up.rt.sent) == 2  # reused, re-sent
    monkeypatch.setattr(processing_requests, "REUSE_MAX_AGE_S", 0)  # the request went stale
    up.c.post(f"/datasets/{did}/versions/{vid}/process", headers=up.h)
    assert len(_requests(up.pg, vid)) == 2  # a fresh immutable request was recorded
    assert up.rt.process(up.rt.sent[-1].to_json()) == "profiled"
    assert _status(up, did, vid) == "PROFILED"
    # Settled: a further re-dispatch sends nothing and records nothing.
    before = len(up.rt.sent)
    assert up.c.post(f"/datasets/{did}/versions/{vid}/process", headers=up.h).status_code == 202
    assert len(up.rt.sent) == before and len(_requests(up.pg, vid)) == 2


def test_the_operator_sweep_reenqueues_only_waiting_fresh_requests(
    up: SimpleNamespace,
) -> None:
    did = _dataset(up)
    waiting = _initiate(up, did)
    done = _initiate(up, did)
    up.c.put(f"/datasets/{did}/versions/{done}/content", headers=up.h, content=CSV)  # processed
    up.rt.fail = True
    up.c.put(f"/datasets/{did}/versions/{waiting}/content", headers=up.h, content=CSV)  # lost
    up.rt.fail = False

    class Broker:
        def __init__(self) -> None:
            self.sent: list[Any] = []

        def enqueue(self, message: Any, *, delay: int | None = None) -> Any:
            self.sent.append(message)
            return message

    broker = Broker()
    with psycopg.connect(up.pg.owner_libpq, autocommit=True) as c:
        assert ops.dispatch_pending(c, broker, dry_run=True) == {
            "enqueued": 0, "pending": 1, "stale": 0, "more": 0, "busy": 0,
        }  # fmt: skip
        assert broker.sent == []
        assert ops.dispatch_pending(c, broker, dry_run=False)["enqueued"] == 1
    (message,) = broker.sent
    assert (message.queue_name, message.actor_name) == ("dataset_ingest", "process_dataset_version")
    env = json.loads(message.args[0])
    assert env["version_id"] == waiting and set(env) == {
        "v", "request_id", "tenant_id", "dataset_id", "version_id", "content_sha256",
        "requested_at_us", "envelope_sha256",
    }  # fmt: skip
    assert up.rt.process(message.args[0]) == "profiled"
    with psycopg.connect(up.pg.owner_libpq, autocommit=True) as c:
        assert ops.dispatch_pending(c, broker, dry_run=True)["pending"] == 0  # nothing left


# --- redelivery and injection ---------------------------------------------------------------


def test_duplicate_and_forged_deliveries_change_nothing(up: SimpleNamespace) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)
    up.c.put(f"/datasets/{did}/versions/{vid}/content", headers=up.h, content=CSV)
    (env,) = up.rt.sent
    events = _owner_rows(up.pg, "SELECT event_type FROM dataset_events WHERE version_id = %s", vid)
    for _ in range(2):
        assert up.rt.process(env.to_json()) == "skipped"  # redelivered: idempotent
    assert (
        _owner_rows(up.pg, "SELECT event_type FROM dataset_events WHERE version_id = %s", vid)
        == events
    )
    assert _owner_rows(
        up.pg, "SELECT count(*) FROM dataset_profiles WHERE version_id = %s", vid
    ) == [(1,)]
    # An injected message for a version nobody requested is refused.
    other = _initiate(up, did)
    forged = WorkEnvelope(
        request_id=uuid.uuid4(), tenant_id=up.tenant, dataset_id=uuid.UUID(did),
        version_id=uuid.UUID(other), content_sha256="a" * 64, requested_at_us=env.requested_at_us,
        envelope_sha256="",
    )  # fmt: skip
    forged = WorkEnvelope(**{**forged.__dict__, "envelope_sha256": forged.recomputed_digest()})
    assert up.rt.process(forged.to_json()) == "refused"
    assert _status(up, did, other) == "QUARANTINED"


# --- response hygiene ------------------------------------------------------------------------


def test_responses_never_expose_keys_tokens_or_queue_internals(up: SimpleNamespace) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)
    put = up.c.put(f"/datasets/{did}/versions/{vid}/content", headers=up.h, content=CSV)
    (env,) = up.rt.sent
    bodies = [
        put.text,
        up.c.get(f"/datasets/{did}/versions/{vid}", headers=up.h).text,
        up.c.get(f"/datasets/{did}/versions", headers=up.h).text,
        up.c.get(f"/datasets/{did}/versions/{vid}/profile", headers=up.h).text,
        up.c.post(f"/datasets/{did}/versions/{vid}/process", headers=up.h).text,
    ]
    version = json.loads(bodies[1])
    for forbidden in ("storage_object_key", "processing_lease_token", "processing_lease",
                      "upload_idempotency_key", "request_id", "envelope"):  # fmt: skip
        assert forbidden not in version, forbidden
    for body in bodies:
        for leak in ("quarantine/", "datasets/", str(env.request_id), env.envelope_sha256,
                     str(up.pg.signers[Purpose.DATASET_INGEST].key_id), "r1,1"):  # fmt: skip
            assert leak not in body, leak


def test_malformed_identifiers_are_refused(up: SimpleNamespace) -> None:
    did = _dataset(up)
    h = {**up.h, "Idempotency-Key": "k"}
    for r in (
        up.c.put("/datasets/not-a-uuid/versions/also-not/content", headers=h, content=CSV),
        up.c.post(f"/datasets/{did}/versions/1/process", headers=h),
        up.c.get(f"/datasets/{did}/versions/..%2F..%2Fx/profile", headers=h),
        up.c.post("/datasets/%2e%2e/versions", headers=h, json={}),
    ):
        assert r.status_code in (404, 405, 422), (r.request.url, r.status_code)
        assert "quarantine/" not in r.text and "Traceback" not in r.text


def test_filenames_are_metadata_only(up: SimpleNamespace) -> None:
    did = _dataset(up)
    checked = 0
    for name in ("../../etc/passwd.csv", "..\\..\\x.csv", "/abs/path.csv", "a/b.csv",
                 "Q3 report (final).csv"):  # fmt: skip
        r = up.c.post(
            f"/datasets/{did}/versions",
            headers={**up.h, "Idempotency-Key": uuid.uuid4().hex},
            json={"original_filename": name, "declared_size_bytes": len(CSV)},
        )
        if r.status_code == 422:
            continue  # refused outright
        assert r.status_code == 201, r.text
        vid = r.json()["id"]
        assert (
            "/" not in r.json()["original_filename"] and "\\" not in r.json()["original_filename"]
        )
        assert up.c.put(f"/datasets/{did}/versions/{vid}/content", headers=up.h,
                        content=CSV).status_code == 202  # fmt: skip
        key = _owner_rows(
            up.pg, "SELECT storage_object_key FROM dataset_versions WHERE id = %s", vid
        )[0][0]
        assert key == f"versions/{up.tenant}/{did}/{vid}/source.csv"  # from ids, never the name
        checked += 1
    assert checked >= 1  # the key derivation was actually exercised


# --- an interrupted upload -------------------------------------------------------------------


async def test_an_interrupted_upload_records_nothing_and_leaves_no_bytes(
    pg_stack: SimpleNamespace, tmp_path: Path
) -> None:
    m = pg_stack.seed_member("owner")
    ctx = TenantContext(user_id=m.user_id, tenant_id=m.tenant_id, role=Role.OWNER)
    engine = create_async_engine(pg_stack.settings.database_url, pool_size=4)
    maker: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    signer = pg_stack.signers[Purpose.API_REQUEST]
    store = LocalBlobStore(tmp_path / "s")
    try:
        actor = svc.Actor.user(m.user_id)
        d = await ingestion.in_context(
            maker, signer, ctx,
            lambda s: svc.create_dataset(s, m.tenant_id, actor, name="i", description=None),
        )  # fmt: skip
        v = await ingestion.in_context(
            maker, signer, ctx,
            lambda s: svc.create_version(
                s, m.tenant_id, actor, d.id, original_filename="a.csv", media_type="text/csv",
                declared_size_bytes=len(CSV), idempotency_key=uuid.uuid4().hex,
            ),
        )  # fmt: skip

        async def disconnecting() -> AsyncIterator[bytes]:
            yield CSV[:10]
            await asyncio.sleep(0)
            raise ConnectionResetError("client went away")

        with pytest.raises(ConnectionResetError):
            await ingestion.store_content(
                maker=maker, signer=signer, store=store, ctx=ctx, dataset_id=d.id,
                version_id=v.id, chunks=disconnecting(), max_bytes=10**6,
            )  # fmt: skip
        rec = await ingestion.in_context(
            maker, signer, ctx, lambda s: svc.get_version(s, m.tenant_id, d.id, v.id)
        )
        assert rec.has_content is False and rec.content_sha256 is None
        assert TenantScopedBlobStore(store, m.tenant_id).list_version(d.id, v.id) == []
        assert _owner_rows(
            pg_stack, "SELECT count(*) FROM dataset_processing_requests WHERE version_id = %s",
            v.id,
        ) == [(0,)]  # fmt: skip
    finally:
        await engine.dispose()


def test_only_an_admin_can_redispatch(up: SimpleNamespace) -> None:
    did = _dataset(up)
    vid = _initiate(up, did)
    up.rt.auto = False
    up.c.put(f"/datasets/{did}/versions/{vid}/content", headers=up.h, content=CSV)
    sent = len(up.rt.sent)
    member = _hdr(up.pg.add_membership(up.tenant, "member"), up.tenant)
    outsider_m = up.pg.seed_member("owner")
    outsider = _hdr(outsider_m.user_id, up.tenant)  # not a member of this workspace
    for h in (member, outsider):
        r = up.c.post(f"/datasets/{did}/versions/{vid}/process", headers=h)
        assert r.status_code == 403, r.text
    assert len(up.rt.sent) == sent and len(_requests(up.pg, vid)) == 1
