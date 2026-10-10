"""Pre-PR review (adversarial) scenarios for dataset ingestion (ADR-030, ADR-031).

The API side stores content and records the processing request; recovery runs
by delivering the version's envelope to the ingest runtime again (what a
re-dispatch, a client retry or the operator sweep does).

Crash windows are simulated by reproducing the exact state a process killed at
that point leaves behind (an object without a database record, a stale
PROFILING lease), then driving the normal recovery path. ADR-033 D1/D2: there
is one immutable object per version, never copied or deleted by a runtime, so
the former "published copy" and "bytes not yet removed" windows no longer
exist; their tests now prove that. Concurrency uses separate sessions or
requests that really race.
"""

import asyncio
import hashlib
import io
import json
import os
import threading
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
from nlw.datasets import ingestion
from nlw.datasets import service as svc
from nlw.datasets.deletion_log import LocalFakeDeletionLog
from nlw.datasets.envelope import WorkEnvelope
from nlw.datasets.lifecycle import VersionStatus
from nlw.datasets.processing_requests import ensure_processing_request
from nlw.datasets.service import Actor
from nlw.ingest.strict import StrictLimits
from nlw.ingest_service import processing
from nlw.ops import datasets as ops
from nlw.storage.blob import LocalBlobStore, TenantScopedBlobStore
from nlw.tenancy.context import Role, TenantContext
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

CSV = b"region,amount\n" + b"".join(f"r{i % 4},{i}\n".encode() for i in range(40))
OTHER = b"region,amount\n" + b"".join(f"s{i % 4},{i}\n".encode() for i in range(40))
assert len(CSV) == len(OTHER)
CONFIG = processing.IngestionConfig(limits=StrictLimits(timeout_s=30), memory_mb=768)


class H:
    def __init__(self, pg: SimpleNamespace, root: Path) -> None:
        m = pg.seed_member("owner")
        self.pg = pg
        self.ctx = TenantContext(user_id=m.user_id, tenant_id=m.tenant_id, role=Role.OWNER)
        self.engine = create_async_engine(pg.settings.database_url, pool_size=10)
        self.maker: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.engine, expire_on_commit=False
        )
        self.signer = pg.signers[Purpose.API_REQUEST]
        pg.enable_ingest()
        self.ingest_engine = create_async_engine(pg.ingest_sa, pool_size=10)
        self.ingest_maker: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.ingest_engine, expire_on_commit=False
        )
        self.ingest_signer = pg.signers[Purpose.DATASET_INGEST]
        self.envelopes: dict[uuid.UUID, WorkEnvelope] = {}
        self.store = LocalBlobStore(root)
        self.scoped = TenantScopedBlobStore(self.store, self.ctx.tenant_id)

    def as_user(self, user: uuid.UUID, role: Role) -> TenantContext:
        return TenantContext(user_id=user, tenant_id=self.ctx.tenant_id, role=role)

    async def run(self, fn: Any, ctx: TenantContext | None = None) -> Any:
        return await ingestion.in_context(self.maker, self.signer, ctx or self.ctx, fn)

    async def dataset(self) -> uuid.UUID:
        t, a = self.ctx.tenant_id, Actor.user(self.ctx.user_id)
        d = await self.run(
            lambda s: svc.create_dataset(
                s, t, a, name=f"d-{uuid.uuid4().hex[:8]}", description=None
            )
        )
        return d.id  # type: ignore[no-any-return]

    async def version(
        self, d: uuid.UUID, *, size: int = len(CSV), name: str = "a.csv", key: str | None = None
    ) -> uuid.UUID:
        t, a = self.ctx.tenant_id, Actor.user(self.ctx.user_id)
        v = await self.run(
            lambda s: svc.create_version(
                s, t, a, d, original_filename=name, media_type="text/csv",
                declared_size_bytes=size, idempotency_key=key or uuid.uuid4().hex,
            )
        )  # fmt: skip
        return v.id  # type: ignore[no-any-return]

    async def put(self, d: uuid.UUID, v: uuid.UUID, data: bytes = CSV) -> svc.VersionRecord:
        async def chunks() -> AsyncIterator[bytes]:
            for i in range(0, len(data), 7):  # many small chunks
                yield data[i : i + 7]

        rec, env = await ingestion.store_content(
            maker=self.maker, signer=self.signer, store=self.store, ctx=self.ctx,
            dataset_id=d, version_id=v, chunks=chunks(), max_bytes=25_000_000,
        )  # fmt: skip
        if env is not None:
            self.envelopes[v] = env
        return rec

    async def process(self, d: uuid.UUID, v: uuid.UUID) -> str:
        """Deliver the version's envelope to the ingest runtime (again)."""
        return await processing.process_envelope(
            maker=self.ingest_maker, signer=self.ingest_signer, store=self.store,
            config=CONFIG, message=self.envelopes[v].to_json(),
        )  # fmt: skip

    async def lease(self, d: uuid.UUID, v: uuid.UUID) -> None:
        """Another (later crashed) ingest delivery holds the lease."""
        await processing.in_ingest_context(
            self.ingest_maker, self.ingest_signer, self.envelopes[v],
            lambda s: svc.acquire_processing_lease(
                s, self.ctx.tenant_id, processing.ACTOR, d, v, token=uuid.uuid4(), ttl_s=300
            ),
        )  # fmt: skip

    async def get(self, d: uuid.UUID, v: uuid.UUID) -> svc.VersionRecord:
        t = self.ctx.tenant_id
        rec: svc.VersionRecord = await self.run(lambda s: svc.get_version(s, t, d, v))
        return rec

    def age_lease(self, v: uuid.UUID) -> None:
        """What a crash leaves behind, an hour later: a stale PROFILING lease."""
        with psycopg.connect(self.pg.owner_libpq, autocommit=True) as c:
            # The crashed processor's lease, expired by the DATABASE clock.
            c.execute(
                "UPDATE dataset_versions "
                "SET processing_lease_expires_at = now() - interval '1 hour' WHERE id = %s",
                (v,),
            )

    def verify(self) -> dict[str, list[str]]:
        with psycopg.connect(self.pg.owner_libpq, autocommit=True) as c:
            return ops.verify_objects(c, self.store)


@pytest.fixture
async def h(pg_stack: SimpleNamespace, tmp_path: Path) -> AsyncIterator[H]:
    harness = H(pg_stack, tmp_path / "store")
    yield harness
    await harness.engine.dispose()
    await harness.ingest_engine.dispose()


# --- crash windows -------------------------------------------------------------------------


async def test_crash_after_the_object_is_written_but_before_the_db_commit(h: H) -> None:
    d = await h.dataset()
    v = await h.version(d)
    # The killed request linked the object, but never recorded it.
    h.scoped.put_stream(h.scoped.object_key(d, v), io.BytesIO(CSV), max_bytes=10**6)
    assert (await h.get(d, v)).has_content is False
    assert h.verify()["unaccounted_objects"] == [str(v)]  # visible to the operator
    # A retry with DIFFERENT bytes can never replace it ...
    with pytest.raises(ingestion.ContentError) as exc:
        await h.put(d, v, OTHER)
    assert exc.value.code == "CONTENT_CONFLICT"
    # ... the identical retry adopts it, and processing proceeds normally.
    rec = await h.put(d, v, CSV)
    assert rec.has_content and rec.content_sha256 == hashlib.sha256(CSV).hexdigest()
    assert await h.process(d, v) == "profiled"
    assert h.verify() == {"missing_objects": [], "digest_mismatches": [], "unaccounted_objects": [],
                          "noncurrent_versions": []}  # fmt: skip


async def test_crash_after_profiling_started_but_before_the_profile_is_stored(h: H) -> None:
    d = await h.dataset()
    v = await h.version(d)
    await h.put(d, v)
    await h.lease(d, v)
    assert await h.process(d, v) == "skipped"  # a live lease is respected
    h.age_lease(v)
    assert await h.process(d, v) == "profiled"


async def test_publishing_neither_copies_nor_moves_the_object(h: H) -> None:
    """ADR-033 D1: no crash window exists between a copy and the publish commit,
    because there is no copy: the one object is profiled in place and stays."""
    d = await h.dataset()
    v = await h.version(d)
    await h.put(d, v)
    key = h.scoped.object_key(d, v)
    before = h.scoped.digest(key)
    assert await h.process(d, v) == "profiled"
    assert h.scoped.list_version(d, v) == [key] and h.scoped.digest(key) == before
    assert (await h.get(d, v)).status is VersionStatus.PROFILED
    assert h.verify()["unaccounted_objects"] == []


async def test_a_rejected_object_is_kept_and_reprocessing_changes_nothing(h: H) -> None:
    """ADR-033 D2: rejection deletes nothing (no "bytes not yet removed" window);
    a redelivery changes nothing; only the operator purge removes the object."""
    bad = b"a,a\n1,2\n"
    d = await h.dataset()
    v = await h.version(d, size=len(bad))
    await h.put(d, v, bad)
    assert await h.process(d, v) == "rejected"
    key = h.scoped.object_key(d, v)
    assert h.scoped.list_version(d, v) == [key]
    assert await h.process(d, v) == "skipped"
    assert h.scoped.list_version(d, v) == [key]
    assert (await h.get(d, v)).status is VersionStatus.REJECTED
    t, a = h.ctx.tenant_id, Actor.user(h.ctx.user_id)
    await h.run(lambda s: svc.request_version_deletion(s, t, a, d, v))
    with psycopg.connect(h.pg.owner_libpq, autocommit=True) as c:
        log = LocalFakeDeletionLog(Path(h.store.root).parent / "receipts.jsonl")
        result = ops.purge(c, h.store, log, dataset_id=d, version_id=v, operator="op",
                           environment="local")  # fmt: skip
    assert result["objects_deleted"] == 1 and h.scoped.list_version(d, v) == []


async def test_tombstone_refuses_orphan_bytes_of_a_version_without_a_key(h: H) -> None:
    """A crash after the object was linked but before it was recorded leaves bytes
    that no storage key points at. The tombstone must still see them."""
    d = await h.dataset()
    v = await h.version(d)
    h.scoped.put_stream(h.scoped.object_key(d, v), io.BytesIO(CSV), max_bytes=10**6)
    t, a = h.ctx.tenant_id, Actor.user(h.ctx.user_id)
    await h.run(lambda s: svc.request_version_deletion(s, t, a, d, v))
    with psycopg.connect(h.pg.owner_libpq, autocommit=True) as c:
        with pytest.raises(ops.TombstoneError, match="still present"):
            ops.tombstone(c, dataset_id=d, version_id=v, store=h.store)
        log = LocalFakeDeletionLog(Path(h.store.root).parent / "receipts.jsonl")
        assert ops.purge(c, h.store, log, dataset_id=d, version_id=v, operator="op",
                         environment="local")["objects_deleted"] == 1  # fmt: skip
        # The keyless version's purge produced evidence and a receipt: the
        # tombstone verifies that receipt too.
        assert (
            ops.tombstone(c, dataset_id=d, version_id=v, store=h.store, log=log)[
                "versions_tombstoned"
            ]
            == 1
        )


# --- concurrency and conflicting uploads ---------------------------------------------------


async def test_simultaneous_identical_content_uploads_store_one_object(h: H) -> None:
    d = await h.dataset()
    v = await h.version(d)
    results = await asyncio.gather(*(h.put(d, v) for _ in range(5)), return_exceptions=True)
    kinds = [
        type(r).__name__ + (f":{r.code}" if hasattr(r, "code") else f":{r!r}"[:120])
        if not isinstance(r, svc.VersionRecord)
        else "ok"
        for r in results
    ]
    assert kinds == ["ok"] * 5, kinds
    assert h.scoped.list_version(d, v) == [h.scoped.object_key(d, v)]


async def test_simultaneous_different_content_uploads_keep_exactly_one(h: H) -> None:
    d = await h.dataset()
    v = await h.version(d)
    results = await asyncio.gather(h.put(d, v, CSV), h.put(d, v, OTHER), return_exceptions=True)
    ok = [r for r in results if isinstance(r, svc.VersionRecord)]
    errors = [r for r in results if isinstance(r, ingestion.ContentError)]
    assert len(ok) == 1 and len(errors) == 1 and errors[0].code == "CONTENT_CONFLICT"
    stored = h.scoped.digest(h.scoped.object_key(d, v))[1]
    assert stored == ok[0].content_sha256  # the record and the bytes agree


async def test_one_key_two_files(h: H) -> None:
    d = await h.dataset()
    key = uuid.uuid4().hex
    v = await h.version(d, key=key)
    with pytest.raises(svc.DatasetConflict) as exc:
        await h.version(d, key=key, name="other.csv")
    assert exc.value.code == "IDEMPOTENCY_KEY_REUSED"
    # Same name and size but different bytes: the same version; the second
    # file can never replace the first.
    assert await h.version(d, key=key) == v
    await h.put(d, v, CSV)
    with pytest.raises(ingestion.ContentError) as content:
        await h.put(d, v, OTHER)
    assert content.value.code == "CONTENT_CONFLICT"


async def test_same_bytes_under_different_filenames_are_separate_versions(h: H) -> None:
    d = await h.dataset()
    v1, v2 = await h.version(d, name="jan.csv"), await h.version(d, name="feb.csv")
    for v in (v1, v2):
        await h.put(d, v)
        assert await h.process(d, v) == "profiled"
    r1, r2 = await h.get(d, v1), await h.get(d, v2)
    assert r1.content_sha256 == r2.content_sha256 and r1.version_number != r2.version_number
    assert h.scoped.list_version(d, v1) != h.scoped.list_version(d, v2)  # separate objects


# --- tampering, deletion races, receipts -----------------------------------------------------


async def test_tampering_after_publication_is_reported_by_restore_validation(h: H) -> None:
    d = await h.dataset()
    v = await h.version(d)
    await h.put(d, v)
    assert await h.process(d, v) == "profiled"
    (h.store.root / h.scoped.object_key(d, v)).write_bytes(OTHER)
    assert h.verify()["digest_mismatches"] == [str(v)]


async def test_activation_while_deletion_is_requested_is_refused(h: H) -> None:
    d = await h.dataset()
    v = await h.version(d)
    await h.put(d, v)
    await h.process(d, v)
    t, a = h.ctx.tenant_id, Actor.user(h.ctx.user_id)
    mapping = json.dumps({"contract_version": "semantics-1", "columns": [
        {"name": "region", "label": "Region", "semantic_type": "category", "role": "dimension",
         "analysis_allowed": True, "description": None},
        {"name": "amount", "label": "Amount", "semantic_type": "count", "role": "measure",
         "analysis_allowed": True, "description": None}]})  # fmt: skip
    await h.run(lambda s: svc.confirm_semantics(s, t, a, d, v, mapping_json=mapping))
    await h.run(lambda s: svc.request_dataset_deletion(s, t, a, d))
    with pytest.raises(svc.DatasetConflict):
        await h.run(lambda s: svc.activate_version(s, t, a, d, v))
    assert (await h.get(d, v)).status is VersionStatus.DELETING


# --- authority changes -------------------------------------------------------------------------


async def test_only_an_admin_can_request_processing_and_another_admin_can_recover(
    h: H, pg_stack: SimpleNamespace
) -> None:
    """ADR-031: a member, or someone who is not a member at all, can neither
    record nor re-dispatch a processing request; another admin can, and the
    ingest runtime then processes it."""
    from sqlalchemy.exc import DBAPIError

    d = await h.dataset()
    v = await h.version(d)
    await h.put(d, v)
    member = h.as_user(pg_stack.add_membership(h.ctx.tenant_id, "member"), Role.MEMBER)
    outsider = pg_stack.seed_member("owner")
    foreign = TenantContext(user_id=outsider.user_id, tenant_id=h.ctx.tenant_id, role=Role.OWNER)
    for ctx in (member, foreign):  # a member, or not a member at all
        with pytest.raises((svc.DatasetError, DBAPIError)):
            await h.run(
                lambda s, c=ctx: ensure_processing_request(s, c.tenant_id, c.user_id, d, v),
                ctx=ctx,
            )
        assert (await h.get(d, v)).status is VersionStatus.QUARANTINED
    other_admin = h.as_user(pg_stack.add_membership(h.ctx.tenant_id, "admin"), Role.ADMIN)
    env = await h.run(
        lambda s: ensure_processing_request(s, h.ctx.tenant_id, other_admin.user_id, d, v),
        ctx=other_admin,
    )
    assert env is not None and env.request_id == h.envelopes[v].request_id  # reused, fresh
    assert await h.process(d, v) == "profiled"


# --- profiler process cleanup -----------------------------------------------------------------


async def test_a_cancelled_profiling_run_kills_its_child(monkeypatch: pytest.MonkeyPatch) -> None:
    procs: list[asyncio.subprocess.Process] = []
    real = asyncio.create_subprocess_exec

    async def capture(*a: Any, **k: Any) -> asyncio.subprocess.Process:
        p = await real(*a, **k)
        procs.append(p)
        return p

    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture)
    release = threading.Event()

    class Slow(io.RawIOBase):
        def readable(self) -> bool:
            return True

        def read(self, n: int | None = -1) -> bytes:
            release.wait(5)
            return b""

    def opener() -> Any:
        return Slow()

    task = asyncio.create_task(processing.run_profiler(opener, CONFIG))
    for _ in range(100):
        if procs:
            break
        await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    proc = procs[0]
    for _ in range(100):
        if proc.returncode is not None:
            break
        await asyncio.sleep(0.05)
    assert proc.returncode is not None, "the profiler child outlived its cancelled parent"


# --- values never reach logs or error responses ---------------------------------------------


_SECRET = "dev-secret-for-tests-32bytes-min-length"


def _hdr(user_id: uuid.UUID, tenant_id: uuid.UUID, **extra: str) -> dict[str, str]:
    token = jwt.encode(
        {"iss": "https://proj.supabase.co/auth/v1", "aud": "authenticated",
         "exp": int(time.time()) + 300, "sub": f"sub-{user_id}", "email": f"{user_id}@example.com"},
        _SECRET, algorithm="HS256",
    )  # fmt: skip
    return {"Authorization": f"Bearer {token}", "X-Workspace-Id": str(tenant_id), **extra}


@pytest.fixture
def api(
    pg_stack: SimpleNamespace,
    tmp_path: Path,
    ingest_runtime: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[TestClient]:
    settings = pg_stack.settings.model_copy(
        update={
            "datasets_api_enabled": True,
            "dataset_storage_backend": "local",
            "dataset_storage_root": str(tmp_path / "api-store"),
        }  # fmt: skip
    )
    with TestClient(create_app(settings)) as c:
        ingest_runtime.attach(c.app, monkeypatch)  # the queue + the ingest runtime
        yield c


def test_formula_and_sensitive_values_never_reach_logs_errors_or_the_profile(
    api: TestClient, pg_stack: SimpleNamespace, capfd: pytest.CaptureFixture[str], caplog: Any
) -> None:
    m = pg_stack.seed_member("owner")
    h = _hdr(m.user_id, m.tenant_id)
    ssn, mail, formula = "123-45-6789", "zz.canary@example.test", '=HYPERLINK("http://x")'
    rows = [f'{ssn},{mail},"{formula.replace(chr(34), chr(34) * 2)}",{i}' for i in range(25)]
    good = ("national,contact,note,n\n" + "\n".join(rows) + "\n").encode()
    bad = good + f"{ssn},{mail}\n".encode()  # ragged last row -> rejected
    did = api.post("/datasets", headers=h, json={"name": "Canary"}).json()["id"]
    bodies: list[str] = []
    for data in (good, bad):
        r = api.post(
            f"/datasets/{did}/versions",
            headers={**h, "Idempotency-Key": uuid.uuid4().hex},
            json={"original_filename": "c.csv", "declared_size_bytes": len(data)},
        )
        vid = r.json()["id"]
        put = api.put(f"/datasets/{did}/versions/{vid}/content", headers=h, content=data)
        bodies += [r.text, put.text, api.get(f"/datasets/{did}/versions/{vid}", headers=h).text]
        prof = api.get(f"/datasets/{did}/versions/{vid}/profile", headers=h)
        bodies.append(prof.text)
    # A wrong-size retry error and a semantic error must not echo values either.
    bodies.append(api.put(f"/datasets/{did}/versions/{vid}/content", headers=h, content=good).text)
    out, err = capfd.readouterr()
    everything = out + err + caplog.text + "\n".join(bodies)
    for canary in (ssn, mail, "HYPERLINK", "http://x"):
        assert canary not in everything, canary
    assert os.environ.get("NLW_LLM_API_KEY", "") == "" or "NLW_LLM_API_KEY" not in everything


@pytest.mark.parametrize("ch", ["\u0085", "\u009f", "\u0080", "‮"])
def test_c1_and_format_characters_are_refused_in_every_api_metadata_field(
    api: TestClient, pg_stack: SimpleNamespace, ch: str
) -> None:
    m = pg_stack.seed_member("owner")
    h = _hdr(m.user_id, m.tenant_id)
    assert api.post("/datasets", headers=h, json={"name": f"Sales{ch}"}).status_code == 422
    assert (
        api.post(
            "/datasets", headers=h, json={"name": "Ok", "description": f"desc{ch}ription"}
        ).status_code
        == 422
    )
    did = api.post("/datasets", headers=h, json={"name": f"Ok-{ord(ch)}"}).json()["id"]
    r = api.post(
        f"/datasets/{did}/versions",
        headers={**h, "Idempotency-Key": uuid.uuid4().hex},
        json={"original_filename": f"a{ch}.csv", "declared_size_bytes": len(CSV)},
    )
    assert r.status_code == 422
    vid = api.post(
        f"/datasets/{did}/versions",
        headers={**h, "Idempotency-Key": uuid.uuid4().hex},
        json={"original_filename": "a.csv", "declared_size_bytes": len(CSV)},
    ).json()["id"]
    api.put(f"/datasets/{did}/versions/{vid}/content", headers=h, content=CSV)
    mapping = {"columns": [
        {"name": "region", "label": f"Reg{ch}ion", "semantic_type": "category",
         "role": "dimension", "analysis_allowed": True},
        {"name": "amount", "label": "Amount", "semantic_type": "count", "role": "measure",
         "analysis_allowed": True}]}  # fmt: skip
    sem = api.post(f"/datasets/{did}/versions/{vid}/semantics", headers=h, json=mapping)
    assert sem.status_code == 422
    bad_header = f"reg{ch}ion,amount\nx,1\n".encode()
    vid2 = api.post(
        f"/datasets/{did}/versions",
        headers={**h, "Idempotency-Key": uuid.uuid4().hex},
        json={"original_filename": "b.csv", "declared_size_bytes": len(bad_header)},
    ).json()["id"]
    api.put(f"/datasets/{did}/versions/{vid2}/content", headers=h, content=bad_header)
    got = api.get(f"/datasets/{did}/versions/{vid2}", headers=h).json()
    assert got["status"] == "REJECTED"
    assert got["rejection_code"] in ("CONTENT_BINARY", "HEADER_INVALID")
