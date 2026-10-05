"""Ingestion orchestration (ADR-030) against real PostgreSQL, the local store and
the isolated profiler process: authority, races, integrity and failure modes."""

import asyncio
import hashlib
import io
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import psycopg
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from nlw.datasets import ingestion
from nlw.datasets import service as svc
from nlw.datasets.service import Actor
from nlw.ingest.strict import StrictLimits
from nlw.storage.blob import LocalBlobStore, TenantScopedBlobStore
from nlw.tenancy.context import Role, TenantContext
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

CSV = b"region,amount\n" + b"".join(f"r{i % 4},{i}\n".encode() for i in range(50))
CONFIG = ingestion.IngestionConfig(limits=StrictLimits(timeout_s=30), memory_mb=768)


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
        self.store = LocalBlobStore(root)
        self.scoped = TenantScopedBlobStore(self.store, self.ctx.tenant_id)

    async def run(self, fn: Any, ctx: TenantContext | None = None) -> Any:
        return await ingestion.in_context(self.maker, self.signer, ctx or self.ctx, fn)

    async def version(self, data: bytes = CSV) -> tuple[uuid.UUID, uuid.UUID]:
        t, actor = self.ctx.tenant_id, Actor.user(self.ctx.user_id)
        d = await self.run(
            lambda s: svc.create_dataset(
                s, t, actor, name=f"d-{uuid.uuid4().hex[:6]}", description=None
            )
        )
        v = await self.run(
            lambda s: svc.create_version(
                s, t, actor, d.id, original_filename="a.csv", media_type="text/csv",
                declared_size_bytes=len(data), idempotency_key=uuid.uuid4().hex,
            )
        )  # fmt: skip
        return d.id, v.id

    async def store_content(self, d: uuid.UUID, v: uuid.UUID, data: bytes = CSV) -> None:
        async def chunks() -> AsyncIterator[bytes]:
            yield data

        await ingestion.store_content(
            maker=self.maker, signer=self.signer, store=self.store, ctx=self.ctx,
            dataset_id=d, version_id=v, chunks=chunks(), max_bytes=25_000_000,
        )  # fmt: skip

    async def process(self, d: uuid.UUID, v: uuid.UUID, ctx: TenantContext | None = None) -> str:
        return await ingestion.process_version(
            maker=self.maker, signer=self.signer, store=self.store, config=CONFIG,
            ctx=ctx or self.ctx, dataset_id=d, version_id=v,
        )  # fmt: skip

    async def get(self, d: uuid.UUID, v: uuid.UUID) -> svc.VersionRecord:
        t = self.ctx.tenant_id
        rec: svc.VersionRecord = await self.run(lambda s: svc.get_version(s, t, d, v))
        return rec


@pytest.fixture
async def h(pg_stack: SimpleNamespace, tmp_path: Path) -> AsyncIterator[H]:
    harness = H(pg_stack, tmp_path / "store")
    yield harness
    await harness.engine.dispose()


def _profiles(pg: SimpleNamespace, v: uuid.UUID) -> int:
    with psycopg.connect(pg.owner_libpq) as c:
        row = c.execute(
            "SELECT count(*) FROM dataset_profiles WHERE version_id = %s", (v,)
        ).fetchone()
    assert row is not None
    return int(row[0])


async def test_processing_publishes_once_under_concurrency(h: H) -> None:
    d, v = await h.version()
    await h.store_content(d, v)
    results = await asyncio.gather(*(h.process(d, v) for _ in range(4)))
    assert sorted(results) == ["profiled", "skipped", "skipped", "skipped"]
    rec = await h.get(d, v)
    assert rec.status.value == "PROFILED" and _profiles(h.pg, v) == 1
    assert h.scoped.list_version(d, v) == [h.scoped.version_key("datasets", d, v)]
    assert await h.process(d, v) == "skipped"  # nothing left to do


async def test_a_demoted_uploader_cannot_process(h: H, pg_stack: SimpleNamespace) -> None:
    d, v = await h.version()
    await h.store_content(d, v)
    demoted = pg_stack.add_membership(h.ctx.tenant_id, "member")
    member_ctx = TenantContext(user_id=demoted, tenant_id=h.ctx.tenant_id, role=Role.MEMBER)
    # RLS re-checks admin authority on every transaction: nothing moves.
    with pytest.raises(svc.DatasetError):  # invisible for update: nothing to claim
        await h.process(d, v, ctx=member_ctx)
    assert (await h.get(d, v)).status.value == "QUARANTINED"


async def test_tampered_bytes_are_rejected_before_profiling(h: H) -> None:
    d, v = await h.version()
    await h.store_content(d, v)
    key = h.scoped.version_key("quarantine", d, v)
    (h.store.root / key).write_bytes(CSV.replace(b"r1", b"r9"))  # same size, other bytes
    assert await h.process(d, v) == "rejected"
    rec = await h.get(d, v)
    assert (rec.status.value, rec.rejection_code and rec.rejection_code.value) == (
        "REJECTED",
        "CONTENT_MISMATCH",
    )
    assert h.scoped.list_version(d, v) == []  # rejected bytes are removed


async def test_a_missing_object_is_rejected(h: H) -> None:
    d, v = await h.version()
    await h.store_content(d, v)
    (h.store.root / h.scoped.version_key("quarantine", d, v)).unlink()
    assert await h.process(d, v) == "rejected"
    rec = await h.get(d, v)
    assert rec.rejection_code is not None and rec.rejection_code.value == "CONTENT_MISMATCH"


async def test_profiler_crash_and_timeout_reject_without_content(
    h: H, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def crashed(*_a: Any, **_k: Any) -> ingestion.ProfilerOutcome:
        return ingestion.ProfilerOutcome("rejected", code="PROCESSING_FAILED")

    d, v = await h.version()
    await h.store_content(d, v)
    monkeypatch.setattr(ingestion, "run_profiler", crashed)
    assert await h.process(d, v) == "rejected"
    assert (await h.get(d, v)).rejection_code.value == "PROCESSING_FAILED"  # type: ignore[union-attr]
    monkeypatch.undo()

    # A real wall-clock overrun: the child is killed and the version rejected.
    slow = ingestion.IngestionConfig(limits=StrictLimits(timeout_s=0.001), memory_mb=768)
    outcome = await ingestion.run_profiler(lambda: io.BytesIO(CSV * 2000), slow)
    assert (outcome.status, outcome.code) in {("rejected", "PARSE_TIMEOUT")}


async def test_a_stale_profiling_lease_is_reclaimed_after_a_crash(
    h: H, pg_stack: SimpleNamespace
) -> None:
    d, v = await h.version()
    await h.store_content(d, v)
    t, actor = h.ctx.tenant_id, Actor.service(h.ctx.user_id)

    await h.run(
        lambda s: svc.acquire_processing_lease(s, t, actor, d, v, token=uuid.uuid4(), ttl_s=300)
    )
    assert await h.process(d, v) == "skipped"  # a live lease is respected
    with psycopg.connect(pg_stack.owner_libpq, autocommit=True) as c:
        # A crashed processor's lease, expired by the DATABASE clock.
        c.execute(
            "UPDATE dataset_versions SET processing_lease_expires_at = now() - interval '1 hour' "
            "WHERE id = %s",
            (v,),
        )
    assert await h.process(d, v) == "profiled"


async def test_deletion_while_profiling_wins(h: H, monkeypatch: pytest.MonkeyPatch) -> None:
    d, v = await h.version()
    await h.store_content(d, v)
    real = ingestion.run_profiler
    t, actor = h.ctx.tenant_id, Actor.user(h.ctx.user_id)

    async def delete_then_profile(*a: Any, **k: Any) -> ingestion.ProfilerOutcome:
        await h.run(lambda s: svc.request_dataset_deletion(s, t, actor, d))
        return await real(*a, **k)

    monkeypatch.setattr(ingestion, "run_profiler", delete_then_profile)
    assert await h.process(d, v) == "skipped"
    rec = await h.get(d, v)
    assert rec.status.value == "DELETING" and _profiles(h.pg, v) == 0


async def test_stored_digest_matches_the_upload(h: H) -> None:
    d, v = await h.version()
    await h.store_content(d, v)
    rec = await h.get(d, v)
    assert rec.content_sha256 == hashlib.sha256(CSV).hexdigest() and rec.has_content


async def test_service_tenant_predicates_hold_even_without_rls(
    h: H, pg_stack: SimpleNamespace
) -> None:
    """Defence in depth: every ingestion read/write names the tenant explicitly,
    so even a session that BYPASSES RLS (the owner) cannot reach another
    tenant's version through the service with a guessed id."""
    d, v = await h.version()
    await h.store_content(d, v)
    assert await h.process(d, v) == "profiled"
    other = uuid.uuid4()
    owner_engine = create_async_engine(pg_stack.owner_sa)
    try:
        maker = async_sessionmaker(owner_engine, expire_on_commit=False)
        async with maker() as s, s.begin():
            with pytest.raises(svc.DatasetVersionNotFound):
                await svc.get_version(s, other, d, v)
            assert await svc.get_profile(s, other, d, v) is None
            assert await svc.storage_key(s, other, d, v) is None
            assert await svc.list_semantic_revisions(s, other, d, v) == []
            with pytest.raises(svc.DatasetNotFound):
                await svc.record_content(
                    s, other, d, v, content_sha256="0" * 64,
                    storage_object_key=f"quarantine/{other}/{d}/{v}",
                )  # fmt: skip
            # The right tenant still sees it through the same RLS-free session.
            assert (await svc.get_profile(s, h.ctx.tenant_id, d, v)) is not None
    finally:
        await owner_engine.dispose()


async def test_concurrent_initiations_with_one_key_create_exactly_one_version(h: H) -> None:
    """Separate sessions racing with the same Idempotency-Key: the dataset row
    lock taken BEFORE the key lookup serializes them, so every caller gets the
    same version and exactly one version number is allocated."""
    t, actor = h.ctx.tenant_id, Actor.user(h.ctx.user_id)
    d = await h.run(lambda s: svc.create_dataset(s, t, actor, name="Race", description=None))
    key = uuid.uuid4().hex
    gate = asyncio.Event()

    async def initiate(s: AsyncSession) -> svc.VersionRecord:
        await gate.wait()  # every session is open before any of them proceeds
        return await svc.create_version(
            s, t, actor, d.id, original_filename="a.csv", media_type="text/csv",
            declared_size_bytes=10, idempotency_key=key,
        )  # fmt: skip

    tasks = [asyncio.create_task(h.run(initiate)) for _ in range(6)]
    await asyncio.sleep(0)  # let every task open its transaction and wait on the gate
    gate.set()
    versions = await asyncio.gather(*tasks)
    assert len({v.id for v in versions}) == 1
    ds = await h.run(lambda s: svc.get_dataset(s, t, d.id))
    assert ds.last_version_number == 1
