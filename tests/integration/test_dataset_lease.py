"""Processing lease (ADR-030, ADR-031): database time, atomic claims, provable
ownership. Every lease operation runs as the ingest runtime (``nlw_ingest``,
a ``dataset_ingest`` context for exactly one version); the API role may not.

Every claimant runs in its own session and transaction; races are started
behind a gate so the database (one compare-and-set UPDATE per attempt), not
the test's ordering, decides who wins. The API host's clock is shifted by a
day in both directions to prove it is never consulted.
"""

import asyncio
import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import psycopg
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from nlw.datasets import ingestion
from nlw.datasets import service as svc
from nlw.datasets.envelope import WorkEnvelope
from nlw.datasets.lifecycle import RejectionCode, VersionStatus
from nlw.datasets.service import Actor, DatasetConflict
from nlw.ingest.strict import StrictLimits
from nlw.ingest_service import processing
from nlw.storage.blob import LocalBlobStore
from nlw.tenancy.context import Role, TenantContext
from nlw.tenancy.session import apply_signed_context
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

CSV = b"region,amount\n" + b"".join(f"r{i % 4},{i}\n".encode() for i in range(40))
PROFILE = json.dumps({"contract_version": "profile-2", "columns": []})


class H:
    def __init__(self, pg: SimpleNamespace, root: Path) -> None:
        m = pg.seed_member("owner")
        self.pg = pg
        self.ctx = TenantContext(user_id=m.user_id, tenant_id=m.tenant_id, role=Role.OWNER)
        self.t, self.actor = m.tenant_id, processing.ACTOR  # service, no human
        self.engine = create_async_engine(pg.settings.database_url, pool_size=12)
        self.maker: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.engine, expire_on_commit=False
        )
        self.signer = pg.signers[Purpose.API_REQUEST]
        pg.enable_ingest()
        self.ingest_engine = create_async_engine(pg.ingest_sa, pool_size=12)
        self.ingest_maker: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.ingest_engine, expire_on_commit=False
        )
        self.ingest_signer = pg.signers[Purpose.DATASET_INGEST]
        self.envelopes: dict[uuid.UUID, WorkEnvelope] = {}
        self.store = LocalBlobStore(root)

    async def run(self, fn: Any) -> Any:
        """One API transaction (signed api_request for the admin)."""
        return await ingestion.in_context(self.maker, self.signer, self.ctx, fn)

    async def ingest(self, v: uuid.UUID, fn: Any) -> Any:
        """One ingest-runtime transaction for exactly version ``v``."""
        async with self.ingest_maker() as s, s.begin():
            await apply_signed_context(
                s, self.pg.sign(Purpose.DATASET_INGEST, tenant_id=self.t, run_id=v)
            )
            return await fn(s)

    async def deliver(self, v: uuid.UUID, config: processing.IngestionConfig) -> str:
        return await processing.process_envelope(
            maker=self.ingest_maker, signer=self.ingest_signer, store=self.store,
            config=config, message=self.envelopes[v].to_json(),
        )  # fmt: skip

    async def quarantined(self) -> tuple[uuid.UUID, uuid.UUID]:
        t, a = self.t, Actor.user(self.ctx.user_id)
        d = await self.run(
            lambda s: svc.create_dataset(
                s, t, a, name=f"l-{uuid.uuid4().hex[:8]}", description=None
            )
        )

        async def chunks() -> AsyncIterator[bytes]:
            yield CSV

        v = await self.run(
            lambda s: svc.create_version(
                s, t, a, d.id, original_filename="a.csv", media_type="text/csv",
                declared_size_bytes=len(CSV), idempotency_key=uuid.uuid4().hex,
            )
        )  # fmt: skip
        _, env = await ingestion.store_content(
            maker=self.maker, signer=self.signer, store=self.store, ctx=self.ctx,
            dataset_id=d.id, version_id=v.id, chunks=chunks(), max_bytes=10**6,
        )  # fmt: skip
        assert env is not None
        self.envelopes[v.id] = env
        return d.id, v.id

    async def acquire(self, d: uuid.UUID, v: uuid.UUID, token: uuid.UUID) -> str:
        state, _ = await self.ingest(
            v,
            lambda s: svc.acquire_processing_lease(
                s, self.t, self.actor, d, v, token=token, ttl_s=300
            ),
        )
        return str(state)

    def expire(self, v: uuid.UUID) -> None:
        with psycopg.connect(self.pg.owner_libpq, autocommit=True) as c:
            c.execute(
                "UPDATE dataset_versions "
                "SET processing_lease_expires_at = now() - interval '1 hour' WHERE id = %s",
                (v,),
            )

    def lease(self, v: uuid.UUID) -> tuple[Any, ...]:
        with psycopg.connect(self.pg.owner_libpq) as c:
            row = c.execute(
                "SELECT status, processing_lease_token, processing_lease_expires_at > now() "
                "FROM dataset_versions WHERE id = %s",
                (v,),
            ).fetchone()
        assert row is not None
        return tuple(row)

    def profiles(self, v: uuid.UUID) -> int:
        with psycopg.connect(self.pg.owner_libpq) as c:
            row = c.execute(
                "SELECT count(*) FROM dataset_profiles WHERE version_id = %s", (v,)
            ).fetchone()
        assert row is not None
        return int(row[0])

    async def publish(self, d: uuid.UUID, v: uuid.UUID, token: uuid.UUID) -> svc.VersionRecord:
        sha = (await self.run(lambda s: svc.get_version(s, self.t, d, v))).content_sha256
        rec: svc.VersionRecord = await self.ingest(
            v,
            lambda s: svc.publish_profile(
                s, self.t, self.actor, d, v, profile_json=PROFILE, contract_version="profile-2",
                content_sha256=sha, row_count=1, column_count=1,
                lease_token=token,
            ),
        )  # fmt: skip
        return rec


@pytest.fixture
async def h(pg_stack: SimpleNamespace, tmp_path: Path) -> AsyncIterator[H]:
    harness = H(pg_stack, tmp_path / "store")
    yield harness
    await harness.engine.dispose()
    await harness.ingest_engine.dispose()


async def _race(h: H, d: uuid.UUID, v: uuid.UUID, n: int) -> list[tuple[str, uuid.UUID]]:
    gate = asyncio.Event()

    async def claimant(token: uuid.UUID) -> tuple[str, uuid.UUID]:
        async def go(s: AsyncSession) -> tuple[str, uuid.UUID]:
            await gate.wait()
            state, _ = await svc.acquire_processing_lease(
                s, h.t, h.actor, d, v, token=token, ttl_s=300
            )
            return str(state), token

        result: tuple[str, uuid.UUID] = await h.ingest(v, go)
        return result

    tasks = [asyncio.create_task(claimant(uuid.uuid4())) for _ in range(n)]
    await asyncio.sleep(0.05)  # every claimant has its own open transaction
    gate.set()
    return list(await asyncio.gather(*tasks))


async def test_racing_acquirers_produce_exactly_one_owner(h: H) -> None:
    d, v = await h.quarantined()
    results = await _race(h, d, v, 6)
    winners = [tok for state, tok in results if state == "acquired"]
    assert len(winners) == 1 and sorted(s for s, _ in results).count("busy") == 5
    status, token, live = h.lease(v)
    assert (status, token, live) == ("PROFILING", winners[0], True)


async def test_racing_stale_reclaimers_produce_exactly_one_owner(h: H) -> None:
    d, v = await h.quarantined()
    assert await h.acquire(d, v, uuid.uuid4()) == "acquired"  # then the processor "crashes"
    h.expire(v)
    results = await _race(h, d, v, 6)
    winners = [tok for state, tok in results if state == "reclaimed"]
    assert len(winners) == 1, results
    assert h.lease(v)[1] == winners[0]


async def test_a_former_owner_can_neither_publish_nor_reject(h: H) -> None:
    d, v = await h.quarantined()
    old, new = uuid.uuid4(), uuid.uuid4()
    assert await h.acquire(d, v, old) == "acquired"
    h.expire(v)
    assert await h.acquire(d, v, new) == "reclaimed"
    with pytest.raises(DatasetConflict) as lost:
        await h.publish(d, v, old)
    assert lost.value.code == "LEASE_LOST"
    assert h.profiles(v) == 0  # the profile insert was rolled back with it
    with pytest.raises(DatasetConflict) as lost2:
        await h.ingest(
            v,
            lambda s: svc.reject_processing(
                s, h.t, h.actor, d, v, token=old, rejection_code=RejectionCode.PARSE_ERROR
            ),
        )
    assert lost2.value.code == "LEASE_LOST"
    assert (await h.publish(d, v, new)).status is VersionStatus.PROFILED
    assert h.lease(v)[:2] == ("PROFILED", None)  # cleared on leaving PROFILING


async def test_renewal_keeps_ownership_and_only_the_owner_can_renew(h: H) -> None:
    d, v = await h.quarantined()
    owner = uuid.uuid4()
    assert await h.acquire(d, v, owner) == "acquired"

    async def renew(tok: uuid.UUID) -> bool:
        ok: bool = await h.ingest(
            v, lambda s: svc.renew_processing_lease(s, h.t, d, v, token=tok, ttl_s=300)
        )
        return ok

    assert await renew(owner) is True
    assert await renew(uuid.uuid4()) is False  # a stranger cannot extend it
    assert await h.acquire(d, v, uuid.uuid4()) == "busy"  # live lease respected
    h.expire(v)
    assert await renew(owner) is True  # not yet reclaimed: still ours
    assert await h.acquire(d, v, uuid.uuid4()) == "busy"


async def test_ownership_lost_during_profiling_publishes_nothing(
    h: H, monkeypatch: pytest.MonkeyPatch
) -> None:
    d, v = await h.quarantined()
    profiling = asyncio.Event()
    release = asyncio.Event()
    real = processing.run_profiler

    async def slow(*a: Any, **k: Any) -> processing.ProfilerOutcome:
        profiling.set()
        await release.wait()
        return await real(*a, **k)

    monkeypatch.setattr(processing, "run_profiler", slow)
    cfg = processing.IngestionConfig(
        limits=StrictLimits(timeout_s=30), memory_mb=768, lease_ttl_s=5, lease_renew_s=0.2
    )
    task = asyncio.create_task(h.deliver(v, cfg))
    await profiling.wait()
    h.expire(v)  # the database decides the lease is stale...
    thief = uuid.uuid4()
    assert await h.acquire(d, v, thief) == "reclaimed"  # ...and someone else takes it
    assert await asyncio.wait_for(task, 10) == "skipped"  # renewal failed: work abandoned
    release.set()
    assert h.lease(v)[:2] == ("PROFILING", thief) and h.profiles(v) == 0


async def test_the_database_refuses_leaving_profiling_without_a_live_lease(h: H) -> None:
    d, v = await h.quarantined()
    assert await h.acquire(d, v, uuid.uuid4()) == "acquired"
    h.expire(v)
    with psycopg.connect(h.pg.owner_libpq, autocommit=True) as c:
        c.execute(
            "INSERT INTO dataset_profiles (version_id, tenant_id, dataset_id, contract_version, "
            "content_sha256, row_count, column_count, profile) SELECT id, tenant_id, dataset_id, "
            "'profile-2', content_sha256, 1, 1, %s::jsonb FROM dataset_versions WHERE id = %s",
            (PROFILE, v),
        )
        for status, extra in (("PROFILED", ""),  # the key never moves (ADR-033 D1)
                              ("REJECTED", ", rejection_code = 'PARSE_ERROR'")):  # fmt: skip
            with pytest.raises(psycopg.errors.CheckViolation, match="live processing lease"):
                c.execute(
                    f"UPDATE dataset_versions SET status = %s{extra} WHERE id = %s",  # noqa: S608
                    (status, v),
                )
        with pytest.raises(psycopg.errors.CheckViolation, match="15 minutes"):
            c.execute(
                "UPDATE dataset_versions SET processing_lease_expires_at = now() + interval '1 day'"
                " WHERE id = %s",
                (v,),
            )
    # Outside PROFILING a lease cannot exist: the guard clears any attempt.
    d2, v2 = await h.quarantined()
    with psycopg.connect(h.pg.owner_libpq, autocommit=True) as c:
        c.execute(
            "UPDATE dataset_versions SET processing_lease_token = gen_random_uuid(), "
            "processing_lease_expires_at = now() + interval '1 minute' WHERE id = %s",
            (v2,),
        )
    assert h.lease(v2) == ("QUARANTINED", None, None)


@pytest.mark.parametrize("skew", [timedelta(hours=-24), timedelta(hours=24)])
async def test_the_api_host_clock_never_changes_the_answer(
    h: H, monkeypatch: pytest.MonkeyPatch, skew: timedelta
) -> None:
    class Skewed(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> "Skewed":
            real = datetime.now(tz or UTC) + skew
            return cls.fromtimestamp(real.timestamp(), tz or UTC)

    for module in (svc, ingestion, processing):
        monkeypatch.setattr(module, "datetime", Skewed, raising=False)
    d, v = await h.quarantined()
    assert await h.acquire(d, v, uuid.uuid4()) == "acquired"
    assert await h.acquire(d, v, uuid.uuid4()) == "busy"  # live by the DATABASE clock
    h.expire(v)
    assert await h.acquire(d, v, uuid.uuid4()) == "reclaimed"  # stale by the DATABASE clock
    d2, v2 = await h.quarantined()
    result = await h.deliver(
        v2, processing.IngestionConfig(limits=StrictLimits(timeout_s=30), memory_mb=768)
    )
    assert result == "profiled"
