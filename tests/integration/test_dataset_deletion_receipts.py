"""Deletion-receipt contract (ADR-030; provider-neutral, LOCAL FAKE only).

A purge stores the receipt's sink, opaque id and deletion-set digest with its
evidence row; the tombstone must verify that receipt through the configured
verifier. A missing, stale, mismatched or unverifiable receipt blocks the
tombstone. No real external deletion log exists (owner decision O-3).
"""

import json
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import psycopg
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from nlw.datasets import ingestion
from nlw.datasets import service as svc
from nlw.datasets.deletion_log import (
    LOCAL_FAKE_SINK,
    DeletionLogUnavailable,
    LocalFakeDeletionLog,
    UnconfiguredDeletionLog,
    deletion_log_from_settings,
)
from nlw.datasets.service import Actor
from nlw.ingest.strict import StrictLimits
from nlw.ingest_service import processing
from nlw.ops import datasets as ops
from nlw.storage.blob import LocalBlobStore
from nlw.tenancy.context import Role, TenantContext
from nlw.tenancy.signing import Purpose

pytestmark = pytest.mark.integration

CSV = b"region,amount\n" + b"".join(f"r{i % 4},{i}\n".encode() for i in range(30))
CONFIG = processing.IngestionConfig(limits=StrictLimits(timeout_s=30), memory_mb=768)


class H:
    def __init__(self, pg: SimpleNamespace, root: Path) -> None:
        m = pg.seed_member("owner")
        self.pg = pg
        self.ctx = TenantContext(user_id=m.user_id, tenant_id=m.tenant_id, role=Role.OWNER)
        self.engine = create_async_engine(pg.settings.database_url, pool_size=6)
        self.maker: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.engine, expire_on_commit=False
        )
        self.signer = pg.signers[Purpose.API_REQUEST]
        pg.enable_ingest()
        self.ingest_engine = create_async_engine(pg.ingest_sa, pool_size=6)
        self.ingest_maker: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.ingest_engine, expire_on_commit=False
        )
        self.ingest_signer = pg.signers[Purpose.DATASET_INGEST]
        self.store = LocalBlobStore(root / "store")
        self.log = LocalFakeDeletionLog(root / "receipts.jsonl")

    async def run(self, fn: Any) -> Any:
        return await ingestion.in_context(self.maker, self.signer, self.ctx, fn)

    async def deleting_dataset(self, versions: int = 1) -> tuple[uuid.UUID, list[uuid.UUID]]:
        t, a = self.ctx.tenant_id, Actor.user(self.ctx.user_id)
        d = (
            await self.run(
                lambda s: svc.create_dataset(
                    s, t, a, name=f"r-{uuid.uuid4().hex[:8]}", description=None
                )
            )
        ).id
        ids = []
        for _ in range(versions):
            v = (
                await self.run(
                    lambda s: svc.create_version(
                        s, t, a, d, original_filename="a.csv", media_type="text/csv",
                        declared_size_bytes=len(CSV), idempotency_key=uuid.uuid4().hex,
                    )
                )
            ).id  # fmt: skip

            async def chunks() -> AsyncIterator[bytes]:
                yield CSV

            _, env = await ingestion.store_content(
                maker=self.maker, signer=self.signer, store=self.store, ctx=self.ctx,
                dataset_id=d, version_id=v, chunks=chunks(), max_bytes=10**6,
            )  # fmt: skip
            assert env is not None
            # The ingest runtime processes the request (as nlw_ingest).
            await processing.process_envelope(
                maker=self.ingest_maker, signer=self.ingest_signer, store=self.store,
                config=CONFIG, message=env.to_json(),
            )  # fmt: skip
            ids.append(v)
        await self.run(lambda s: svc.request_dataset_deletion(s, t, a, d))
        return d, ids

    def owner(self) -> psycopg.Connection[Any]:
        return psycopg.connect(self.pg.owner_libpq, autocommit=True)

    def purge(self, d: uuid.UUID) -> None:
        with self.owner() as c:
            ops.purge(c, self.store, self.log, dataset_id=d, operator="op-r", environment="local")

    def tombstone(self, d: uuid.UUID, log: Any = None) -> dict[str, Any]:
        with self.owner() as c:
            return ops.tombstone(c, dataset_id=d, store=self.store, log=log or self.log)

    def edit_receipts(self, fn: Callable[[dict[str, Any]], None]) -> None:
        records = self.log.read_all()
        for r in records:
            fn(r)
        self.log.path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records))


@pytest.fixture
async def h(pg_stack: SimpleNamespace, tmp_path: Path) -> AsyncIterator[H]:
    harness = H(pg_stack, tmp_path)
    yield harness
    await harness.engine.dispose()
    await harness.ingest_engine.dispose()


async def test_a_purge_stores_its_receipt_with_the_evidence_and_the_tombstone_verifies_it(
    h: H,
) -> None:
    d, (v,) = await h.deleting_dataset()
    h.purge(d)
    with h.owner() as c:
        row = c.execute(
            "SELECT receipt_sink, receipt_id, receipt_digest FROM dataset_events "
            "WHERE version_id = %s AND event_type = 'VERSION_OBJECT_PURGED'",
            (v,),
        ).fetchone()
    assert row is not None
    sink, rid, digest = row
    (receipt,) = h.log.read_all()
    assert (sink, rid, digest) == (LOCAL_FAKE_SINK, receipt["receipt_id"],
                                   receipt["deletion_set_sha256"])  # fmt: skip
    assert (receipt["tenant_id"], receipt["dataset_id"], receipt["version_id"]) == (
        str(h.ctx.tenant_id), str(d), str(v),
    )  # fmt: skip
    assert receipt["operator"] == "op-r" and receipt["verified_absent"] is True
    raw = json.dumps(receipt)
    for leak in ("quarantine/", "datasets/", "a.csv", str(h.store.root), "region"):
        assert leak not in raw, leak
    assert h.tombstone(d)["dataset"] == "DELETED"


@pytest.mark.parametrize(
    "tamper,reason",
    [
        (lambda r: r.update(tenant_id=str(uuid.uuid4())), "WORKSPACE_MISMATCH"),
        (lambda r: r.update(dataset_id=str(uuid.uuid4())), "DATASET_MISMATCH"),
        (lambda r: r.update(version_id=str(uuid.uuid4())), "VERSION_MISMATCH"),
        (lambda r: r.update(content_sha256="0" * 64), "DIGEST_MISMATCH"),
        (lambda r: r.update(object_ref_sha256=["1" * 64]), "DIGEST_MISMATCH"),
        (lambda r: r.update(deletion_set_sha256="2" * 64), "DIGEST_MISMATCH"),
        (lambda r: r.update(sink="another-sink"), "SINK_MISMATCH"),
        (
            lambda r: r.update(
                deleted_at=(datetime.fromisoformat(r["deleted_at"]) - timedelta(days=1)).isoformat()
            ),
            "STALE",
        ),  # fmt: skip
        (lambda r: r.update(verified_absent=False), "MALFORMED"),
        (lambda r: r.update(receipt_id="not-this-one"), "MISSING"),
    ],
)
async def test_a_mismatched_receipt_blocks_the_tombstone(
    h: H, tamper: Callable[[dict[str, Any]], None], reason: str
) -> None:
    d, (v,) = await h.deleting_dataset()
    h.purge(d)
    h.edit_receipts(tamper)
    with pytest.raises(ops.TombstoneError, match=reason):
        h.tombstone(d)
    with h.owner() as c:
        status = c.execute("SELECT status FROM dataset_versions WHERE id = %s", (v,)).fetchone()
    assert status == ("DELETING",)  # nothing was scrubbed


async def test_a_receipt_for_another_version_cannot_be_reused(h: H) -> None:
    d, (v1, v2) = await h.deleting_dataset(versions=2)
    h.purge(d)
    with h.owner() as c:  # swap the two evidence rows' receipts (owner-only rows)
        rows = dict(
            c.execute(
                "SELECT version_id, receipt_id FROM dataset_events "
                "WHERE dataset_id = %s AND event_type = 'VERSION_OBJECT_PURGED'",
                (d,),
            ).fetchall()
        )
        for mine, theirs in ((v1, v2), (v2, v1)):
            c.execute(
                "UPDATE dataset_events SET receipt_id = %s WHERE version_id = %s "
                "AND event_type = 'VERSION_OBJECT_PURGED'",
                (rows[theirs], mine),
            )
    with pytest.raises(ops.TombstoneError, match="VERSION_MISMATCH"):
        h.tombstone(d)


async def test_a_missing_or_unreadable_log_or_an_unconfigured_verifier_blocks(h: H) -> None:
    d, _ = await h.deleting_dataset()
    h.purge(d)
    with pytest.raises(ops.TombstoneError, match="sink"):
        h.tombstone(d, log=UnconfiguredDeletionLog())
    h.log.path.write_text("{not json\n")
    with pytest.raises(ops.TombstoneError, match="UNVERIFIABLE"):
        h.tombstone(d)
    h.log.path.unlink()
    with pytest.raises(ops.TombstoneError, match="MISSING"):
        h.tombstone(d)


async def test_a_repeated_purge_is_idempotent_and_the_latest_receipt_counts(h: H) -> None:
    d, (v,) = await h.deleting_dataset()
    h.purge(d)
    h.purge(d)
    receipts = h.log.read_all()
    assert len(receipts) == 2 and receipts[0]["receipt_id"] != receipts[1]["receipt_id"]
    # The first receipt is lost; the latest evidence row names the second: fine.
    h.log.path.write_text(json.dumps(receipts[1], sort_keys=True) + "\n")
    assert h.tombstone(d)["dataset"] == "DELETED"


async def test_the_database_binds_receipts_to_purge_evidence_only(h: H) -> None:
    d, (v,) = await h.deleting_dataset()
    with h.owner() as c:
        tenant = h.ctx.tenant_id
        for sql, args in (
            (  # a purge record without a receipt
                "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, event_type, "
                "from_status, to_status, actor_kind, reason_code) VALUES (%s,%s,%s,%s,"
                "'VERSION_OBJECT_PURGED','DELETING','DELETING','operator','OPERATOR_PURGE')",
                (uuid.uuid4(), tenant, d, v),
            ),
            (  # a receipt on any other event
                "INSERT INTO dataset_events (id, tenant_id, dataset_id, event_type, to_status, "
                "actor_kind, receipt_sink, receipt_id, receipt_digest) VALUES (%s,%s,%s,"
                "'DATASET_TOMBSTONED','DELETED','operator','local-fake','x',%s)",
                (uuid.uuid4(), tenant, d, "a" * 64),
            ),
            (  # malformed receipt fields
                "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, event_type, "
                "from_status, to_status, actor_kind, reason_code, receipt_sink, receipt_id, "
                "receipt_digest) VALUES (%s,%s,%s,%s,'VERSION_OBJECT_PURGED','DELETING',"
                "'DELETING','operator','OPERATOR_PURGE','Bad Sink!','id','nothex')",
                (uuid.uuid4(), tenant, d, v),
            ),
        ):
            with pytest.raises(psycopg.errors.CheckViolation):
                c.execute(sql, args)


def test_the_fake_verifier_is_refused_when_deployed(tmp_path: Path) -> None:
    for env in ("staging", "production"):
        with pytest.raises(DeletionLogUnavailable):
            deletion_log_from_settings("local", str(tmp_path / "x.jsonl"), env)
    assert isinstance(
        deletion_log_from_settings("local", str(tmp_path / "x.jsonl"), "local"),
        LocalFakeDeletionLog,
    )
    assert isinstance(deletion_log_from_settings("none", None, "production"),
                      UnconfiguredDeletionLog)  # fmt: skip
