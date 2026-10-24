"""The external deletion log on S3 Object Lock, end to end against PostgreSQL
(ADR-034, owner decision O-3). The receipt bucket is the in-memory S3 of
``tests/unit/receipt_s3_fake.py`` (no network, no AWS); objects live in a
local store.

- purge -> a retained, write-once receipt -> tombstone verifies it;
- no purge without a log that can retain its receipt (checked before deleting);
- ``reconcile-receipts`` checks every purge event against its receipt;
- ``reapply-receipts`` re-applies the external log to a restored database while
  the recovery lock holds it: a live version whose bytes a receipt proves
  deleted becomes DELETING with ``RESTORE_REAPPLY`` evidence the tombstone
  accepts; conflicts and untrustworthy receipts change nothing.
"""

import importlib.util
import json
import sys
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import psycopg
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from nlw.datasets import ingestion
from nlw.datasets import service as svc
from nlw.datasets.deletion_log import DeletionReceipt, ReceiptRef, UnconfiguredDeletionLog
from nlw.datasets.deletion_log_s3 import S3DeletionLog, receipt_key
from nlw.datasets.lifecycle import EventType, ReasonCode
from nlw.datasets.service import Actor
from nlw.ingest.strict import StrictLimits
from nlw.ingest_service import processing
from nlw.ops import datasets as ops
from nlw.storage.blob import LocalBlobStore, TenantScopedBlobStore
from nlw.tenancy.context import Role, TenantContext
from nlw.tenancy.signing import Purpose

_FAKE = Path(__file__).resolve().parents[1] / "unit" / "receipt_s3_fake.py"
_spec = importlib.util.spec_from_file_location("receipt_s3_fake", _FAKE)
assert _spec is not None and _spec.loader is not None
fake = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("receipt_s3_fake", fake)
_spec.loader.exec_module(fake)

pytestmark = pytest.mark.integration

CSV = b"region,amount\n" + b"".join(f"r{i % 4},{i}\n".encode() for i in range(30))
CONFIG = processing.IngestionConfig(limits=StrictLimits(timeout_s=30), memory_mb=768)
MAPPING = json.dumps({"contract_version": "semantics-1", "columns": [
    {"name": "region", "label": "Region", "semantic_type": "category", "role": "dimension",
     "analysis_allowed": True, "description": None},
    {"name": "amount", "label": "Amount", "semantic_type": "count", "role": "measure",
     "analysis_allowed": True, "description": None}]})  # fmt: skip


class H:
    def __init__(self, pg: SimpleNamespace, root: Path) -> None:
        m = pg.seed_member("owner")
        self.pg = pg
        self.tenant = m.tenant_id
        self.ctx = TenantContext(user_id=m.user_id, tenant_id=m.tenant_id, role=Role.OWNER)
        self.actor = Actor.user(m.user_id)
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
        self.bucket = fake.ReceiptBucket()
        self.log = S3DeletionLog(self.bucket.client("operator"), fake.BUCKET)

    async def run(self, fn: Any) -> Any:
        return await ingestion.in_context(self.maker, self.signer, self.ctx, fn)

    async def dataset(self) -> uuid.UUID:
        name = f"r-{uuid.uuid4().hex[:8]}"
        d = await self.run(
            lambda s: svc.create_dataset(s, self.tenant, self.actor, name=name, description=None)
        )
        return d.id  # type: ignore[no-any-return]

    async def profiled(self, d: uuid.UUID) -> uuid.UUID:
        v = (
            await self.run(
                lambda s: svc.create_version(
                    s, self.tenant, self.actor, d, original_filename="a.csv",
                    media_type="text/csv", declared_size_bytes=len(CSV),
                    idempotency_key=uuid.uuid4().hex,
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
        await processing.process_envelope(
            maker=self.ingest_maker, signer=self.ingest_signer, store=self.store,
            config=CONFIG, message=env.to_json(),
        )  # fmt: skip
        return v  # type: ignore[no-any-return]

    async def active(self, d: uuid.UUID) -> uuid.UUID:
        v = await self.profiled(d)
        t, a = self.tenant, self.actor
        await self.run(lambda s: svc.confirm_semantics(s, t, a, d, v, mapping_json=MAPPING))
        await self.run(lambda s: svc.activate_version(s, t, a, d, v))
        return v

    def owner(self) -> psycopg.Connection[Any]:
        return psycopg.connect(self.pg.owner_libpq, autocommit=True)

    def row(self, v: uuid.UUID) -> tuple[Any, ...]:
        with self.owner() as c:
            row = c.execute(
                "SELECT v.status, d.active_version_id FROM dataset_versions v "
                "JOIN datasets d ON d.id = v.dataset_id WHERE v.id = %s",
                (v,),
            ).fetchone()
        assert row is not None
        return tuple(row)

    def reasons(self, v: uuid.UUID) -> list[tuple[str, str]]:
        with self.owner() as c:
            return [
                (str(e), str(r))
                for e, r in c.execute(
                    "SELECT event_type, reason_code FROM dataset_events WHERE version_id = %s "
                    "AND reason_code = 'RESTORE_REAPPLY' ORDER BY created_at, event_type",
                    (v,),
                ).fetchall()
            ]

    def digest(self, v: uuid.UUID) -> str:
        with self.owner() as c:
            row = c.execute("SELECT content_sha256 FROM dataset_versions WHERE id = %s", (v,))
            return str(row.fetchone()[0])  # type: ignore[index]

    def bytes_deleted_after_snapshot(
        self, d: uuid.UUID, v: uuid.UUID, *, content: str | None = None
    ) -> DeletionReceipt:
        """What a purge after the restored snapshot left behind: the bytes are
        gone and its receipt is in the external log; the database forgot both."""
        keys, verified = TenantScopedBlobStore(self.store, self.tenant).delete_version_and_verify(
            d, v
        )
        assert verified
        r = DeletionReceipt.for_version(
            sink=self.log.sink_id, environment="local", tenant_id=self.tenant, dataset_id=d,
            version_id=v, content_sha256=content or self.digest(v), deleted_keys=keys,
            operator="op-before-restore",
        )  # fmt: skip
        self.log.append(r)
        return r

    def lock(self) -> uuid.UUID:
        rid = uuid.uuid4()
        with self.owner() as c:
            c.execute("INSERT INTO dr_restore_events (id, cutoff_at) VALUES (%s, now())", (rid,))
        return rid

    def unlock(self, rid: uuid.UUID) -> None:
        with self.owner() as c:
            c.execute(
                "UPDATE dr_restore_events SET validation_completed_at = now(), "
                "runtime_enabled_at = now() WHERE id = %s",
                (rid,),
            )


@pytest.fixture
async def h(pg_stack: SimpleNamespace, tmp_path: Path) -> AsyncIterator[H]:
    harness = H(pg_stack, tmp_path)
    yield harness
    await harness.engine.dispose()
    await harness.ingest_engine.dispose()


async def _deleting(h: H) -> tuple[uuid.UUID, uuid.UUID]:
    d = await h.dataset()
    v = await h.profiled(d)
    await h.run(lambda s: svc.request_dataset_deletion(s, h.tenant, h.actor, d))
    return d, v


# --- purge, verify, tombstone ------------------------------------------------------------------


async def test_a_purge_writes_one_retained_receipt_the_tombstone_verifies(h: H) -> None:
    d, v = await _deleting(h)
    with h.owner() as c:
        ops.purge(c, h.store, h.log, dataset_id=d, operator="op", environment="local")
        sink, rid = c.execute(
            "SELECT receipt_sink, receipt_id FROM dataset_events "
            "WHERE version_id = %s AND event_type = 'VERSION_OBJECT_PURGED'",
            (v,),
        ).fetchone()  # type: ignore[misc]
    assert sink == f"s3.{fake.BUCKET}"
    [stored] = h.bucket.objects[receipt_key(ReceiptRef(h.tenant, d, v, rid))]
    assert stored.mode == "GOVERNANCE" and stored.retain_until is not None
    assert "a.csv" not in stored.data.decode() and "versions/" not in stored.data.decode()
    with h.owner() as c:
        assert ops.reconcile_receipts(c, h.log) == {
            "unverified": [], "other_sink": [], "receipts_without_event": [],
            "workspace_unverified": [], "workspace_receipts_without_tombstone": [],
            "unexpected_objects": 0,
        }  # fmt: skip
        assert ops.tombstone(c, dataset_id=d, store=h.store, log=h.log)["dataset"] == "DELETED"
    assert "delete_object" not in h.log._s3.calls  # type: ignore[attr-defined]


async def test_no_byte_is_deleted_unless_the_log_can_retain_the_receipt(h: H) -> None:
    d, v = await _deleting(h)
    h.bucket.set_lock(None)
    with h.owner() as c, pytest.raises(ops.TombstoneError, match="Object Lock"):
        ops.purge(c, h.store, h.log, dataset_id=d, operator="op", environment="local")
    assert TenantScopedBlobStore(h.store, h.tenant).list_version(d, v)  # bytes untouched
    assert h.bucket.objects == {}
    with h.owner() as c:
        assert not ops._has_purge_evidence(c, v)


async def test_a_receipt_that_lost_its_retention_blocks_the_tombstone(h: H) -> None:
    d, v = await _deleting(h)
    with h.owner() as c:
        ops.purge(c, h.store, h.log, dataset_id=d, operator="op", environment="local")
    [key] = h.bucket.objects
    h.bucket.expire_retention(key)
    with h.owner() as c:
        assert ops.reconcile_receipts(c, h.log)["unverified"] == [f"{v}:NOT_RETAINED"]
        with pytest.raises(ops.TombstoneError, match="NOT_RETAINED"):
            ops.tombstone(c, dataset_id=d, store=h.store, log=h.log)
    assert h.row(v)[0] == "DELETING"


async def test_reconcile_lists_a_receipt_no_purge_event_names(h: H) -> None:
    d, v = await _deleting(h)
    h.bytes_deleted_after_snapshot(d, v)  # receipt written, purge never committed
    with h.owner() as c:
        assert ops.reconcile_receipts(c, h.log)["receipts_without_event"] == [str(v)]


# --- re-applying the external log to a restored database ---------------------------------------


async def test_reapply_runs_only_while_the_recovery_lock_holds_a_restored_database(h: H) -> None:
    with h.owner() as c, pytest.raises(ops.TombstoneError, match="recovery lock"):
        ops.reapply_receipts(c, h.log)


async def test_reapply_restores_the_deletions_a_restored_database_forgot(h: H) -> None:
    # The restored snapshot predates these purges:
    d = await h.dataset()
    live = await h.active(d)  # deleted and purged after the snapshot
    keep = await h.profiled(d)  # never deleted
    d2, deleting = await _deleting(h)  # requested before the snapshot, purged after
    h.bytes_deleted_after_snapshot(d, live)
    h.bytes_deleted_after_snapshot(d2, deleting)
    gone_d, gone_v = uuid.uuid4(), uuid.uuid4()  # created after the snapshot
    h.log.append(
        DeletionReceipt.for_version(
            sink=h.log.sink_id, environment="local", tenant_id=h.tenant, dataset_id=gone_d,
            version_id=gone_v, content_sha256=None, deleted_keys=[], operator="op",
        )
    )  # fmt: skip
    assert h.row(live) == ("ACTIVE", live)
    lock = h.lock()

    with h.owner() as c:
        dry = ops.reapply_receipts(c, h.log, dry_run=True)
    assert (dry["reapplied"], dry["recorded"], dry["absent"]) == (1, 1, 1)
    assert h.row(live) == ("ACTIVE", live)  # a dry run changes nothing

    with h.owner() as c:
        result = ops.reapply_receipts(c, h.log)
    assert result == {
        "receipts": 3, "reapplied": 1, "recorded": 1, "already_recorded": 0,
        "already_tombstoned": 0, "absent": 1, "conflict": [], "unreadable": [],
        "workspace_receipts": 0, "workspaces_reoffboarded": 0, "workspaces_already": 0,
        "workspaces_absent": 0, "grants_scrubbed": 0, "workspace_unreadable": [],
        "unexpected_objects": 0, "dry_run": 0,
    }  # fmt: skip
    assert h.row(live) == ("DELETING", None)  # unusable, no longer the active version
    assert h.row(keep)[0] == "PROFILED"
    assert h.reasons(live) == [
        ("VERSION_DELETION_REQUESTED", "RESTORE_REAPPLY"),
        ("VERSION_OBJECT_PURGED", "RESTORE_REAPPLY"),
    ]
    assert h.reasons(deleting) == [("VERSION_OBJECT_PURGED", "RESTORE_REAPPLY")]

    with h.owner() as c:  # idempotent
        again = ops.reapply_receipts(c, h.log)
    assert (again["reapplied"], again["recorded"], again["already_recorded"]) == (0, 0, 2)

    h.unlock(lock)
    with h.owner() as c:
        # The re-applied receipts predate the re-created requests, yet verify.
        assert ops.reconcile_receipts(c, h.log)["unverified"] == []
        ops.tombstone(c, dataset_id=d, version_id=live, store=h.store, log=h.log)
        assert ops.tombstone(c, dataset_id=d2, store=h.store, log=h.log)["dataset"] == "DELETED"
    assert h.row(live)[0] == "DELETED" and h.row(deleting)[0] == "DELETED"


async def test_reapply_never_alters_a_conflicting_or_untrustworthy_receipt(h: H) -> None:
    d = await h.dataset()
    conflicting = await h.profiled(d)
    expired = await h.profiled(d)
    h.bytes_deleted_after_snapshot(d, conflicting, content="0" * 64)
    r = h.bytes_deleted_after_snapshot(d, expired)
    h.bucket.expire_retention(receipt_key(ReceiptRef(h.tenant, d, expired, r.receipt_id)))
    h.lock()
    with h.owner() as c:
        result = ops.reapply_receipts(c, h.log)
    assert result["conflict"] == [str(conflicting)]
    assert result["unreadable"] == [str(expired)]
    assert result["reapplied"] == result["recorded"] == 0
    assert h.row(conflicting)[0] == "PROFILED" and h.row(expired)[0] == "PROFILED"


async def test_reapply_ignores_a_retained_receipt_that_is_not_self_consistent(h: H) -> None:
    """A receipt S3 serves intact and retained, but filed under a live version
    while naming another one, or whose digest does not recompute, changes
    nothing."""
    d = await h.dataset()
    live = await h.profiled(d)
    other = await h.profiled(d)
    r = DeletionReceipt.for_version(
        sink=h.log.sink_id, environment="local", tenant_id=h.tenant, dataset_id=d,
        version_id=other, content_sha256=h.digest(other), deleted_keys=[], operator="op",
    )  # fmt: skip
    misfiled = receipt_key(ReceiptRef(h.tenant, d, live, r.receipt_id))
    h.bucket.plant(misfiled, r.to_json().encode())
    changes = {"receipt_id": str(uuid.uuid4()), "version_id": str(live),
               "deletion_set_sha256": "f" * 64}  # fmt: skip
    bad_digest = DeletionReceipt(**{**r.__dict__, **changes})
    h.bucket.plant(
        receipt_key(ReceiptRef(h.tenant, d, live, bad_digest.receipt_id)),
        bad_digest.to_json().encode(),
    )
    h.lock()
    with h.owner() as c:
        result = ops.reapply_receipts(c, h.log)
    assert result["unreadable"] == [str(live)]
    assert result["reapplied"] == result["recorded"] == 0
    assert h.row(live)[0] == "PROFILED" and h.row(other)[0] == "PROFILED"


async def test_a_genuinely_stale_receipt_still_blocks_an_ordinary_tombstone(h: H) -> None:
    """The relaxed time check applies to RESTORE_REAPPLY evidence only: an
    ordinary purge event naming a receipt older than its deletion request is
    refused."""
    d, v = await _deleting(h)
    keys, _ = TenantScopedBlobStore(h.store, h.tenant).delete_version_and_verify(d, v)
    early = DeletionReceipt.for_version(
        sink=h.log.sink_id, environment="local", tenant_id=h.tenant, dataset_id=d,
        version_id=v, content_sha256=h.digest(v), deleted_keys=keys, operator="op",
    )  # fmt: skip
    early = DeletionReceipt(**{**early.__dict__, "deleted_at": "2020-01-01T00:00:00+00:00"})
    h.log.append(early)
    with h.owner() as c:
        ops._event(
            c, h.tenant, d, v, EventType.VERSION_OBJECT_PURGED, "DELETING",
            to_status="DELETING", reason=ReasonCode.OPERATOR_PURGE,
            receipt=(h.log.sink_id, early.receipt_id, early.deletion_set_sha256),
        )  # fmt: skip
        with pytest.raises(ops.TombstoneError, match="STALE"):
            ops.tombstone(c, dataset_id=d, store=h.store, log=h.log)
        assert ops.reconcile_receipts(c, h.log)["unverified"] == [f"{v}:STALE"]


def test_only_reapplied_evidence_relaxes_the_time_check() -> None:
    requested = datetime(2026, 10, 14, tzinfo=UTC)
    assert ops._not_before(requested, "OPERATOR_PURGE") == requested
    assert ops._not_before(requested, None) == requested
    assert ops._not_before(requested, "RESTORE_REAPPLY") < requested


# --- review findings (PR #66) ------------------------------------------------------------------

BOMB = b"[" * 30_000 + b"]" * 30_000


def _snapshot(h: H) -> tuple[Any, ...]:
    with h.owner() as c:
        versions = c.execute(
            "SELECT id, status FROM dataset_versions WHERE tenant_id = %s ORDER BY id", (h.tenant,)
        ).fetchall()
        events = c.execute(
            "SELECT count(*) FROM dataset_events WHERE tenant_id = %s", (h.tenant,)
        ).fetchone()
    return tuple(versions), events


async def test_one_malicious_receipt_never_stops_reconcile_reapply_or_the_tombstone(h: H) -> None:
    """M-2: a retained, checksum-valid receipt nested far past the parser's
    limit is reported as malformed/unreadable; every other receipt is still
    checked and applied, and nothing changes because of the bad one."""
    d = await h.dataset()
    victim, good = await h.profiled(d), await h.profiled(d)
    h.bytes_deleted_after_snapshot(d, good)
    # Sorted first, so a crash would stop the run before the good receipt.
    first = min(victim, good)
    h.bucket.plant(receipt_key(ReceiptRef(h.tenant, d, first, "0-bomb")), BOMB)
    lock = h.lock()
    with h.owner() as c:
        result = ops.reapply_receipts(c, h.log)
    h.unlock(lock)
    assert result["unreadable"] == [str(first)] and ops.reapply_failed(result)
    assert h.row(good)[0] == "DELETING"
    if first == victim:
        assert h.row(victim)[0] == "PROFILED"

    # A purge event naming the bomb as its receipt: reconcile reports it,
    # the tombstone refuses it, neither crashes.
    d2, v2 = await _deleting(h)
    keys, _ = TenantScopedBlobStore(h.store, h.tenant).delete_version_and_verify(d2, v2)
    h.bucket.plant(receipt_key(ReceiptRef(h.tenant, d2, v2, "bomb-2")), BOMB)
    with h.owner() as c:
        ops._event(
            c, h.tenant, d2, v2, EventType.VERSION_OBJECT_PURGED, "DELETING",
            to_status="DELETING", reason=ReasonCode.OPERATOR_PURGE,
            receipt=(h.log.sink_id, "bomb-2", "0" * 64),
        )  # fmt: skip
        report = ops.reconcile_receipts(c, h.log)
        assert f"{v2}:MALFORMED" in report["unverified"] and ops.reconcile_failed(report)
        with pytest.raises(ops.TombstoneError, match="MALFORMED"):
            ops.tombstone(c, dataset_id=d2, store=h.store, log=h.log)
    assert h.row(v2)[0] == "DELETING"


class _BadListing:
    """The real fake for reads, but a listing that turns bad after one good page."""

    def __init__(self, inner: Any, bad: dict[str, Any]) -> None:
        self.inner, self.bad, self.reads = inner, bad, 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def get_object(self, **kw: Any) -> dict[str, Any]:
        self.reads += 1
        return self.inner.get_object(**kw)  # type: ignore[no-any-return]

    def list_objects_v2(self, **kw: Any) -> dict[str, Any]:
        if kw.get("ContinuationToken"):
            return self.bad
        page = dict(self.inner.list_objects_v2(**kw))
        return {**page, "IsTruncated": True, "NextContinuationToken": "t1"}


@pytest.mark.parametrize(
    "bad",
    [
        {"Prefix": "other/", "Contents": []},
        {"Prefix": "receipts/", "EncodingType": "url", "Contents": []},
        {"Prefix": "receipts/", "IsTruncated": True, "Contents": []},
        {"Prefix": "receipts/", "IsTruncated": True, "NextContinuationToken": "t1", "Contents": []},
        {"Prefix": "receipts/", "Contents": [{"Key": "versions/elsewhere"}]},
    ],
    ids=["prefix-echo", "encoding", "truncated-no-token", "repeated-token", "key-outside-prefix"],
)
async def test_a_malformed_listing_changes_nothing_and_trusts_no_receipt(
    h: H, bad: dict[str, Any]
) -> None:
    """L-1: reapply lists the log in full before acting; reconcile reports
    nothing from a listing it cannot trust."""
    d = await h.dataset()
    v = await h.profiled(d)
    h.bytes_deleted_after_snapshot(d, v)  # a valid receipt on the good first page
    client = _BadListing(h.bucket.client("operator"), bad)
    log = S3DeletionLog(client, fake.BUCKET)
    before = _snapshot(h)
    h.lock()
    with h.owner() as c:
        with pytest.raises(ops.TombstoneError, match="listing"):
            ops.reapply_receipts(c, log)
        with pytest.raises(ops.TombstoneError, match="listing"):
            ops.reconcile_receipts(c, log)
    assert _snapshot(h) == before and h.row(v)[0] == "PROFILED"
    assert client.reads == 0  # no receipt was read, let alone trusted


async def test_objects_that_are_not_receipts_are_reported_and_fail_the_commands(h: H) -> None:
    """L-2: counted, never read, never applied; both commands report them."""
    d = await h.dataset()
    v = await h.profiled(d)
    h.bytes_deleted_after_snapshot(d, v)
    h.bucket.plant(f"receipts/{h.tenant}/{d}/{v}/stray.txt", b"not a receipt")
    h.lock()
    with h.owner() as c:
        result = ops.reapply_receipts(c, h.log)
        report = ops.reconcile_receipts(c, h.log)
    assert result["unexpected_objects"] == 1 and result["reapplied"] == 1
    assert ops.reapply_failed(result)
    assert report["unexpected_objects"] == 1 and ops.reconcile_failed(report)


# --- L-3: the operator CLI prints sanitized errors only ---------------------------------------


@pytest.fixture
def cli(h: H, monkeypatch: pytest.MonkeyPatch) -> H:
    monkeypatch.setenv("DATABASE_MIGRATION_URL", h.pg.owner_sa)
    monkeypatch.setattr(ops, "configured_deletion_log", lambda settings: h.log)
    return h


SECRETS = ("SECRET-HOST.internal", "receipts/", fake.BUCKET, fake.ACCOUNT, "Traceback")


async def test_cli_reports_counts_and_fails_on_strays(
    cli: H, capsys: pytest.CaptureFixture[str]
) -> None:
    d = await cli.dataset()
    v = await cli.profiled(d)
    cli.bytes_deleted_after_snapshot(d, v)
    cli.bucket.plant(f"receipts/{cli.tenant}/{d}/{v}/stray.txt", b"x")
    cli.lock()
    assert ops.main(["reapply-receipts"]) == 1
    assert ops.main(["reconcile-receipts"]) == 1
    out = capsys.readouterr()
    assert "unexpected_objects=1" in out.out and "reapplied=1" in out.out
    for secret in SECRETS:
        assert secret not in out.out + out.err


async def test_cli_turns_an_operational_failure_into_a_sanitized_error(
    cli: H, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    d = await cli.dataset()
    a, b = await cli.profiled(d), await cli.profiled(d)
    cli.bytes_deleted_after_snapshot(d, a)
    cli.bytes_deleted_after_snapshot(d, b)
    cli.lock()
    real = ops._reapply_one
    calls = {"n": 0}

    def failing(*args: Any, **kw: Any) -> str:
        calls["n"] += 1
        if calls["n"] == 2:
            raise psycopg.OperationalError(
                f"connection to SECRET-HOST.internal lost; {fake.BUCKET} receipts/x {fake.ACCOUNT}"
            )
        return real(*args, **kw)

    monkeypatch.setattr(ops, "_reapply_one", failing)
    assert ops.main(["reapply-receipts"]) == 3
    out = capsys.readouterr()
    assert "stopped by an unexpected OperationalError" in out.err
    assert "partial receipts=2 reapplied=1" in out.err  # progress, as counts only
    for secret in SECRETS:
        assert secret not in out.out + out.err
    # Idempotent: the re-run finishes the job.
    monkeypatch.setattr(ops, "_reapply_one", real)
    assert ops.main(["reapply-receipts"]) == 0
    assert "already_recorded=1" in capsys.readouterr().out


def test_cli_never_echoes_a_rejected_configuration_value(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for k, v in {
        "DATASET_STORAGE_BACKEND": "s3",
        "DATASET_S3_BUCKET": f"nlw-local-datasets-{fake.ACCOUNT}-us-east-1",
        "DATASET_S3_REGION": "us-east-1",
        "DATASET_S3_KMS_KEY_ARN": f"arn:aws:kms:us-east-1:{fake.ACCOUNT}:key/"
        "11111111-2222-3333-4444-555555555555",
        "DATASET_DELETION_LOG": "s3",
        "DATASET_DELETION_LOG_BUCKET": "nlw-local-deletion-receipts-999988887777-us-east-1",
    }.items():
        monkeypatch.setenv(k, v)
    assert ops.main(["reconcile-receipts"]) == 2
    err = capsys.readouterr().err
    assert "environment and account" in err
    assert "999988887777" not in err and fake.ACCOUNT not in err and "Traceback" not in err


async def test_a_sink_mismatch_names_the_sink_kind_not_the_bucket(h: H) -> None:
    d, v = await _deleting(h)
    with h.owner() as c:
        ops.purge(c, h.store, h.log, dataset_id=d, operator="op", environment="local")
        with pytest.raises(ops.TombstoneError) as exc:
            ops.tombstone(c, dataset_id=d, store=h.store, log=UnconfiguredDeletionLog())
    assert "another sink (s3)" in str(exc.value)
    assert fake.BUCKET not in str(exc.value) and fake.ACCOUNT not in str(exc.value)
