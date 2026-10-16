"""O-4 object restore (ADR-036) against PostgreSQL. The dataset bucket and the
restore bucket AWS Backup restores into are local stores; receipts live in the
in-memory Object Lock S3 (no network, no AWS).

``restore-objects`` copies back only what the restored database still
references, verified against its recorded digest, never over an existing
object, and never before every deletion receipt is re-applied.
"""

import io
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from test_dataset_retention import _rejected
from test_deletion_receipt_log import H

from nlw.datasets import service as svc
from nlw.datasets.deletion_log import UnconfiguredDeletionLog
from nlw.ops import datasets as ops
from nlw.storage.blob import LocalBlobStore

pytestmark = pytest.mark.integration

MAX = 10**6
KEY = "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555"


class R(H):  # type: ignore[misc]
    def __init__(self, pg: SimpleNamespace, root: Path) -> None:
        super().__init__(pg, root)
        self.restored = LocalBlobStore(root / "restore-bucket")

    def key(self, v: uuid.UUID) -> str:
        with self.owner() as c:
            row = c.execute(
                "SELECT storage_object_key FROM dataset_versions WHERE id = %s", (v,)
            ).fetchone()
        assert row is not None and row[0]
        return str(row[0])

    def backed_up(self, *versions: uuid.UUID) -> None:
        """AWS Backup restored these objects into the restore bucket."""
        for v in versions:
            with self.store.open(self.key(v)) as body:
                self.restored.put_stream(self.key(v), body, max_bytes=MAX)

    def lost(self, *versions: uuid.UUID) -> None:
        """The dataset bucket no longer holds these objects."""
        for v in versions:
            self.store.delete(self.key(v))

    def restore(self, **kw: Any) -> dict[str, Any]:
        kw.setdefault("log", self.log)
        with self.owner() as c:
            return ops.restore_objects(c, self.restored, self.store, max_bytes=MAX, **kw)


@pytest.fixture
async def h(pg_stack: SimpleNamespace, tmp_path: Path) -> AsyncIterator[R]:
    harness = R(pg_stack, tmp_path)
    yield harness
    await harness.engine.dispose()
    await harness.ingest_engine.dispose()


EMPTY: dict[str, list[str]] = {
    "missing_in_backup": [],
    "backup_mismatch": [],
    "present_mismatch": [],
    "no_digest": [],
}


async def test_restore_runs_only_while_the_recovery_lock_holds_a_restored_database(h: R) -> None:
    with pytest.raises(ops.TombstoneError, match="restore-objects runs only while the recovery"):
        h.restore()
    rid = h.lock()
    h.unlock(rid)
    with pytest.raises(ops.TombstoneError, match="recovery lock"):
        h.restore()


async def test_lost_objects_are_restored_verified_and_present_ones_left_alone(h: R) -> None:
    d = await h.dataset()
    active, kept = await h.active(d), await h.profiled(d)
    h.backed_up(active, kept)
    h.lost(active)
    h.lock()

    dry = h.restore(dry_run=True)
    assert (dry["restored"], dry["present"], dry["dry_run"]) == (1, 1, 1)
    assert not h.store.exists(h.key(active))  # a dry run writes nothing

    result = h.restore()
    assert result == {
        "present": 1, "restored": 1, "rejected_skipped": 0, **EMPTY,
        "more": 0, "next": "", "dry_run": 0,
    }  # fmt: skip
    assert h.store.digest(h.key(active))[1] == h.digest(active)
    with h.owner() as c:
        report = ops.verify_objects(c, h.store)
    assert report["missing_objects"] == [] and report["digest_mismatches"] == []

    again = h.restore()  # idempotent
    assert (again["present"], again["restored"]) == (2, 0)


async def test_a_receipted_deletion_is_never_resurrected(h: R) -> None:
    # The backup predates a purge whose receipt is in the external log; the
    # restored database forgot the deletion.
    d = await h.dataset()
    purged = await h.active(d)
    h.backed_up(purged)
    h.bytes_deleted_after_snapshot(d, purged)
    h.lock()
    with pytest.raises(ops.TombstoneError, match="run reapply-receipts first"):
        h.restore()
    assert not h.store.exists(h.key(purged))

    with h.owner() as c:
        ops.reapply_receipts(c, h.log)
    result = h.restore()  # DELETING now: never a candidate
    assert (result["restored"], result["present"]) == (0, 0)
    assert result == {**result, **EMPTY}
    assert not h.store.exists(h.key(purged))


async def test_deleting_and_rejected_versions_are_never_restored(h: R) -> None:
    d = await h.dataset()
    rejected = await _rejected(h, d)
    d2 = await h.dataset()
    deleting = await h.profiled(d2)
    await h.run(lambda s: svc.request_dataset_deletion(s, h.tenant, h.actor, d2))
    h.backed_up(rejected, deleting)
    h.lost(rejected, deleting)
    h.lock()
    result = h.restore()
    assert (result["restored"], result["rejected_skipped"]) == (0, 1)
    assert result == {**result, **EMPTY}
    assert not h.store.exists(h.key(rejected)) and not h.store.exists(h.key(deleting))


async def test_a_missing_or_different_copy_is_reported_and_never_written(h: R) -> None:
    d = await h.dataset()
    absent, tampered, changed = await h.profiled(d), await h.profiled(d), await h.profiled(d)
    h.backed_up(changed)
    h.lost(absent, tampered)
    data = b"region,amount\nX,1\n"
    h.restored.put_stream(h.key(tampered), io.BytesIO(data), max_bytes=MAX)
    # A different object already in the dataset bucket is never overwritten.
    h.lost(changed)
    h.store.put_stream(h.key(changed), io.BytesIO(data), max_bytes=MAX)
    h.lock()

    result = h.restore()
    assert result["missing_in_backup"] == [str(absent)]
    assert result["backup_mismatch"] == [str(tampered)]
    assert result["present_mismatch"] == [str(changed)]
    assert ops.restore_failed(result)
    assert not h.store.exists(h.key(absent)) and not h.store.exists(h.key(tampered))
    assert h.store.digest(h.key(changed))[1] != h.digest(changed)


async def test_pages_continue_after_the_cursor_until_none_is_left(h: R) -> None:
    d = await h.dataset()
    versions = [await h.profiled(d) for _ in range(3)]
    h.backed_up(*versions)
    h.lost(*versions)
    h.lock()

    first = h.restore(limit=2)
    assert (first["restored"], first["more"], first["next"]) == (2, 1, str(versions[1]))
    # Without the cursor the same page comes back (now present): never past it.
    assert h.restore(limit=2)["present"] == 2 and not h.store.exists(h.key(versions[2]))
    last = h.restore(limit=2, after=first["next"])
    assert (last["restored"], last["more"], last["next"]) == (1, 0, "")
    assert all(h.store.exists(h.key(v)) for v in versions)

    for bad, match in (("not-a-uuid", "version id"), (str(uuid.uuid4()), "names no")):
        with pytest.raises(ops.TombstoneError, match=match):
            h.restore(after=bad)
    for limit in (0, 10_001):
        with pytest.raises(ops.TombstoneError, match="--limit"):
            h.restore(limit=limit)


async def test_an_unconfigured_log_needs_no_receipt_check(h: R) -> None:
    d = await h.dataset()
    v = await h.profiled(d)
    h.backed_up(v)
    h.lost(v)
    h.lock()
    assert h.restore(log=UnconfiguredDeletionLog())["restored"] == 1


async def test_the_cli_runs_as_the_restore_role_only(
    h: R, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DATABASE_MIGRATION_URL", h.pg.owner_sa)
    d = await h.dataset()
    v = await h.profiled(d)
    h.backed_up(v)
    h.lost(v)
    h.lock()
    assert ops.main(["restore-objects", "--dry-run"]) == 2  # no S3 store, no restore bucket
    assert "needs the S3 dataset store and DATASET_RESTORE_BUCKET" in capsys.readouterr().err

    # Configured: every store and the log are built with the restore role,
    # never the operator credentials.
    from nlw.storage import factory

    services: list[str] = []

    def store(settings: Any, service: str) -> Any:
        services.append(service)
        return h.store

    monkeypatch.setattr(ops, "dataset_store", store)
    monkeypatch.setattr(factory, "restore_source_store", lambda settings: h.restored)
    monkeypatch.setattr(ops, "restore_receipt_log", lambda settings: h.log)
    monkeypatch.setattr(ops, "configured_deletion_log", None)  # the operator log: never
    monkeypatch.setenv("DATASET_STORAGE_BACKEND", "s3")
    monkeypatch.setenv("DATASET_S3_BUCKET", "nlw-local-datasets-111122223333-us-east-1")
    monkeypatch.setenv("DATASET_S3_REGION", "us-east-1")
    monkeypatch.setenv("DATASET_S3_KMS_KEY_ARN", KEY)
    monkeypatch.setenv(
        "DATASET_RESTORE_BUCKET", "nlw-local-datasets-restore-111122223333-us-east-1"
    )
    assert ops.main(["restore-objects"]) == 0, capsys.readouterr().err
    assert services == ["restore"]
    assert "restored=1" in capsys.readouterr().out
    assert h.store.exists(h.key(v))
