"""Physical deletion before the tombstone (ADR-030), end to end on a real stack.

Upload through the API, request deletion, then the operator's purge (delete,
verify, receipt, event) and tombstone (refused while any byte could remain).
Also: restore validation of metadata against objects, idempotency, and the
fail-closed behaviour without a deletion log or store.
"""

import json
import threading
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

from nlw.api.app import create_app
from nlw.datasets.deletion_log import LocalFakeDeletionLog, UnconfiguredDeletionLog
from nlw.ops import datasets as ops
from nlw.storage.blob import LocalBlobStore

pytestmark = pytest.mark.integration

_SECRET = "dev-secret-for-tests-32bytes-min-length"
CSV = b"region,amount\n" + b"".join(f"r{i % 3},{i}\n".encode() for i in range(30))
MAPPING = {
    "columns": [
        {"name": "region", "label": "Region", "semantic_type": "category",
         "role": "dimension", "analysis_allowed": True},
        {"name": "amount", "label": "Amount", "semantic_type": "count",
         "role": "measure", "analysis_allowed": True},
    ]
}  # fmt: skip


def _hdr(user_id: uuid.UUID, tenant_id: uuid.UUID) -> dict[str, str]:
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
    return {"Authorization": f"Bearer {token}", "X-Workspace-Id": str(tenant_id)}


@pytest.fixture
def env(
    pg_stack: SimpleNamespace,
    tmp_path: Path,
    ingest_runtime: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[SimpleNamespace]:
    root = tmp_path / "datasets"
    settings = pg_stack.settings.model_copy(
        update={
            "datasets_api_enabled": True,
            "dataset_storage_backend": "local",
            "dataset_storage_root": str(root),
        }
    )
    m = pg_stack.seed_member("owner")
    with TestClient(create_app(settings)) as c:
        ingest_runtime.attach(c.app, monkeypatch)  # the queue + the ingest runtime
        yield SimpleNamespace(
            c=c,
            h=_hdr(m.user_id, m.tenant_id),
            tenant=m.tenant_id,
            store=LocalBlobStore(root / "local"),
            log=LocalFakeDeletionLog(tmp_path / "receipts" / "deletions.jsonl"),
            pg=pg_stack,
        )


def _owner(pg: SimpleNamespace) -> psycopg.Connection[Any]:
    return psycopg.connect(pg.owner_libpq, autocommit=True)


def _active(e: SimpleNamespace, name: str = "Sales") -> tuple[str, str]:
    did = e.c.post("/datasets", headers=e.h, json={"name": name}).json()["id"]
    vid = e.c.post(
        f"/datasets/{did}/versions",
        headers={**e.h, "Idempotency-Key": uuid.uuid4().hex},
        json={"original_filename": "sales-q3.csv", "declared_size_bytes": len(CSV)},
    ).json()["id"]
    assert (
        e.c.put(f"/datasets/{did}/versions/{vid}/content", headers=e.h, content=CSV).status_code
        == 202
    )
    base = f"/datasets/{did}/versions/{vid}"
    assert e.c.post(f"{base}/semantics", headers=e.h, json=MAPPING).status_code == 201
    assert e.c.post(f"{base}/activate", headers=e.h).status_code == 200
    return did, vid


def _files(store: LocalBlobStore) -> list[str]:
    return sorted(str(p.relative_to(store.root)) for p in store.root.rglob("*") if p.is_file())


def _purge(e: SimpleNamespace, did: str, vid: str | None = None, log: Any = None) -> dict[str, Any]:
    with _owner(e.pg) as c:
        return ops.purge(
            c,
            e.store,
            log or e.log,
            dataset_id=uuid.UUID(did),
            version_id=uuid.UUID(vid) if vid else None,
            operator="op-test",
            environment="local",
        )


def _tombstone(e: SimpleNamespace, did: str, vid: str | None = None) -> dict[str, Any]:
    with _owner(e.pg) as c:
        return ops.tombstone(
            c,
            dataset_id=uuid.UUID(did),
            version_id=uuid.UUID(vid) if vid else None,
            store=e.store,
            log=e.log,
        )


def test_request_purge_verify_tombstone_end_to_end(env: SimpleNamespace) -> None:
    e = env
    did, vid = _active(e)
    assert _files(e.store) == [f"versions/{e.tenant}/{did}/{vid}/source.csv"]
    assert e.c.delete(f"/datasets/{did}", headers=e.h).status_code == 202

    with pytest.raises(ops.TombstoneError, match="not purged"):
        _tombstone(e, did)  # bytes still exist: refused
    result = _purge(e, did)
    assert result == {"dataset_id": did, "versions_purged": 1, "objects_deleted": 1}
    assert _files(e.store) == []  # nothing recoverable remains in the store

    receipts = e.log.read_all()
    assert len(receipts) == 1
    r = receipts[0]
    assert (r["receipt_version"], r["version_id"], r["objects_deleted"], r["verified_absent"]) == (
        "deletion-receipt-2",
        vid,
        1,
        True,
    )
    raw = json.dumps(receipts)
    for leaked in ("Sales", "sales-q3.csv", "datasets/", "quarantine/", "region"):
        assert leaked not in raw, leaked

    assert _tombstone(e, did) == {"dataset_id": did, "versions_tombstoned": 1, "dataset": "DELETED"}
    with _owner(e.pg) as c:
        ds = c.execute("SELECT status, name FROM datasets WHERE id = %s", (did,)).fetchone()
        v = c.execute(
            "SELECT status, original_filename, storage_object_key, content_sha256 "
            "FROM dataset_versions WHERE id = %s",
            (vid,),
        ).fetchone()
        prof = c.execute(
            "SELECT profile IS NULL, row_count FROM dataset_profiles WHERE version_id = %s", (vid,)
        ).fetchone()
        sem = c.execute(
            "SELECT bool_and(mapping IS NULL) FROM dataset_semantic_revisions "
            "WHERE version_id = %s",
            (vid,),
        ).fetchone()
        events = [
            row[0]
            for row in c.execute(
                "SELECT event_type FROM dataset_events WHERE version_id = %s ORDER BY created_at",
                (vid,),
            ).fetchall()
        ]
    assert ds == ("DELETED", None)
    assert v is not None and v[:3] == ("DELETED", None, None) and v[3] is not None  # digest kept
    assert prof == (True, 30) and sem == (True,)
    assert events[-3:] == [
        "VERSION_DELETION_REQUESTED",
        "VERSION_OBJECT_PURGED",
        "VERSION_TOMBSTONED",
    ]
    # A tombstone is final: nothing leaves DELETED, for any role.
    with _owner(e.pg) as c, pytest.raises(psycopg.errors.CheckViolation):
        c.execute("UPDATE dataset_versions SET status = 'DELETING' WHERE id = %s", (vid,))
    assert e.c.get(f"/datasets/{did}", headers=e.h).status_code == 404


def test_tombstone_is_refused_if_bytes_reappear_after_the_purge(env: SimpleNamespace) -> None:
    e = env
    did, vid = _active(e)
    e.c.delete(f"/datasets/{did}", headers=e.h)
    _purge(e, did)
    stray = e.store.root / "versions" / str(e.tenant) / did / vid / "source.csv"
    stray.parent.mkdir(parents=True, exist_ok=True)
    stray.write_bytes(CSV)  # e.g. restored from an old object backup
    with pytest.raises(ops.TombstoneError, match="still present"):
        _tombstone(e, did)
    _purge(e, did)  # idempotent: deletes the stray and records fresh evidence
    assert len(e.log.read_all()) == 2
    assert _tombstone(e, did)["dataset"] == "DELETED"


def test_tombstone_needs_purge_evidence_and_a_live_check(env: SimpleNamespace) -> None:
    e = env
    did, vid = _active(e)
    e.c.delete(f"/datasets/{did}", headers=e.h)
    # Bytes removed out of band, with no purge: the tombstone still refuses.
    for p in list(e.store.root.rglob("*")):
        if p.is_file():
            p.unlink()
    with pytest.raises(ops.TombstoneError, match="not purged"):
        _tombstone(e, did)
    _purge(e, did)
    with _owner(e.pg) as c, pytest.raises(ops.TombstoneError, match="no dataset store"):
        ops.tombstone(c, dataset_id=uuid.UUID(did), store=None)
    assert _tombstone(e, did)["dataset"] == "DELETED"


def test_purge_refusals(env: SimpleNamespace) -> None:
    e = env
    did, vid = _active(e)
    with pytest.raises(ops.TombstoneError, match="not DELETING"):
        _purge(e, did)
    with pytest.raises(ops.TombstoneError, match="not DELETING"):
        _purge(e, did, vid)
    e.c.delete(f"/datasets/{did}", headers=e.h)
    with pytest.raises(ops.TombstoneError, match="deletion log"):
        _purge(e, did, log=UnconfiguredDeletionLog())
    assert _files(e.store) != []  # nothing was deleted without a receipt sink
    with pytest.raises(ops.TombstoneError, match="operator"), _owner(e.pg) as c:
        ops.purge(c, e.store, e.log, dataset_id=uuid.UUID(did), operator=" ", environment="local")
    with _owner(e.pg) as c, pytest.raises(ops.TombstoneError, match="no dataset store"):
        ops.purge(c, None, e.log, dataset_id=uuid.UUID(did), operator="op", environment="local")


def test_single_version_purge_and_tombstone_on_a_live_dataset(env: SimpleNamespace) -> None:
    e = env
    did, v1 = _active(e)
    v2 = e.c.post(
        f"/datasets/{did}/versions",
        headers={**e.h, "Idempotency-Key": uuid.uuid4().hex},
        json={"original_filename": "b.csv", "declared_size_bytes": len(CSV)},
    ).json()["id"]
    e.c.put(f"/datasets/{did}/versions/{v2}/content", headers=e.h, content=CSV)
    assert e.c.delete(f"/datasets/{did}/versions/{v1}", headers=e.h).status_code == 202
    assert e.c.get(f"/datasets/{did}", headers=e.h).json()["active_version_id"] is None
    _purge(e, did, v1)
    assert _files(e.store) == [f"versions/{e.tenant}/{did}/{v2}/source.csv"]  # v2 untouched
    assert _tombstone(e, did, v1)["versions_tombstoned"] == 1
    assert e.c.get(f"/datasets/{did}/versions/{v2}", headers=e.h).json()["status"] == "PROFILED"


def test_repeated_and_concurrent_deletion_requests_are_idempotent(env: SimpleNamespace) -> None:
    e = env
    did, vid = _active(e)
    codes: list[int] = []

    def go() -> None:
        codes.append(e.c.delete(f"/datasets/{did}", headers=e.h).status_code)

    threads = [threading.Thread(target=go) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert codes == [202] * 5
    with _owner(e.pg) as c:
        n = c.execute(
            "SELECT count(*) FROM dataset_events WHERE dataset_id = %s "
            "AND event_type = 'DATASET_DELETION_REQUESTED'",
            (did,),
        ).fetchone()
    assert n == (1,)
    for _ in range(2):  # repeated physical deletion is safe
        _purge(e, did)
    assert _files(e.store) == []


def test_a_rejected_versions_object_is_kept_until_the_purge(env: SimpleNamespace) -> None:
    """ADR-033 D2: the ingest runtime deletes nothing; a rejected object stays
    immutable until the operator's purge, which records evidence for it."""
    e = env
    did = e.c.post("/datasets", headers=e.h, json={"name": "Bad"}).json()["id"]
    bad = b"a,a\n1,2\n"
    vid = e.c.post(
        f"/datasets/{did}/versions",
        headers={**e.h, "Idempotency-Key": uuid.uuid4().hex},
        json={"original_filename": "bad.csv", "declared_size_bytes": len(bad)},
    ).json()["id"]
    e.c.put(f"/datasets/{did}/versions/{vid}/content", headers=e.h, content=bad)
    assert e.c.get(f"/datasets/{did}/versions/{vid}", headers=e.h).json()["status"] == "REJECTED"
    assert _files(e.store) == [f"versions/{e.tenant}/{did}/{vid}/source.csv"]
    e.c.delete(f"/datasets/{did}", headers=e.h)
    result = _purge(e, did)
    assert (result["versions_purged"], result["objects_deleted"]) == (1, 1)
    assert _files(e.store) == []
    assert _tombstone(e, did)["dataset"] == "DELETED"


def test_restore_validation_reports_metadata_object_mismatches(env: SimpleNamespace) -> None:
    e = env
    d1, v1 = _active(e, "One")
    d2, v2 = _active(e, "Two")
    clean: dict[str, list[str]] = {
        "missing_objects": [],
        "digest_mismatches": [],
        "unaccounted_objects": [],
        "noncurrent_versions": [],
    }
    with _owner(e.pg) as c:
        assert ops.verify_objects(c, e.store) == clean
    base = e.store.root / "versions" / str(e.tenant)
    (base / d1 / v1 / "source.csv").unlink()  # a DB-only restore
    (base / d2 / v2 / "source.csv").write_bytes(CSV + b"x,1\n")
    orphan_id = str(uuid.uuid4())
    (base / d2 / orphan_id).mkdir(parents=True)
    (base / d2 / orphan_id / "source.csv").write_bytes(b"left over")
    with _owner(e.pg) as c:
        report = ops.verify_objects(c, e.store)
    assert report == {**clean, "missing_objects": [v1], "digest_mismatches": [v2],
                      "unaccounted_objects": [orphan_id]}  # fmt: skip


def test_operator_cli_purges_and_tombstones_with_ids_only_output(
    env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    e = env
    did, _vid = _active(e)
    e.c.delete(f"/datasets/{did}", headers=e.h)
    monkeypatch.setenv("DATABASE_MIGRATION_URL", e.pg.owner_libpq)
    monkeypatch.setenv("DATASET_STORAGE_BACKEND", "local")
    monkeypatch.setenv("DATASET_STORAGE_ROOT", str(e.store.root.parent))
    monkeypatch.setenv("DATASET_DELETION_LOG", "local")
    monkeypatch.setenv("DATASET_DELETION_LOG_PATH", str(e.log.path))
    monkeypatch.setenv("APP_ENV", "local")
    assert ops.main(["tombstone", "--dataset", did]) == 2
    assert ops.main(["purge", "--dataset", did, "--operator", "op-cli"]) == 0
    assert ops.main(["verify-objects"]) == 0
    assert ops.main(["tombstone", "--dataset", did]) == 0
    out = capsys.readouterr()
    text = out.out + out.err
    assert "not purged" in text and "dataset=DELETED" in text
    assert "Sales" not in text and "sales-q3" not in text and "datasets/" not in text
