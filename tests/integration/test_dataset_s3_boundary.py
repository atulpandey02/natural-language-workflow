"""The S3 dataset store end to end (ADR-033): the real API and the real ingest
runtime (as ``nlw_ingest``) against a deterministic in-memory S3 that enforces
the ADR-033 bucket policy. Each actor uses its OWN recording client view, so
the tests prove exactly which S3 operations the API, the ingest runtime and
the operator use. No network, no AWS."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jwt
import psycopg
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from nlw.api.app import create_app
from nlw.datasets.deletion_log import LocalFakeDeletionLog
from nlw.ops import datasets as ops
from nlw.storage.blob import TenantScopedBlobStore
from nlw.storage.s3 import S3BlobStore

pytestmark = pytest.mark.integration

_FAKE = Path(__file__).resolve().parents[1] / "unit" / "s3_fake.py"
_spec = importlib.util.spec_from_file_location("s3_fake", _FAKE)
assert _spec and _spec.loader
fake = importlib.util.module_from_spec(_spec)
sys.modules["s3_fake"] = fake
_spec.loader.exec_module(fake)

_SECRET = "dev-secret-for-tests-32bytes-min-length"
MiB = 1024 * 1024
CSV = b"region,amount\n" + b"".join(f"r{i % 3},{i}\n".encode() for i in range(30))
BAD = b"a,a\n1,2\n"
API_OPS = {
    "put_object",
    "create_multipart_upload",
    "upload_part",
    "complete_multipart_upload",
    "abort_multipart_upload",
    "get_object_attributes",
}
MAPPING = {
    "columns": [
        {"name": "region", "label": "Region", "semantic_type": "category",
         "role": "dimension", "analysis_allowed": True},
        {"name": "amount", "label": "Amount", "semantic_type": "amount",
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


def _store(view: Any, **kw: Any) -> S3BlobStore:
    return S3BlobStore(view, bucket=fake.BUCKET, kms_key_arn=fake.KEY_ARN, part_size=5 * MiB, **kw)


@pytest.fixture
def s3(
    pg_stack: SimpleNamespace,
    tmp_path: Path,
    ingest_runtime: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[SimpleNamespace]:
    settings = pg_stack.settings.model_copy(
        update={
            "datasets_api_enabled": True,
            # Mounts the upload routes; the store itself is replaced below.
            "dataset_storage_backend": "local",
            "dataset_storage_root": str(tmp_path / "unused"),
        }
    )
    bucket = fake.FakeBucket()
    views = SimpleNamespace(api=bucket.client(), ingest=bucket.client(), operator=bucket.client())
    m = pg_stack.seed_member("owner")
    app = create_app(settings)
    with TestClient(app) as c:
        app.state.dataset_store = _store(views.api)
        rt = ingest_runtime.attach(app, monkeypatch)
        rt.store = _store(views.ingest, read_limit=settings.dataset_max_upload_bytes)
        yield SimpleNamespace(
            c=c, rt=rt, h=_hdr(m.user_id, m.tenant_id), tenant=m.tenant_id, pg=pg_stack,
            bucket=bucket, views=views, operator=_store(views.operator),
            log=LocalFakeDeletionLog(tmp_path / "receipts.jsonl"),
        )  # fmt: skip


def _dataset(s: SimpleNamespace) -> str:
    r = s.c.post("/datasets", headers=s.h, json={"name": f"d-{uuid.uuid4().hex[:6]}"})
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def _upload(s: SimpleNamespace, did: str, data: bytes) -> tuple[str, Any]:
    r = s.c.post(
        f"/datasets/{did}/versions",
        headers={**s.h, "Idempotency-Key": uuid.uuid4().hex},
        json={"original_filename": "a.csv", "declared_size_bytes": len(data)},
    )
    vid = str(r.json()["id"])
    put = s.c.put(f"/datasets/{did}/versions/{vid}/content", headers=s.h, content=data)
    return vid, put


def _row(s: SimpleNamespace, vid: str) -> tuple[Any, ...]:
    with psycopg.connect(s.pg.owner_libpq) as c:
        row = c.execute(
            "SELECT status, storage_object_key, content_sha256 FROM dataset_versions WHERE id = %s",
            (vid,),
        ).fetchone()
    assert row is not None
    return tuple(row)


def _big_csv(target: int) -> bytes:
    rows = [b"region,amount\n"]
    size, i = len(rows[0]), 0
    while size < target:
        line = f"r{i % 7},{i}{'0' * 90}\n".encode()  # ~100-byte rows: under the row cap
        rows.append(line)
        size += len(line)
        i += 1
    return b"".join(rows)


# --- who calls what ----------------------------------------------------------------------


@pytest.mark.parametrize("size", ["small", "multipart"])
def test_the_api_writes_and_inspects_metadata_and_the_ingest_runtime_only_reads(
    s3: SimpleNamespace, size: str
) -> None:
    did = _dataset(s3)
    data = CSV if size == "small" else _big_csv(6 * MiB)
    vid, put = _upload(s3, did, data)
    assert put.status_code == 202, put.text
    status, key, _sha = _row(s3, vid)
    with psycopg.connect(s3.pg.owner_libpq) as c:
        code = c.execute(
            "SELECT rejection_code FROM dataset_versions WHERE id = %s", (vid,)
        ).fetchone()
    assert status == "PROFILED", code
    assert key == f"versions/{s3.tenant}/{did}/{vid}/source.csv"
    assert set(s3.views.api.calls) <= API_OPS and "get_object" not in s3.views.api.calls
    assert set(s3.views.ingest.calls) == {"get_object"}  # read-only: no write/copy/list/delete
    assert list(s3.bucket.objects) == [key] and len(s3.bucket.objects[key]) == 1
    if size == "multipart":
        assert "complete_multipart_upload" in s3.views.api.calls


def test_the_one_object_never_moves_or_multiplies_across_the_lifecycle(
    s3: SimpleNamespace,
) -> None:
    did = _dataset(s3)
    v1, _ = _upload(s3, did, CSV)
    key1 = _row(s3, v1)[1]
    assert s3.c.post(f"/datasets/{did}/versions/{v1}/semantics", headers=s3.h,
                     json=MAPPING).status_code == 201  # fmt: skip
    assert s3.c.post(f"/datasets/{did}/versions/{v1}/activate", headers=s3.h).status_code == 200
    v2, _ = _upload(s3, did, CSV.replace(b"r1", b"r9"))
    s3.c.post(f"/datasets/{did}/versions/{v2}/semantics", headers=s3.h, json=MAPPING)
    s3.c.post(f"/datasets/{did}/versions/{v2}/activate", headers=s3.h)
    assert _row(s3, v1)[:2] == ("SUPERSEDED", key1)  # same key in every state
    assert _row(s3, v2)[0] == "ACTIVE"
    keys = sorted(s3.bucket.objects)
    assert keys == sorted([key1, _row(s3, v2)[1]])  # no copies, no second area
    assert all(len(v) == 1 for v in s3.bucket.objects.values())  # never rewritten
    assert set(s3.views.ingest.calls) == {"get_object"}


def test_an_orphan_from_a_lost_response_is_adopted_by_metadata_only(s3: SimpleNamespace) -> None:
    did = _dataset(s3)
    r = s3.c.post(
        f"/datasets/{did}/versions",
        headers={**s3.h, "Idempotency-Key": uuid.uuid4().hex},
        json={"original_filename": "a.csv", "declared_size_bytes": len(CSV)},
    )
    vid = str(r.json()["id"])
    # A crashed attempt stored the object but never recorded it.
    key = TenantScopedBlobStore(s3.operator, s3.tenant).object_key(uuid.UUID(did), uuid.UUID(vid))
    _store(s3.bucket.client()).put_stream(key, io.BytesIO(CSV), max_bytes=len(CSV))
    other = s3.c.put(f"/datasets/{did}/versions/{vid}/content", headers=s3.h,
                     content=CSV.replace(b"r1", b"r2"))  # fmt: skip
    assert other.status_code == 409 and other.json()["error"]["code"] == "CONTENT_CONFLICT"
    same = s3.c.put(f"/datasets/{did}/versions/{vid}/content", headers=s3.h, content=CSV)
    assert same.status_code == 202 and _row(s3, vid)[0] == "PROFILED"
    assert len(s3.bucket.objects[key]) == 1  # adopted, never replaced
    assert "get_object_attributes" in s3.views.api.calls
    assert "get_object" not in s3.views.api.calls


# --- rejected objects (D2) -----------------------------------------------------------------


def _events(s: SimpleNamespace, vid: str) -> list[tuple[Any, ...]]:
    with psycopg.connect(s.pg.owner_libpq) as c:
        return c.execute(
            "SELECT event_type, actor_kind, reason_code, receipt_id IS NOT NULL "
            "FROM dataset_events WHERE version_id = %s ORDER BY created_at, id",
            (vid,),
        ).fetchall()


def test_a_rejected_object_is_retained_until_the_operator_purges_every_version(
    s3: SimpleNamespace,
) -> None:
    did = _dataset(s3)
    vid, _ = _upload(s3, did, BAD)
    status, key, _ = _row(s3, vid)
    assert status == "REJECTED"
    assert key in s3.bucket.objects  # the ingest runtime deleted nothing
    assert set(s3.views.ingest.calls) == {"get_object"}
    s3.views.operator.delete_object(Bucket=fake.BUCKET, Key=key)  # a stray delete marker
    with psycopg.connect(s3.pg.owner_libpq, autocommit=True) as c:
        assert [str(r[2]) for r in ops.rejected_pending(c)] == [vid]
        assert ops.rejected_stats(c)["retained"] == 1
        dry = ops.purge_rejected(c, s3.operator, s3.log, operator="op", environment="local",
                                 dry_run=True)  # fmt: skip
        assert (dry["selected"], dry["purged"]) == (1, 0) and _row(s3, vid)[0] == "REJECTED"
        done = ops.purge_rejected(c, s3.operator, s3.log, operator="op", environment="local")
        assert (done["moved"], done["purged"]) == (1, 1)
        assert key not in s3.bucket.objects  # every version AND the delete marker
        again = ops.purge_rejected(c, s3.operator, s3.log, operator="op", environment="local")
        assert again["selected"] == 0  # idempotent
        assert ops.rejected_stats(c)["retained"] == 0
        assert ops.tombstone(c, dataset_id=uuid.UUID(did), version_id=uuid.UUID(vid),
                             store=s3.operator, log=s3.log)["versions_tombstoned"] == 1  # fmt: skip
    events = _events(s3, vid)
    assert ("VERSION_DELETION_REQUESTED", "operator", "REJECTED_RETENTION", False) in events
    assert ("VERSION_OBJECT_PURGED", "operator", "OPERATOR_PURGE", True) in events
    receipt = json.loads(s3.log.path.read_text().splitlines()[-1])
    assert receipt["objects_deleted"] == 2  # the version AND the delete marker, by version id
    assert set(s3.views.operator.calls) <= {
        "list_object_versions", "list_multipart_uploads", "delete_object", "head_object",
        "abort_multipart_upload",
    }  # fmt: skip


def test_purge_commands_refuse_while_the_recovery_lock_is_active(s3: SimpleNamespace) -> None:
    did = _dataset(s3)
    vid, _ = _upload(s3, did, BAD)
    with psycopg.connect(s3.pg.owner_libpq, autocommit=True) as c:
        c.execute("INSERT INTO dr_restore_events (id, cutoff_at) VALUES (%s, now())",
                  (uuid.uuid4(),))  # fmt: skip
        for dry_run in (False, True):
            with pytest.raises(ops.TombstoneError, match="recovery lock"):
                ops.purge_rejected(c, s3.operator, s3.log, operator="op", environment="local",
                                   dry_run=dry_run)  # fmt: skip
    assert _row(s3, vid)[0] == "REJECTED" and _row(s3, vid)[1] in s3.bucket.objects
    assert "delete_object" not in s3.views.operator.calls


def test_the_rejected_metrics_textfile_holds_aggregates_only(
    s3: SimpleNamespace, tmp_path: Path
) -> None:
    did = _dataset(s3)
    _upload(s3, did, BAD)
    path = tmp_path / "datasets.prom"
    with psycopg.connect(s3.pg.owner_libpq, autocommit=True) as c:
        ops.write_rejected_metrics(str(path), ops.rejected_stats(c))
    text = path.read_text()
    assert "nlw_dataset_rejected_retained 1" in text
    assert "nlw_dataset_rejected_oldest_age_seconds" in text
    assert str(s3.tenant) not in text and did not in text and "{" not in text  # no labels


# --- the database guards (migration 0028) ----------------------------------------------------


def test_the_ingest_role_can_no_longer_change_a_storage_key(pg_stack: SimpleNamespace) -> None:
    with (
        psycopg.connect(pg_stack.ingest_libpq) as c,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        c.execute("UPDATE dataset_versions SET storage_object_key = storage_object_key WHERE false")


def test_a_recorded_key_never_moves_and_new_keys_are_versions_keys(s3: SimpleNamespace) -> None:
    did = _dataset(s3)
    vid, _ = _upload(s3, did, CSV)
    key = _row(s3, vid)[1]
    legacy = f"datasets/{s3.tenant}/{did}/{vid}"
    with psycopg.connect(s3.pg.owner_libpq, autocommit=True) as c:
        with pytest.raises(psycopg.errors.CheckViolation):  # the old publish move is gone
            c.execute("UPDATE dataset_versions SET storage_object_key = %s WHERE id = %s",
                      (legacy, vid))  # fmt: skip
        r = s3.c.post(f"/datasets/{did}/versions",
                      headers={**s3.h, "Idempotency-Key": uuid.uuid4().hex},
                      json={"original_filename": "b.csv", "declared_size_bytes": 3})  # fmt: skip
        fresh = str(r.json()["id"])
        with pytest.raises(psycopg.errors.CheckViolation):  # new keys use versions/ only
            legacy_key = f"quarantine/{s3.tenant}/{did}/{fresh}"
            c.execute(
                "UPDATE dataset_versions SET storage_object_key = %s, content_sha256 = %s "
                "WHERE id = %s",
                (legacy_key, "a" * 64, fresh),
            )
    assert _row(s3, vid)[1] == key


def test_0028_downgrade_is_refused_once_versions_keys_exist(s3: SimpleNamespace) -> None:
    did = _dataset(s3)
    _upload(s3, did, CSV)
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", s3.pg.owner_sa)
    with pytest.raises(Exception, match="0028 downgrade refused"):
        command.downgrade(cfg, "0027_dataset_ingest_dispatch")
    with psycopg.connect(s3.pg.owner_libpq) as c:
        assert c.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0028_dataset_object_layout",
        )
