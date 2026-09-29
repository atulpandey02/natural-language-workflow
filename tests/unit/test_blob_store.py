"""B04 library layer: tenant-scoped blob keys and verified deletion."""

import io
import uuid
from pathlib import Path

import pytest

from nlw.storage.blob import (
    BlobKeyError,
    BlobTooLargeError,
    LocalBlobStore,
    TenantScopedBlobStore,
)


def _stores(tmp_path: Path) -> tuple[LocalBlobStore, TenantScopedBlobStore, TenantScopedBlobStore]:
    inner = LocalBlobStore(tmp_path / "blobs")
    return (
        inner,
        TenantScopedBlobStore(inner, uuid.uuid4()),
        TenantScopedBlobStore(inner, uuid.uuid4()),
    )


def test_put_returns_size_and_digest_and_is_readable(tmp_path: Path) -> None:
    _, a, _ = _stores(tmp_path)
    ds = uuid.uuid4()
    key = a.key("quarantine", ds, "upload.csv")
    size, digest = a.put_stream(key, io.BytesIO(b"a,b\n1,2\n"), max_bytes=100)
    assert size == 8 and len(digest) == 64
    with a.open(key) as f:
        assert f.read() == b"a,b\n1,2\n"


def test_over_cap_stream_leaves_no_object(tmp_path: Path) -> None:
    inner, a, _ = _stores(tmp_path)
    key = a.key("quarantine", uuid.uuid4(), "big.csv")
    with pytest.raises(BlobTooLargeError):
        a.put_stream(key, io.BytesIO(b"x" * 101), max_bytes=100)
    assert not a.exists(key)
    assert list(inner.root.rglob("*.csv")) == [] and list(inner.root.rglob(".upload-*")) == []


@pytest.mark.parametrize(
    "bad",
    [
        "../etc/passwd",
        "quarantine/../../x",
        "/abs/path",
        "quarantine//x",
        "Quarantine/UPPER/x",
        "quarantine/t/d/..",
    ],
)
def test_malformed_keys_are_refused(tmp_path: Path, bad: str) -> None:
    inner, _, _ = _stores(tmp_path)
    with pytest.raises(BlobKeyError):
        inner.exists(bad)


def test_foreign_tenant_keys_are_refused_before_the_store(tmp_path: Path) -> None:
    _, a, b = _stores(tmp_path)
    ds = uuid.uuid4()
    key_b = b.key("datasets", ds, "raw.csv")
    b.put_stream(key_b, io.BytesIO(b"x"), max_bytes=10)
    for op in (a.exists, a.open, a.delete):
        with pytest.raises(BlobKeyError):
            op(key_b)
    with pytest.raises(BlobKeyError):
        a.put_stream(key_b, io.BytesIO(b"y"), max_bytes=10)
    with pytest.raises(BlobKeyError):
        a.key("elsewhere", ds, "raw.csv")
    assert b.exists(key_b)


def test_delete_dataset_removes_both_areas_and_verifies(tmp_path: Path) -> None:
    _, a, b = _stores(tmp_path)
    ds, other = uuid.uuid4(), uuid.uuid4()
    for area, name in (("quarantine", "u1.csv"), ("datasets", "raw.csv"), ("datasets", "p.json")):
        a.put_stream(a.key(area, ds, name), io.BytesIO(b"x"), max_bytes=10)
    keep = a.key("datasets", other, "raw.csv")
    a.put_stream(keep, io.BytesIO(b"x"), max_bytes=10)
    keep_b = b.key("datasets", ds, "raw.csv")  # same dataset id, other tenant
    b.put_stream(keep_b, io.BytesIO(b"x"), max_bytes=10)

    assert a.delete_dataset_and_verify(ds) is True
    assert a.list_dataset("datasets", ds) == [] and a.list_dataset("quarantine", ds) == []
    assert a.exists(keep) and b.exists(keep_b)
    assert a.delete_dataset_and_verify(ds) is True  # idempotent
