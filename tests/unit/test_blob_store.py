"""B04 library layer: tenant-scoped blob keys and verified deletion."""

import hashlib
import io
import uuid
from pathlib import Path

import pytest

from nlw.storage.blob import (
    BlobDigestMismatch,
    BlobExistsError,
    BlobKeyError,
    BlobTooLargeError,
    LocalBlobStore,
    TenantScopedBlobStore,
    list_area,
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


def test_orphaned_partial_upload_is_deleted_and_verified(tmp_path: Path) -> None:
    """A writer killed mid-upload leaves ``.upload-*`` bytes behind (no except
    block runs on SIGKILL). Dataset deletion must remove them too, and must
    not report success while any byte under the dataset prefix remains."""
    inner, a, _ = _stores(tmp_path)
    ds = uuid.uuid4()
    key = a.key("quarantine", ds, "upload.csv")
    a.put_stream(key, io.BytesIO(b"a,b\n"), max_bytes=100)
    orphan = inner.root / "quarantine" / str(a.tenant_id) / str(ds) / ".upload-abc123_x"
    orphan.write_bytes(b"customer bytes from a crashed upload")

    assert any(k.endswith(".upload-abc123_x") for k in a.list_dataset("quarantine", ds))
    assert a.delete_dataset_and_verify(ds) is True
    assert not orphan.exists() and not inner.exists(key)


def test_partial_upload_names_are_not_caller_keys(tmp_path: Path) -> None:
    _, a, _ = _stores(tmp_path)
    ds = uuid.uuid4()
    with pytest.raises(BlobKeyError):
        a.key("quarantine", ds, ".upload-abc123")
    with pytest.raises(BlobKeyError):
        a.open(f"quarantine/{a.tenant_id}/{ds}/.upload-abc123")


# --- write-once objects and per-version helpers (ADR-030) ----------------------------


def test_objects_are_write_once(tmp_path: Path) -> None:
    """An upload can never alter a stored version: an existing key is refused
    before the stream is read, and the original bytes are untouched."""
    _, a, _ = _stores(tmp_path)
    ds, ver = uuid.uuid4(), uuid.uuid4()
    key = a.version_key("quarantine", ds, ver)
    a.put_stream(key, io.BytesIO(b"a,b\n1,2\n"), max_bytes=100)
    replacement = io.BytesIO(b"x,y\n9,9\n")
    with pytest.raises(BlobExistsError):
        a.put_stream(key, replacement, max_bytes=100)
    assert replacement.tell() == 0  # refused before reading
    with a.open(key) as f:
        assert f.read() == b"a,b\n1,2\n"


def test_digest_streams_size_and_sha(tmp_path: Path) -> None:
    _, a, _ = _stores(tmp_path)
    key = a.version_key("datasets", uuid.uuid4(), uuid.uuid4())
    data = b"h\n" + b"1\n" * 50_000
    assert a.put_stream(key, io.BytesIO(data), max_bytes=len(data)) == a.digest(key)
    assert a.digest(key) == (len(data), hashlib.sha256(data).hexdigest())


def test_version_keys_are_opaque_and_scoped(tmp_path: Path) -> None:
    _, a, b = _stores(tmp_path)
    ds, ver = uuid.uuid4(), uuid.uuid4()
    key = a.version_key("quarantine", ds, ver)
    assert key == f"quarantine/{a.tenant_id}/{ds}/{ver}"
    with pytest.raises(BlobKeyError):
        a.version_key("backups", ds, ver)
    with pytest.raises(BlobKeyError):  # another tenant's view cannot address it
        b.open(key)


def test_partial_uploads_are_attributed_to_their_version(tmp_path: Path) -> None:
    inner, a, _ = _stores(tmp_path)
    ds, v1, v2 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    a.put_stream(a.version_key("quarantine", ds, v1), io.BytesIO(b"a\n1\n"), max_bytes=10)
    a.put_stream(a.version_key("quarantine", ds, v2), io.BytesIO(b"a\n2\n"), max_bytes=10)

    class Boom(io.BytesIO):
        def read(self, n: int | None = -1) -> bytes:
            raise OSError("client went away")

    with pytest.raises(OSError):
        a.put_stream(a.version_key("datasets", ds, v1), Boom(), max_bytes=10)
    # A crashed writer (SIGKILL: no cleanup ran) leaves a partial named for v1.
    crash = inner.root / "datasets" / str(a.tenant_id) / str(ds) / f".upload-{v1.hex}_k9"
    crash.write_bytes(b"customer bytes")
    assert sorted(a.list_version(ds, v1)) == sorted(
        [a.version_key("quarantine", ds, v1), crash.relative_to(inner.root).as_posix()]
    )
    deleted, verified = a.delete_version_and_verify(ds, v1)
    assert verified and len(deleted) == 2
    assert a.list_version(ds, v1) == [] and a.exists(a.version_key("quarantine", ds, v2))
    assert a.delete_version_and_verify(ds, v1) == ([], True)  # idempotent


def test_failed_stream_leaves_no_partial(tmp_path: Path) -> None:
    _, a, _ = _stores(tmp_path)
    ds, ver = uuid.uuid4(), uuid.uuid4()

    class Boom(io.BytesIO):
        def read(self, n: int | None = -1) -> bytes:
            raise OSError("client went away")

    with pytest.raises(OSError):
        a.put_stream(a.version_key("quarantine", ds, ver), Boom(), max_bytes=10)
    assert a.list_version(ds, ver) == []


def test_copy_verified_detects_tampering_and_accepts_retries(tmp_path: Path) -> None:
    inner, a, _ = _stores(tmp_path)
    ds, ver = uuid.uuid4(), uuid.uuid4()
    src, dst = a.version_key("quarantine", ds, ver), a.version_key("datasets", ds, ver)
    data = b"a,b\n1,2\n"
    _, sha = a.put_stream(src, io.BytesIO(data), max_bytes=100)
    assert a.copy_verified(src, dst, expected_sha256=sha, max_bytes=100) == len(data)
    assert a.copy_verified(src, dst, expected_sha256=sha, max_bytes=100) == len(data)  # retry
    with pytest.raises(BlobDigestMismatch):  # an existing destination with other bytes
        a.copy_verified(src, dst, expected_sha256="0" * 64, max_bytes=100)
    # Tampered source: the copy is refused and nothing is left at the destination.
    ver2 = uuid.uuid4()
    src2, dst2 = a.version_key("quarantine", ds, ver2), a.version_key("datasets", ds, ver2)
    a.put_stream(src2, io.BytesIO(data), max_bytes=100)
    (inner.root / src2).write_bytes(b"a,b\n6,6\n")
    with pytest.raises(BlobDigestMismatch):
        a.copy_verified(src2, dst2, expected_sha256=sha, max_bytes=100)
    assert not a.exists(dst2)


def test_missing_object_errors_and_delete_is_idempotent(tmp_path: Path) -> None:
    _, a, _ = _stores(tmp_path)
    key = a.version_key("datasets", uuid.uuid4(), uuid.uuid4())
    with pytest.raises(FileNotFoundError):
        a.digest(key)
    with pytest.raises(FileNotFoundError):
        a.open(key)
    a.delete(key)
    a.delete(key)
    assert not a.exists(key)


def test_local_stores_are_isolated_by_root(tmp_path: Path) -> None:
    one, two = LocalBlobStore(tmp_path / "dev"), LocalBlobStore(tmp_path / "other")
    tenant = uuid.uuid4()
    key = TenantScopedBlobStore(one, tenant).version_key("datasets", uuid.uuid4(), uuid.uuid4())
    one.put_stream(key, io.BytesIO(b"x"), max_bytes=1)
    assert one.exists(key) and not two.exists(key)


def test_operator_area_listing_is_bounded_to_known_areas(tmp_path: Path) -> None:
    inner, a, b = _stores(tmp_path)
    ka = a.version_key("datasets", uuid.uuid4(), uuid.uuid4())
    kb = b.version_key("quarantine", uuid.uuid4(), uuid.uuid4())
    a.put_stream(ka, io.BytesIO(b"x"), max_bytes=1)
    b.put_stream(kb, io.BytesIO(b"y"), max_bytes=1)
    assert list(list_area(inner, "datasets")) == [ka]
    assert list(list_area(inner, "quarantine")) == [kb]
    with pytest.raises(BlobKeyError):
        list(list_area(inner, ".."))


def test_write_once_holds_when_the_object_appears_during_the_upload(tmp_path: Path) -> None:
    """The existence pre-check is only a fast path: if another writer creates
    the object while this stream is being written, the final link must still
    refuse to replace it."""
    inner, a, _ = _stores(tmp_path)
    ds, ver = uuid.uuid4(), uuid.uuid4()
    key = a.version_key("quarantine", ds, ver)
    target = inner.root / key

    class Racing(io.BytesIO):
        def read(self, n: int | None = -1) -> bytes:
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"first writer")
            return super().read(n)

    with pytest.raises(BlobExistsError):
        a.put_stream(key, Racing(b"second writer"), max_bytes=100)
    assert target.read_bytes() == b"first writer"
    assert a.list_version(ds, ver) == [key]  # and no partial is left behind


def test_a_lost_link_race_reports_what_was_streamed(tmp_path: Path) -> None:
    """The loser of a concurrent write learns the size and digest of the bytes
    it streamed, so identical retries can be recognised as identical."""
    inner, a, _ = _stores(tmp_path)
    key = a.version_key("quarantine", uuid.uuid4(), uuid.uuid4())
    target = inner.root / key
    data = b"a,b\n1,2\n"

    class Racing(io.BytesIO):
        def read(self, n: int | None = -1) -> bytes:
            out = super().read(n)
            if not out and not target.exists():  # the other writer wins at the end
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            return out

    with pytest.raises(BlobExistsError) as exc:
        a.put_stream(key, Racing(data), max_bytes=100)
    assert (exc.value.size, exc.value.sha256) == (len(data), hashlib.sha256(data).hexdigest())
    pre = a.version_key("quarantine", uuid.uuid4(), uuid.uuid4())
    a.put_stream(pre, io.BytesIO(b"x"), max_bytes=10)
    with pytest.raises(BlobExistsError) as refused:  # pre-check: nothing was read
        a.put_stream(pre, io.BytesIO(b"y"), max_bytes=10)
    assert (refused.value.size, refused.value.sha256) == (None, None)


def test_concurrent_publication_accepts_only_identical_bytes(tmp_path: Path) -> None:
    inner, a, _ = _stores(tmp_path)
    ds, ver = uuid.uuid4(), uuid.uuid4()
    src, dst = a.version_key("quarantine", ds, ver), a.version_key("datasets", ds, ver)
    data = b"a,b\n1,2\n"
    _, sha = a.put_stream(src, io.BytesIO(data), max_bytes=100)
    real_exists = inner.exists

    def racing_exists(key: str) -> bool:
        if key == dst and not (inner.root / dst).exists():
            (inner.root / dst).parent.mkdir(parents=True, exist_ok=True)
            (inner.root / dst).write_bytes(data)  # another publisher, after our check
            return False
        return real_exists(key)

    inner.exists = racing_exists  # type: ignore[method-assign]
    assert a.copy_verified(src, dst, expected_sha256=sha, max_bytes=100) == len(data)
