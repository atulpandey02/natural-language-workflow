"""Hostile inputs against the disposable local dataset store (PR #56 review).

Client filenames are metadata only: keys come from trusted ids. The store must
refuse any key that is not a plain id path, and links planted inside the store
must never let a write escape its root or replace a committed object. (The
local backend is refused in staging and production by configuration.)"""

import io
import os
import uuid
from pathlib import Path

import pytest

from nlw.storage.blob import (
    BlobExistsError,
    BlobKeyError,
    LocalBlobStore,
    TenantScopedBlobStore,
)


@pytest.mark.parametrize(
    "bad",
    [
        "quarantine/%2e%2e/x",
        "quarantine/..%2fx",
        "quarantine\\..\\x",
        "C:/quarantine/x",
        "quarantine/x\x00y",
        "quarantine/x\ny",
        "quarantine/\u2025/x",  # a dot-leader, not "..", must still be refused
        "quarantine/x\u0301",
        "quarantine/" + "a" * 300,
    ],
)
def test_keys_that_are_not_plain_id_paths_are_refused(tmp_path: Path, bad: str) -> None:
    store = LocalBlobStore(tmp_path / "root")
    with pytest.raises(BlobKeyError):
        store.put_stream(bad, io.BytesIO(b"x"), max_bytes=10)
    assert [p for p in (tmp_path / "root").rglob("*") if p.is_file()] == []


def test_version_keys_come_from_ids_only(tmp_path: Path) -> None:
    tenant, d, v = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    scoped = TenantScopedBlobStore(LocalBlobStore(tmp_path / "root"), tenant)
    assert scoped.version_key("quarantine", d, v) == f"quarantine/{tenant}/{d}/{v}"


def test_a_symlink_planted_in_the_store_cannot_redirect_a_write_outside(tmp_path: Path) -> None:
    root, outside = tmp_path / "root", tmp_path / "outside"
    outside.mkdir()
    tenant, d, v = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    store = LocalBlobStore(root)
    (root / "quarantine").mkdir()
    os.symlink(outside, root / "quarantine" / str(tenant))  # the tenant prefix escapes
    scoped = TenantScopedBlobStore(store, tenant)
    with pytest.raises(BlobKeyError):
        scoped.put_stream(scoped.version_key("quarantine", d, v), io.BytesIO(b"x"), max_bytes=10)
    assert list(outside.rglob("*")) == []


def test_a_planted_link_at_the_destination_is_never_replaced(tmp_path: Path) -> None:
    tenant, d, v = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    store = LocalBlobStore(tmp_path / "root")
    scoped = TenantScopedBlobStore(store, tenant)
    key = scoped.version_key("quarantine", d, v)
    victim = tmp_path / "victim"
    victim.write_bytes(b"precious")
    target = store.root / key
    target.parent.mkdir(parents=True)
    os.link(victim, target)  # a hard link to a file outside the store
    with pytest.raises(BlobExistsError):
        scoped.put_stream(key, io.BytesIO(b"attacker"), max_bytes=100)
    assert victim.read_bytes() == b"precious"


def test_a_stale_partial_upload_does_not_block_or_become_the_object(tmp_path: Path) -> None:
    tenant, d, v = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    store = LocalBlobStore(tmp_path / "root")
    scoped = TenantScopedBlobStore(store, tenant)
    key = scoped.version_key("quarantine", d, v)
    (store.root / key).parent.mkdir(parents=True)
    stale = store.root / key.rpartition("/")[0] / f".upload-{v.hex}_crashed"
    stale.write_bytes(b"half a fi")
    assert scoped.put_stream(key, io.BytesIO(b"whole file"), max_bytes=100)[0] == 10
    assert store.digest(key)[0] == 10 and stale.read_bytes() == b"half a fi"
    keys, verified = scoped.delete_version_and_verify(d, v)  # the operator purge
    assert verified and not stale.exists() and not store.exists(key)
