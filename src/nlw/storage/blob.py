"""Blob storage abstraction for dataset bytes (Phase 2 plan section 21).

- ``BlobStore``: the minimal protocol the ingestion path needs.
- ``LocalBlobStore``: filesystem adapter for development and CI.
- ``TenantScopedBlobStore``: the ONLY wrapper runtime code should hold. Every key
  is derived server-side as ``{area}/{tenant_id}/{dataset_id}/{object}``; a key
  outside the bound tenant's prefix, or any key containing traversal or
  non-canonical segments, is refused before the backing store is touched.

Objects are write-once: ``put_stream`` never replaces an existing object
(``BlobExistsError``), so an upload can never alter a stored version. Dataset
uploads use the version id as the object name (ADR-030), never a filename.

The S3 adapter is deliberately absent: adding an S3 client is a new runtime
dependency that needs owner approval and an ADR (plan section 22).
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO, Protocol

AREAS = ("quarantine", "datasets")
_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
# An in-progress (or crash-orphaned) LocalBlobStore upload: never a caller key,
# but still customer bytes, so dataset listing and deletion must see it.
_PARTIAL_PREFIX = ".upload-"
_PARTIAL = re.compile(r"^\.upload-[a-z0-9_]{1,64}$")
_CHUNK = 1 << 20


class BlobKeyError(ValueError):
    """A key is malformed or outside the caller's tenant prefix."""


class BlobTooLargeError(ValueError):
    """The stream exceeded the caller's hard byte cap; nothing was stored."""


class BlobExistsError(ValueError):
    """An object already exists at the key; objects are never overwritten.

    When the race is lost at the final link (another writer finished first),
    the stream has been consumed: ``size`` and ``sha256`` then describe what
    THIS writer streamed, so the caller can compare it with the winner's
    object. They are ``None`` when the existence pre-check refused the write
    before reading anything."""

    def __init__(self, message: str, *, size: int | None = None, sha256: str | None = None) -> None:
        super().__init__(message)
        self.size = size
        self.sha256 = sha256


class BlobDigestMismatch(ValueError):
    """Stored bytes do not match the recorded digest (tampered or truncated)."""


class BlobStore(Protocol):
    def put_stream(self, key: str, stream: BinaryIO, *, max_bytes: int) -> tuple[int, str]:
        """Store the stream at ``key`` (never replacing an existing object);
        return (byte_size, sha256 hex)."""

    def open(self, key: str) -> BinaryIO: ...

    def digest(self, key: str) -> tuple[int, str]:
        """(byte_size, sha256 hex) of the stored object, computed by streaming."""

    def exists(self, key: str) -> bool: ...

    def delete(self, key: str) -> None:
        """Idempotent: deleting a missing key is not an error."""

    def list_prefix(self, prefix: str) -> Iterator[str]: ...


def _partial_hint(key: str) -> str:
    """The partial-file prefix for ``key``: ``.upload-<object name, alnum only>_``
    so a crashed upload can still be attributed to its version and purged."""
    name = re.sub(r"[^a-z0-9]", "", key.rpartition("/")[2])[:40]
    return f"{_PARTIAL_PREFIX}{name}_"


def validate_key(key: str) -> list[str]:
    parts = key.split("/")
    if len(parts) < 2 or any(not _SEGMENT.match(p) for p in parts):
        raise BlobKeyError("malformed blob key")
    return parts


class LocalBlobStore:
    """Filesystem store rooted at ``root``. Writes are atomic and write-once
    (temp file + hard link, which fails if the target exists) and a stream over
    ``max_bytes`` leaves no object behind."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str, *, partial_ok: bool = False) -> Path:
        head, _, last = key.rpartition("/")
        if partial_ok and head and _PARTIAL.match(last):
            validate_key(head)
        else:
            validate_key(key)
        path = (self.root / key).resolve()
        if self.root not in path.parents:
            raise BlobKeyError("key escapes the store root")
        return path

    def put_stream(self, key: str, stream: BinaryIO, *, max_bytes: int) -> tuple[int, str]:
        path = self._path(key)
        if path.exists():
            raise BlobExistsError("an object already exists at this key")
        path.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        size = 0
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=_partial_hint(key))
        try:
            with os.fdopen(fd, "wb") as out:
                while chunk := stream.read(_CHUNK):
                    size += len(chunk)
                    if size > max_bytes:
                        raise BlobTooLargeError("stream exceeds the byte cap")
                    digest.update(chunk)
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            try:
                # link(2) fails with EEXIST instead of replacing: write-once.
                os.link(tmp, path)
            except FileExistsError:
                raise BlobExistsError(
                    "an object already exists at this key", size=size, sha256=digest.hexdigest()
                ) from None
        finally:
            Path(tmp).unlink(missing_ok=True)
        return size, digest.hexdigest()

    def open(self, key: str) -> BinaryIO:
        return self._path(key).open("rb")

    def digest(self, key: str) -> tuple[int, str]:
        h = hashlib.sha256()
        size = 0
        with self._path(key).open("rb") as f:
            while chunk := f.read(_CHUNK):
                size += len(chunk)
                h.update(chunk)
        return size, h.hexdigest()

    def exists(self, key: str) -> bool:
        return self._path(key, partial_ok=True).is_file()

    def delete(self, key: str) -> None:
        self._path(key, partial_ok=True).unlink(missing_ok=True)

    def list_prefix(self, prefix: str) -> Iterator[str]:
        """Every stored file under ``prefix``, INCLUDING partial uploads a
        crashed writer left behind (``.upload-*``): deletion and its
        verification must account for all bytes, not only completed objects."""
        base = self._path(prefix)
        if not base.exists():
            return
        for p in sorted(base.rglob("*")):
            if p.is_file():
                yield p.relative_to(self.root).as_posix()


def list_area(store: LocalBlobStore, area: str) -> Iterator[str]:
    """OPERATOR ONLY (restore validation): every stored file in one area, across
    tenants. Runtime code must use ``TenantScopedBlobStore``."""
    if area not in AREAS:
        raise BlobKeyError("unknown storage area")
    base = store.root / area
    if not base.exists():
        return
    for p in sorted(base.rglob("*")):
        if p.is_file():
            yield p.relative_to(store.root).as_posix()


class TenantScopedBlobStore:
    """A view of ``inner`` that can only address one tenant's objects."""

    def __init__(self, inner: BlobStore, tenant_id: uuid.UUID) -> None:
        self._inner = inner
        self.tenant_id = tenant_id
        self._tenant = str(tenant_id)

    def key(self, area: str, dataset_id: uuid.UUID, name: str) -> str:
        """Derive a key server-side; clients never supply keys."""
        if area not in AREAS:
            raise BlobKeyError("unknown storage area")
        key = f"{area}/{self._tenant}/{dataset_id}/{name}"
        self._check(key)
        return key

    def _check(self, key: str) -> None:
        parts = validate_key(key)
        if len(parts) < 4 or parts[0] not in AREAS or parts[1] != self._tenant:
            raise BlobKeyError("key is outside this tenant's prefix")

    def put_stream(self, key: str, stream: BinaryIO, *, max_bytes: int) -> tuple[int, str]:
        self._check(key)
        return self._inner.put_stream(key, stream, max_bytes=max_bytes)

    def open(self, key: str) -> BinaryIO:
        self._check(key)
        return self._inner.open(key)

    def digest(self, key: str) -> tuple[int, str]:
        self._check(key)
        return self._inner.digest(key)

    def exists(self, key: str) -> bool:
        self._check(key)
        return self._inner.exists(key)

    def delete(self, key: str) -> None:
        self._check(key)
        self._inner.delete(key)

    def list_dataset(self, area: str, dataset_id: uuid.UUID) -> list[str]:
        prefix = f"{area}/{self._tenant}/{dataset_id}"
        self._check(prefix + "/x")
        return list(self._inner.list_prefix(prefix))

    def delete_dataset_and_verify(self, dataset_id: uuid.UUID) -> bool:
        """Delete every object for a dataset in both areas, then verify that
        each deleted key is gone. Returns True only when verification holds;
        the caller must keep the dataset in DELETING otherwise."""
        keys = [k for area in AREAS for k in self.list_dataset(area, dataset_id)]
        for k in keys:
            self._inner.delete(k)
        return not any(self._inner.exists(k) for k in keys) and not any(
            self.list_dataset(area, dataset_id) for area in AREAS
        )

    # --- per-version helpers (dataset uploads, ADR-030) ---------------------

    def version_key(self, area: str, dataset_id: uuid.UUID, version_id: uuid.UUID) -> str:
        """The only key a dataset version's bytes may have in ``area``."""
        return self.key(area, dataset_id, str(version_id))

    def list_version(self, dataset_id: uuid.UUID, version_id: uuid.UUID) -> list[str]:
        """Every stored file for one version in both areas, including partial
        uploads a crashed writer left behind for it."""
        name = str(version_id)
        partial = _partial_hint(name)
        out: list[str] = []
        for area in AREAS:
            for k in self.list_dataset(area, dataset_id):
                last = k.rpartition("/")[2]
                if last == name or last.startswith(partial):
                    out.append(k)
        return out

    def delete_version_and_verify(
        self, dataset_id: uuid.UUID, version_id: uuid.UUID
    ) -> tuple[list[str], bool]:
        """Delete every object (and partial) of one version, then verify none
        remains. Returns (deleted keys, verified). Idempotent: a second call
        deletes nothing and still verifies."""
        keys = self.list_version(dataset_id, version_id)
        for k in keys:
            self._inner.delete(k)
        verified = not any(self._inner.exists(k) for k in keys) and not self.list_version(
            dataset_id, version_id
        )
        return keys, verified

    def copy_verified(self, src: str, dst: str, *, expected_sha256: str, max_bytes: int) -> int:
        """Stream ``src`` to a NEW object ``dst`` and verify both digests equal
        ``expected_sha256``. On mismatch the new object is removed and
        ``BlobDigestMismatch`` is raised. If ``dst`` already exists with the
        expected digest (a retried publish) it is accepted; with any other
        digest it is refused."""
        self._check(src)
        self._check(dst)
        if self._inner.exists(dst):
            size, digest = self._inner.digest(dst)
            if digest != expected_sha256:
                raise BlobDigestMismatch("existing destination does not match")
            return size
        try:
            with self._inner.open(src) as stream:
                size, digest = self._inner.put_stream(dst, stream, max_bytes=max_bytes)
        except BlobExistsError:
            # A concurrent publisher linked dst first: accept it only if it holds
            # exactly the expected bytes (never replace it).
            size, digest = self._inner.digest(dst)
            if digest != expected_sha256:
                raise BlobDigestMismatch("existing destination does not match") from None
            return size
        if digest != expected_sha256:
            self._inner.delete(dst)
            raise BlobDigestMismatch("source bytes do not match the recorded digest")
        return size
