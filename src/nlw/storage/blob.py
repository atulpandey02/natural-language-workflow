"""Blob storage abstraction for dataset bytes (ADR-030, ADR-033).

- ``BlobStore``: the protocol the upload, ingest and operator paths need.
- ``LocalBlobStore``: filesystem adapter for development and CI.
- ``nlw.storage.s3.S3BlobStore``: the AWS S3 adapter (ADR-033).
- ``TenantScopedBlobStore``: the ONLY wrapper runtime code should hold. Every key
  is derived server-side from ids; a key outside the bound tenant's prefix, or
  any key containing traversal or non-canonical segments, is refused before the
  backing store is touched.

ADR-033 D1: one immutable object per dataset version, written once and never
copied, moved or rewritten:

    versions/<workspace_id>/<dataset_id>/<version_id>/source.csv

PostgreSQL holds the version's lifecycle; "published" is a database state. The
legacy ``quarantine/`` and ``datasets/`` areas (development data written before
ADR-033) remain only listable and purgeable by the operator.

Runtime code can create and read objects, never remove them:
``TenantScopedBlobStore`` has no single-object delete or copy. Removal is the
operator's version-aware ``purge_prefix`` (purge, ``purge-rejected``).
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

OBJECT_AREA = "versions"
LEGACY_AREAS = ("quarantine", "datasets")
AREAS = (OBJECT_AREA, *LEGACY_AREAS)
SOURCE_NAME = "source.csv"
_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
# An in-progress (or crash-orphaned) LocalBlobStore upload: never a caller key,
# but still customer bytes, so dataset listing and deletion must see it.
_PARTIAL_PREFIX = ".upload-"
_PARTIAL = re.compile(r"^\.upload-[a-z0-9_]{1,64}$")
_CHUNK = 1 << 20
LOCAL_FINGERPRINT = "sha256:"


class BlobKeyError(ValueError):
    """A key is malformed or outside the caller's tenant prefix."""


class BlobTooLargeError(ValueError):
    """The stream exceeded the caller's hard byte cap; nothing was stored."""


class BlobSizeMismatch(ValueError):
    """The stream ended with a size other than the expected one; nothing was
    stored (refused BEFORE the object is finalized, so no delete is needed)."""

    def __init__(self, message: str, *, size: int) -> None:
        super().__init__(message)
        self.size = size


class BlobExistsError(ValueError):
    """An object already exists at the key; objects are never overwritten.

    When the race is lost at finalization (another writer finished first), the
    stream has been consumed: ``size``, ``sha256`` and ``fingerprint`` then
    describe what THIS writer streamed, so the caller can compare it with the
    winner's object through ``attributes`` (metadata only). They are ``None``
    when an existence pre-check refused the write before reading anything."""

    def __init__(
        self,
        message: str,
        *,
        size: int | None = None,
        sha256: str | None = None,
        fingerprint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.size = size
        self.sha256 = sha256
        self.fingerprint = fingerprint


class BlobDigestMismatch(ValueError):
    """Stored bytes do not match the recorded digest (tampered or truncated)."""


class BlobUnavailable(OSError):
    """The store could not be reached or refused the request. Messages are
    author-controlled: never a bucket, key, ARN, request id or credential."""


class BlobStore(Protocol):
    def put_stream(
        self, key: str, stream: BinaryIO, *, max_bytes: int, expected_size: int | None = None
    ) -> tuple[int, str]:
        """Store the stream at ``key`` (never replacing an existing object);
        return (byte_size, sha256 hex). Over ``max_bytes``: ``BlobTooLargeError``;
        ending at another size than ``expected_size``: ``BlobSizeMismatch``.
        Either way nothing is stored."""

    def open(self, key: str) -> BinaryIO: ...

    def digest(self, key: str) -> tuple[int, str]:
        """(byte_size, sha256 hex) of the stored object, computed by streaming."""

    def attributes(self, key: str) -> tuple[int, str]:
        """(byte_size, fingerprint) from METADATA only (no object read).
        ``FileNotFoundError`` if absent."""

    def exists(self, key: str) -> bool: ...

    def list_prefix(self, prefix: str) -> Iterator[str]:
        """Every stored item under ``prefix``, including partial uploads,
        noncurrent versions and delete markers: deletion and its verification
        must account for all bytes."""

    def purge_prefix(self, prefix: str) -> list[str]:
        """OPERATOR ONLY: remove every item ``list_prefix`` reports; return
        their identifiers."""

    def list_area(self, area: str) -> Iterator[str]:
        """OPERATOR ONLY (restore validation): every stored item in one area,
        across tenants."""


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


def item_key(item: str) -> str:
    """The object key of a ``list_prefix`` item (S3 items carry a version or
    upload suffix after ``#``)."""
    return item.partition("#")[0]


class LocalBlobStore:
    """Filesystem store rooted at ``root``. Writes are atomic and write-once
    (temp file + hard link, which fails if the target exists) and a stream over
    ``max_bytes`` or of the wrong size leaves no object behind."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str, *, partial_ok: bool = False) -> Path:
        key = key.removesuffix("/")
        head, _, last = key.rpartition("/")
        if partial_ok and head and _PARTIAL.match(last):
            validate_key(head)
        else:
            validate_key(key)
        path = (self.root / key).resolve()
        if self.root not in path.parents:
            raise BlobKeyError("key escapes the store root")
        return path

    def put_stream(
        self, key: str, stream: BinaryIO, *, max_bytes: int, expected_size: int | None = None
    ) -> tuple[int, str]:
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
            if expected_size is not None and size != expected_size:
                raise BlobSizeMismatch("the stream is not the expected size", size=size)
            sha = digest.hexdigest()
            try:
                # link(2) fails with EEXIST instead of replacing: write-once.
                os.link(tmp, path)
            except FileExistsError:
                raise BlobExistsError(
                    "an object already exists at this key",
                    size=size,
                    sha256=sha,
                    fingerprint=LOCAL_FINGERPRINT + sha,
                ) from None
        finally:
            Path(tmp).unlink(missing_ok=True)
        return size, sha

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

    def attributes(self, key: str) -> tuple[int, str]:
        size, sha = self.digest(key)  # the local store has no separate metadata
        return size, LOCAL_FINGERPRINT + sha

    def exists(self, key: str) -> bool:
        return self._path(key, partial_ok=True).is_file()

    def delete(self, key: str) -> None:
        """Development/test helper (not part of ``BlobStore``)."""
        self._path(key, partial_ok=True).unlink(missing_ok=True)

    def list_prefix(self, prefix: str) -> Iterator[str]:
        """Every stored file under ``prefix`` (a key or a directory prefix),
        INCLUDING partial uploads a crashed writer left behind (``.upload-*``)."""
        base = self._path(prefix, partial_ok=True)
        if base.is_file():
            yield base.relative_to(self.root).as_posix()
            return
        if not base.exists():
            return
        for p in sorted(base.rglob("*")):
            if p.is_file():
                yield p.relative_to(self.root).as_posix()

    def purge_prefix(self, prefix: str) -> list[str]:
        removed = list(self.list_prefix(prefix))
        for key in removed:
            (self.root / key).unlink(missing_ok=True)
        return removed

    def list_area(self, area: str) -> Iterator[str]:
        if area not in AREAS:
            raise BlobKeyError("unknown storage area")
        base = self.root / area
        if not base.exists():
            return
        for p in sorted(base.rglob("*")):
            if p.is_file():
                yield p.relative_to(self.root).as_posix()


def list_area(store: BlobStore, area: str) -> Iterator[str]:
    """OPERATOR ONLY (restore validation): every stored item in one area, across
    tenants. Runtime code must use ``TenantScopedBlobStore``."""
    if area not in AREAS:
        raise BlobKeyError("unknown storage area")
    return store.list_area(area)


class TenantScopedBlobStore:
    """A view of ``inner`` that can only address one tenant's objects.

    Runtime callers (the upload API, the ingest runtime) can create, read and
    inspect objects. There is deliberately no single-object delete and no copy:
    an object never moves, and only the operator's version-aware purge
    (``delete_version_and_verify`` / ``delete_dataset_and_verify``) removes
    bytes."""

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
        parts = validate_key(key.removesuffix("/"))
        if len(parts) < 3 or parts[0] not in AREAS or parts[1] != self._tenant:
            raise BlobKeyError("key is outside this tenant's prefix")

    def object_key(self, dataset_id: uuid.UUID, version_id: uuid.UUID) -> str:
        """The ONE key a dataset version's bytes ever have (ADR-033 D1)."""
        return self.key(OBJECT_AREA, dataset_id, f"{version_id}/{SOURCE_NAME}")

    def version_key(self, area: str, dataset_id: uuid.UUID, version_id: uuid.UUID) -> str:
        """``versions``: the object key; a legacy area: the pre-ADR-033 key
        (operator listing and purge of development data only)."""
        if area == OBJECT_AREA:
            return self.object_key(dataset_id, version_id)
        if area not in LEGACY_AREAS:
            raise BlobKeyError("unknown storage area")
        return self.key(area, dataset_id, str(version_id))

    def put_stream(
        self, key: str, stream: BinaryIO, *, max_bytes: int, expected_size: int | None = None
    ) -> tuple[int, str]:
        self._check(key)
        return self._inner.put_stream(key, stream, max_bytes=max_bytes, expected_size=expected_size)

    def open(self, key: str) -> BinaryIO:
        self._check(key)
        return self._inner.open(key)

    def digest(self, key: str) -> tuple[int, str]:
        self._check(key)
        return self._inner.digest(key)

    def attributes(self, key: str) -> tuple[int, str]:
        self._check(key)
        return self._inner.attributes(key)

    def exists(self, key: str) -> bool:
        self._check(key)
        return self._inner.exists(key)

    def list_dataset(self, area: str, dataset_id: uuid.UUID) -> list[str]:
        prefix = f"{area}/{self._tenant}/{dataset_id}/"
        self._check(prefix + "x")
        return list(self._inner.list_prefix(prefix))

    def delete_dataset_and_verify(self, dataset_id: uuid.UUID) -> bool:
        """OPERATOR ONLY. Remove every item (all versions, markers, partial
        uploads) of a dataset in every area, then verify none remains. True only
        when verification holds; the caller keeps the dataset DELETING otherwise."""
        for area in AREAS:
            prefix = f"{area}/{self._tenant}/{dataset_id}/"
            self._check(prefix + "x")
            self._inner.purge_prefix(prefix)
        return not any(self.list_dataset(area, dataset_id) for area in AREAS)

    # --- per-version helpers (dataset uploads, ADR-030/033) ----------------

    def _version_prefix(self, dataset_id: uuid.UUID, version_id: uuid.UUID) -> str:
        prefix = f"{OBJECT_AREA}/{self._tenant}/{dataset_id}/{version_id}/"
        self._check(prefix + SOURCE_NAME)
        return prefix

    def _legacy_items(self, dataset_id: uuid.UUID, version_id: uuid.UUID) -> list[str]:
        name = str(version_id)
        partial = _partial_hint(name)
        out: list[str] = []
        for area in LEGACY_AREAS:
            for item in self.list_dataset(area, dataset_id):
                last = item_key(item).rpartition("/")[2]
                if last == name or last.startswith(partial):
                    out.append(item)
        return out

    def list_version(self, dataset_id: uuid.UUID, version_id: uuid.UUID) -> list[str]:
        """Every stored item for one version: its object (every S3 version and
        delete marker, in-progress uploads, local partial files) and any legacy
        pre-ADR-033 copies."""
        prefix = self._version_prefix(dataset_id, version_id)
        return [*self._inner.list_prefix(prefix), *self._legacy_items(dataset_id, version_id)]

    def delete_version_and_verify(
        self, dataset_id: uuid.UUID, version_id: uuid.UUID
    ) -> tuple[list[str], bool]:
        """OPERATOR ONLY. Remove every item of one version (version-aware on
        S3), then verify none remains. Returns (removed items, verified).
        Idempotent: a second call removes nothing and still verifies."""
        removed = self._inner.purge_prefix(self._version_prefix(dataset_id, version_id))
        for item in self._legacy_items(dataset_id, version_id):
            removed += self._inner.purge_prefix(item_key(item))
        return removed, not self.list_version(dataset_id, version_id)
