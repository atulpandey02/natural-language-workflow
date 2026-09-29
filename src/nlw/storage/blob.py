"""Blob storage abstraction for dataset bytes (Phase 2 plan section 21).

- ``BlobStore``: the minimal protocol the ingestion path needs.
- ``LocalBlobStore``: filesystem adapter for development and CI.
- ``TenantScopedBlobStore``: the ONLY wrapper runtime code should hold. Every key
  is derived server-side as ``{area}/{tenant_id}/{dataset_id}/{object}``; a key
  outside the bound tenant's prefix, or any key containing traversal or
  non-canonical segments, is refused before the backing store is touched.

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
_CHUNK = 1 << 20


class BlobKeyError(ValueError):
    """A key is malformed or outside the caller's tenant prefix."""


class BlobTooLargeError(ValueError):
    """The stream exceeded the caller's hard byte cap; nothing was stored."""


class BlobStore(Protocol):
    def put_stream(self, key: str, stream: BinaryIO, *, max_bytes: int) -> tuple[int, str]:
        """Store the stream at ``key``; return (byte_size, sha256 hex)."""

    def open(self, key: str) -> BinaryIO: ...

    def exists(self, key: str) -> bool: ...

    def delete(self, key: str) -> None:
        """Idempotent: deleting a missing key is not an error."""

    def list_prefix(self, prefix: str) -> Iterator[str]: ...


def validate_key(key: str) -> list[str]:
    parts = key.split("/")
    if len(parts) < 2 or any(not _SEGMENT.match(p) for p in parts):
        raise BlobKeyError("malformed blob key")
    return parts


class LocalBlobStore:
    """Filesystem store rooted at ``root``. Writes are atomic (temp + rename) and
    a stream over ``max_bytes`` leaves no object behind."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        validate_key(key)
        path = (self.root / key).resolve()
        if self.root not in path.parents:
            raise BlobKeyError("key escapes the store root")
        return path

    def put_stream(self, key: str, stream: BinaryIO, *, max_bytes: int) -> tuple[int, str]:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        size = 0
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".upload-")
        try:
            with os.fdopen(fd, "wb") as out:
                while chunk := stream.read(_CHUNK):
                    size += len(chunk)
                    if size > max_bytes:
                        raise BlobTooLargeError("stream exceeds the byte cap")
                    digest.update(chunk)
                    out.write(chunk)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return size, digest.hexdigest()

    def open(self, key: str) -> BinaryIO:
        return self._path(key).open("rb")

    def exists(self, key: str) -> bool:
        return self._path(key).is_file()

    def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)

    def list_prefix(self, prefix: str) -> Iterator[str]:
        base = self._path(prefix)
        if not base.exists():
            return
        for p in sorted(base.rglob("*")):
            if p.is_file() and not p.name.startswith(".upload-"):
                yield p.relative_to(self.root).as_posix()


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
