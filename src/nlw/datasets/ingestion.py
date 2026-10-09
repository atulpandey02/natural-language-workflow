"""Upload ingestion around the lifecycle service (ADR-030, ADR-031).

Responsibility (and nothing else): ``store_content`` streams the request body
into the version's ONE immutable object
(``versions/{tenant}/{dataset}/{version_id}/source.csv``, ADR-033 D1), capped
at the declared size and refused BEFORE it is finalized when the size differs
(so this module never deletes anything), then, in ONE transaction, records its
digest and key once and an immutable processing request. It returns the work
envelope the caller enqueues AFTER commit. Profiling never happens here: the
dedicated ingest runtime (``nlw.ingest_service``, role ``nlw_ingest``) is the
only processor.

The API reads object METADATA only (``attributes``: size and checksum
fingerprint, to adopt its own object after a lost response or crash); it
never reads object content and never deletes.

Every database step is a short transaction under a FRESHLY signed
``api_request`` context for the uploading admin: RLS re-checks admin
membership each time. No transaction is held open while bytes stream.

Logs carry ids, codes and sizes only: never cell values, file content,
filenames, storage keys or credentials.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable

import anyio
import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from nlw.datasets import service
from nlw.datasets.envelope import WorkEnvelope
from nlw.datasets.lifecycle import VersionStatus
from nlw.datasets.processing_requests import ensure_processing_request
from nlw.datasets.service import DatasetConflict
from nlw.storage.blob import (
    BlobExistsError,
    BlobSizeMismatch,
    BlobStore,
    BlobTooLargeError,
    BlobUnavailable,
    TenantScopedBlobStore,
)
from nlw.tenancy.context import TenantContext
from nlw.tenancy.session import set_request_context
from nlw.tenancy.signing import ContextSigner

log = structlog.get_logger(__name__)


class ContentError(Exception):
    """A content upload was refused. ``code`` is stable; ``status`` the HTTP code."""

    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


# ------------------------------------------------------------------ transactions
async def in_context[T](
    maker: async_sessionmaker[AsyncSession],
    signer: ContextSigner,
    ctx: TenantContext,
    fn: Callable[[AsyncSession], Awaitable[T]],
) -> T:
    """Run ``fn`` in ONE short transaction with a freshly signed request context."""
    async with maker() as session, session.begin():
        await set_request_context(session, signer, ctx)
        return await fn(session)


# ------------------------------------------------------------------ content upload
class _BodyReader:
    """A blocking file-like view of an async byte iterator, for use from a worker
    thread (``anyio.to_thread``): each ``read`` pulls the next request chunk on
    the event loop. Never buffers more than one chunk."""

    def __init__(self, chunks: AsyncIterator[bytes]) -> None:
        self._chunks = chunks
        self._pending = b""
        self._done = False

    async def _next(self) -> bytes:
        try:
            return await self._chunks.__anext__()
        except StopAsyncIteration:
            return b""

    def read(self, n: int = -1) -> bytes:
        while not self._pending and not self._done:
            chunk = anyio.from_thread.run(self._next)
            if not chunk:
                self._done = True
            self._pending = chunk
        if n < 0 or n >= len(self._pending):
            out, self._pending = self._pending, b""
        else:
            out, self._pending = self._pending[:n], self._pending[n:]
        return out


async def _hash_only(chunks: AsyncIterator[bytes], cap: int) -> tuple[int, str]:
    import hashlib

    h = hashlib.sha256()
    size = 0
    async for chunk in chunks:
        size += len(chunk)
        if size > cap:
            raise ContentError("CONTENT_TOO_LARGE", 413)
        h.update(chunk)
    return size, h.hexdigest()


async def store_content(
    *,
    maker: async_sessionmaker[AsyncSession],
    signer: ContextSigner,
    store: BlobStore,
    ctx: TenantContext,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    chunks: AsyncIterator[bytes],
    max_bytes: int,
) -> tuple[service.VersionRecord, WorkEnvelope | None]:
    """Stream the body into the version's one immutable object, then
    record its digest AND an immutable processing request in one transaction.
    Returns the version and the envelope to enqueue after commit (None when
    there is nothing to process). Idempotent: re-sending identical bytes returns
    the version and its (fresh or new) request; different bytes are a 409. The
    body must be exactly the declared size."""
    version = await in_context(
        maker,
        signer,
        ctx,
        lambda s: service.get_version(s, ctx.tenant_id, dataset_id, version_id),
    )
    if version.status is not VersionStatus.QUARANTINED and not version.has_content:
        raise ContentError("DATASET_VERSION_CONFLICT", 409)
    cap = min(version.declared_size_bytes, max_bytes)
    if version.has_content:  # a retried PUT: compare, store nothing
        size, digest = await _hash_only(chunks, cap)
        if (size, digest) != (version.declared_size_bytes, version.content_sha256):
            raise ContentError("CONTENT_CONFLICT", 409)
        envelope = await in_context(
            maker,
            signer,
            ctx,
            lambda s: ensure_processing_request(
                s, ctx.tenant_id, ctx.user_id, dataset_id, version_id
            ),
        )
        return version, envelope

    scoped = TenantScopedBlobStore(store, ctx.tenant_id)
    key = scoped.object_key(dataset_id, version_id)
    try:
        size, digest = await anyio.to_thread.run_sync(
            lambda: scoped.put_stream(
                key,
                _BodyReader(chunks),  # type: ignore[arg-type]
                max_bytes=cap,
                expected_size=version.declared_size_bytes,
            )
        )
    except BlobTooLargeError:
        raise ContentError("CONTENT_SIZE_MISMATCH", 413) from None
    except BlobSizeMismatch:
        # Refused before the object was finalized: nothing was stored.
        raise ContentError("CONTENT_SIZE_MISMATCH", 422) from None
    except BlobExistsError as exc:
        # An earlier attempt (a lost response, a crash before the database
        # commit) or a concurrent one stored this version's object. Adopt it
        # only if these bytes are identical, compared through METADATA (size
        # and checksum fingerprint), never by reading the object; never replace
        # it. A pre-check refusal (local store) consumed nothing: hash the rest.
        if exc.size is not None and exc.sha256 is not None and exc.fingerprint is not None:
            size, digest, mine = exc.size, exc.sha256, exc.fingerprint
        else:
            size, digest = await _hash_only(chunks, cap)
            mine = f"sha256:{digest}"
        try:
            existing = await anyio.to_thread.run_sync(lambda: scoped.attributes(key))
        except FileNotFoundError:
            raise ContentError("CONTENT_CONFLICT", 409) from None
        if existing != (size, mine) or size != version.declared_size_bytes:
            raise ContentError("CONTENT_CONFLICT", 409) from None
    except BlobUnavailable:
        raise ContentError("STORAGE_UNAVAILABLE", 503) from None

    async def record(s: AsyncSession) -> tuple[service.VersionRecord, WorkEnvelope | None]:
        v = await service.record_content(
            s, ctx.tenant_id, dataset_id, version_id, content_sha256=digest, storage_object_key=key
        )
        # Same transaction: content recorded <=> its processing request exists.
        return v, await ensure_processing_request(
            s, ctx.tenant_id, ctx.user_id, dataset_id, version_id
        )

    try:
        recorded, envelope = await in_context(maker, signer, ctx, record)
    except DatasetConflict as exc:
        # Nothing was recorded. CONTENT_CONFLICT: another writer's bytes are
        # this version's (write-once key). Otherwise the dataset or version
        # left QUARANTINED while streaming (deletion): it can never record
        # content again, and an object we created is removed by the operator
        # purge of that DELETING version (``verify-objects`` lists it until then).
        raise ContentError(exc.code, 409) from None
    log.info(
        "dataset.content_stored",
        tenant_id=str(ctx.tenant_id),
        dataset_id=str(dataset_id),
        version_id=str(version_id),
        size_bytes=size,
    )
    return recorded, envelope
