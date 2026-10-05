"""Upload ingestion around the lifecycle service (ADR-030).

Responsibilities (and nothing else):

1. ``store_content``: stream the request body into the version's write-once
   quarantine object (``quarantine/{tenant}/{dataset}/{version_id}``), capped at
   the declared size, then record its digest and key once.
2. ``process_version``: ``QUARANTINED -> PROFILING``; stream the stored object
   into the isolated profiler process (``nlw.ingest.runner``); then either
   publish (verified copy to ``datasets/``, profile + ``PROFILED`` in one
   transaction, remove the quarantine copy) or reject with a closed code (and
   remove the quarantine object).

Every database step is its own short transaction under a FRESHLY signed
``api_request`` context for the uploading admin (``actor_kind = service``): RLS
re-checks admin membership each time, so a demoted uploader's processing fails
closed. No transaction is held open while bytes stream. The general worker and
the scheduler are not involved.

Logs carry ids, codes, sizes and error classes only: never cell values, file
content, filenames, storage keys or credentials.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import BinaryIO, Literal

import anyio
import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from nlw.datasets import service
from nlw.datasets.lifecycle import RejectionCode, VersionStatus
from nlw.datasets.service import Actor, DatasetConflict
from nlw.ingest.strict import Profile2, StrictLimits
from nlw.storage.blob import (
    BlobDigestMismatch,
    BlobExistsError,
    BlobStore,
    BlobTooLargeError,
    TenantScopedBlobStore,
)
from nlw.tenancy.context import TenantContext
from nlw.tenancy.session import set_request_context
from nlw.tenancy.signing import ContextSigner

log = structlog.get_logger(__name__)

_MAX_RESULT_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class IngestionConfig:
    limits: StrictLimits
    memory_mb: int
    # Processing lease (database time): held for lease_ttl_s, renewed every
    # lease_renew_s while profiling runs. A crashed processor's lease expires
    # after at most lease_ttl_s and can then be reclaimed.
    lease_ttl_s: float = 120.0
    lease_renew_s: float = 30.0

    def __post_init__(self) -> None:
        if not 0 < self.lease_renew_s < self.lease_ttl_s <= service.MAX_LEASE_TTL_S:
            raise ValueError("need 0 < lease_renew_s < lease_ttl_s <= MAX_LEASE_TTL_S")


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
) -> service.VersionRecord:
    """Stream the body into the version's write-once quarantine object and record
    its digest. Idempotent: re-sending identical bytes returns the version;
    different bytes are a 409. The body must be exactly the declared size."""
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
        return version

    scoped = TenantScopedBlobStore(store, ctx.tenant_id)
    key = scoped.version_key("quarantine", dataset_id, version_id)
    created = False
    try:
        size, digest = await anyio.to_thread.run_sync(
            lambda: scoped.put_stream(key, _BodyReader(chunks), max_bytes=cap)  # type: ignore[arg-type]
        )
        created = True
    except BlobTooLargeError:
        raise ContentError("CONTENT_SIZE_MISMATCH", 413) from None
    except BlobExistsError as exc:
        # A concurrent or earlier attempt stored this version's object. Accept it
        # only if these bytes are identical; never replace it. If the race was
        # lost at the final link, the body was already streamed: use its digest.
        if exc.size is not None and exc.sha256 is not None:
            size, digest = exc.size, exc.sha256
        else:
            size, digest = await _hash_only(chunks, cap)
        existing = await anyio.to_thread.run_sync(lambda: scoped.digest(key))
        if existing != (size, digest):
            raise ContentError("CONTENT_CONFLICT", 409) from None
    if size != version.declared_size_bytes:
        if created:
            await anyio.to_thread.run_sync(lambda: scoped.delete(key))
        raise ContentError("CONTENT_SIZE_MISMATCH", 422)
    try:
        recorded = await in_context(
            maker,
            signer,
            ctx,
            lambda s: service.record_content(
                s,
                ctx.tenant_id,
                dataset_id,
                version_id,
                content_sha256=digest,
                storage_object_key=key,
            ),
        )
    except DatasetConflict as exc:
        # Different recorded content means our object cannot be this version's
        # (same key, write-once): the other writer won; nothing to clean up.
        raise ContentError(exc.code, 409) from None
    log.info(
        "dataset.content_stored",
        tenant_id=str(ctx.tenant_id),
        dataset_id=str(dataset_id),
        version_id=str(version_id),
        size_bytes=size,
    )
    return recorded


# ------------------------------------------------------------------ profiling
ProfilerStatus = Literal["profiled", "rejected", "failed"]


@dataclass(frozen=True)
class ProfilerOutcome:
    status: ProfilerStatus
    profile: Profile2 | None = None
    code: str | None = None


def _child_env() -> dict[str, str]:
    """No credentials: only what the interpreter needs to start."""
    keep = ("PATH", "LANG", "LC_ALL", "SYSTEMROOT", "TMPDIR")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env["PYTHONHASHSEED"] = "0"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


_TERM_GRACE_S = 2.0  # graceful SIGTERM window before a bounded SIGKILL


def _runner_argv(args: str) -> list[str]:
    """The isolated profiler command (separate function so tests can substitute
    deterministic misbehaving children)."""
    return [sys.executable, "-I", "-m", "nlw.ingest.runner", args]


async def _stop_child(proc: asyncio.subprocess.Process) -> None:
    """Terminate (SIGTERM), wait up to ``_TERM_GRACE_S``, then SIGKILL; always
    wait for the exit status and close the pipes. Idempotent."""
    if proc.stdin is not None:
        with contextlib.suppress(BrokenPipeError, ConnectionResetError, RuntimeError):
            proc.stdin.close()
    if proc.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), _TERM_GRACE_S)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            await proc.wait()
            log.warning("dataset.profiler_killed")
    else:
        await proc.wait()


async def run_profiler(
    open_stream: Callable[[], BinaryIO], config: IngestionConfig
) -> ProfilerOutcome:
    """Stream bytes into ``python -m nlw.ingest.runner`` and parse its single
    result line. A wall-clock overrun kills the process (``PARSE_TIMEOUT``)."""
    limits = config.limits
    args = json.dumps(
        {
            "max_bytes": limits.max_bytes,
            "max_rows": limits.max_rows,
            "max_columns": limits.max_columns,
            "max_field_chars": limits.max_field_chars,
            "timeout_s": limits.timeout_s,
            "memory_mb": config.memory_mb,
        }
    )
    proc = await asyncio.create_subprocess_exec(
        *_runner_argv(args),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env=_child_env(),
    )
    assert proc.stdin is not None and proc.stdout is not None

    async def feed() -> None:
        assert proc.stdin is not None
        stream = await anyio.to_thread.run_sync(open_stream)
        # A child that stops reading (a rejection) breaks the pipe: that is its
        # answer, read from stdout.
        try:
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                while chunk := await anyio.to_thread.run_sync(stream.read, 1 << 16):
                    proc.stdin.write(chunk)
                    await proc.stdin.drain()
        finally:
            stream.close()
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                proc.stdin.close()

    async def collect() -> bytes:
        assert proc.stdout is not None
        return await proc.stdout.read(_MAX_RESULT_BYTES)

    try:
        async with asyncio.timeout(limits.timeout_s + 10):
            _, out = await asyncio.gather(feed(), collect())
            await proc.wait()
    except TimeoutError:
        return ProfilerOutcome("rejected", code=RejectionCode.PARSE_TIMEOUT.value)
    finally:
        # Every exit path -- success, rejection, timeout, an error, or the
        # caller's cancellation (task cancelled, API shutting down) -- stops and
        # REAPS the child: no zombie, no orphan. Shielded so a second
        # cancellation cannot interrupt the cleanup itself.
        await asyncio.shield(_stop_child(proc))
    if proc.returncode not in (0, 3):  # killed by RLIMIT_CPU/AS or a signal
        return ProfilerOutcome("rejected", code=RejectionCode.PROCESSING_FAILED.value)
    try:
        result = json.loads(out.decode("utf-8").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return ProfilerOutcome("rejected", code=RejectionCode.PROCESSING_FAILED.value)
    if result.get("status") == "profiled":
        return ProfilerOutcome("profiled", profile=Profile2.model_validate(result["profile"]))
    if result.get("status") == "rejected":
        code = str(result.get("code"))
        if code not in RejectionCode.__members__:
            code = RejectionCode.PROCESSING_FAILED.value
        return ProfilerOutcome("rejected", code=code)
    return ProfilerOutcome("rejected", code=RejectionCode.PROCESSING_FAILED.value)


ProcessResult = Literal["profiled", "rejected", "skipped"]


async def process_version(
    *,
    maker: async_sessionmaker[AsyncSession],
    signer: ContextSigner,
    store: BlobStore,
    config: IngestionConfig,
    ctx: TenantContext,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
) -> ProcessResult:
    """Profile one version (see ``_process``). A deletion requested while the
    version was being profiled wins: the remaining steps are refused by the
    lifecycle (``DatasetConflict``) and the result is ``skipped``; the purge
    removes whatever bytes were written."""
    try:
        return await _process(
            maker=maker,
            signer=signer,
            store=store,
            config=config,
            ctx=ctx,
            dataset_id=dataset_id,
            version_id=version_id,
        )
    except DatasetConflict as exc:
        log.info("dataset.processing_superseded", code=exc.code)
        return "skipped"


# Settled states whose bytes a crashed process may have left behind.
_PUBLISHED_STATES = frozenset(
    {VersionStatus.PROFILED, VersionStatus.ACTIVE, VersionStatus.SUPERSEDED}
)


async def _remove_leftovers(
    scoped: TenantScopedBlobStore,
    version: service.VersionRecord,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
) -> None:
    """Idempotent recovery for a crash AFTER a settled outcome was committed:
    a published version must not keep its quarantine copy, and a rejected
    version must not keep any bytes. Never touches an in-flight upload
    (QUARANTINED/PROFILING) or a DELETING version (that is the purge's job)."""
    try:
        if version.status in _PUBLISHED_STATES:
            quarantine = scoped.version_key("quarantine", dataset_id, version_id)
            if await anyio.to_thread.run_sync(lambda: scoped.exists(quarantine)):
                await anyio.to_thread.run_sync(lambda: scoped.delete(quarantine))
                log.info("dataset.leftover_removed", version_id=str(version_id), area="quarantine")
        elif version.status is VersionStatus.REJECTED:
            keys, _ = await anyio.to_thread.run_sync(
                lambda: scoped.delete_version_and_verify(dataset_id, version_id)
            )
            if keys:
                log.info("dataset.leftover_removed", version_id=str(version_id), area="rejected")
    except OSError as exc:  # retried on the next process call; the purge covers it too
        log.warning("dataset.leftover_cleanup_failed", error_class=type(exc).__name__)


async def _process(
    *,
    maker: async_sessionmaker[AsyncSession],
    signer: ContextSigner,
    store: BlobStore,
    config: IngestionConfig,
    ctx: TenantContext,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
) -> ProcessResult:
    """Profile one version. Safe to call repeatedly and concurrently: only the
    caller that wins ``QUARANTINED -> PROFILING`` (or finds a STALE ``PROFILING``
    lease after a crash) profiles; everyone else gets ``skipped``."""
    actor = Actor.service(ctx.user_id)
    tenant = ctx.tenant_id
    scoped = TenantScopedBlobStore(store, tenant)

    token = uuid.uuid4()

    async def claim(
        s: AsyncSession,
    ) -> tuple[service.LeaseClaim, service.VersionRecord, str | None]:
        state, v = await service.acquire_processing_lease(
            s, tenant, actor, dataset_id, version_id, token=token, ttl_s=config.lease_ttl_s
        )
        key = await service.storage_key(s, tenant, dataset_id, version_id)
        return state, v, key

    try:
        state, version, key = await in_context(maker, signer, ctx, claim)
    except DatasetConflict:
        return "skipped"
    if state not in ("acquired", "reclaimed"):
        if state == "not_claimable":
            await _remove_leftovers(scoped, version, dataset_id, version_id)
        return "skipped"
    if key is None or version.content_sha256 is None:  # pragma: no cover - acquire needs a key
        return "skipped"

    lost = asyncio.Event()
    work = asyncio.create_task(
        _profile_and_settle(
            maker=maker,
            signer=signer,
            config=config,
            ctx=ctx,
            scoped=scoped,
            version=version,
            key=key,
            token=token,
        )
    )

    async def keep_lease() -> None:
        while True:
            await asyncio.sleep(config.lease_renew_s)
            renewed = await in_context(
                maker,
                signer,
                ctx,
                lambda s: service.renew_processing_lease(
                    s, tenant, dataset_id, version_id, token=token, ttl_s=config.lease_ttl_s
                ),
            )
            if not renewed:  # someone reclaimed it, or the version left PROFILING
                lost.set()
                work.cancel()
                return

    renewer = asyncio.create_task(keep_lease())
    try:
        return await work
    except asyncio.CancelledError:
        if lost.is_set():
            log.info("dataset.lease_lost", version_id=str(version_id))
            return "skipped"
        raise
    finally:
        renewer.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await renewer


async def _profile_and_settle(
    *,
    maker: async_sessionmaker[AsyncSession],
    signer: ContextSigner,
    config: IngestionConfig,
    ctx: TenantContext,
    scoped: TenantScopedBlobStore,
    version: service.VersionRecord,
    key: str,
    token: uuid.UUID,
) -> ProcessResult:
    """The work done while holding the lease. Settling (publish or reject)
    proves ownership with ``token``; a lost lease surfaces as LEASE_LOST."""
    actor = Actor.service(ctx.user_id)
    tenant, dataset_id, version_id = ctx.tenant_id, version.dataset_id, version.id
    assert version.content_sha256 is not None
    expected_sha = version.content_sha256
    published = scoped.version_key("datasets", dataset_id, version_id)

    async def reject(code: str) -> ProcessResult:
        await in_context(
            maker,
            signer,
            ctx,
            lambda s: service.reject_processing(
                s,
                tenant,
                actor,
                dataset_id,
                version_id,
                token=token,
                rejection_code=RejectionCode(code),
            ),
        )
        # Rejected bytes are not kept: delete now (the purge re-verifies later).
        try:
            await anyio.to_thread.run_sync(
                lambda: scoped.delete_version_and_verify(dataset_id, version_id)
            )
        except OSError as exc:
            log.warning("dataset.reject_cleanup_failed", error_class=type(exc).__name__)
        log.info(
            "dataset.version_rejected",
            tenant_id=str(tenant),
            dataset_id=str(dataset_id),
            version_id=str(version_id),
            rejection_code=code,
        )
        return "rejected"

    if key.startswith("datasets/"):  # pragma: no cover - PROFILING never has a published key
        return "skipped"
    try:
        stored = await anyio.to_thread.run_sync(lambda: scoped.digest(key))
    except (FileNotFoundError, OSError):
        return await reject(RejectionCode.CONTENT_MISMATCH.value)
    if stored != (version.declared_size_bytes, expected_sha):
        return await reject(RejectionCode.CONTENT_MISMATCH.value)

    outcome = await run_profiler(lambda: scoped.open(key), config)
    if outcome.status != "profiled" or outcome.profile is None:
        return await reject(outcome.code or RejectionCode.PROCESSING_FAILED.value)
    profile = outcome.profile
    if profile.content_sha256 != expected_sha or profile.size_bytes != version.declared_size_bytes:
        return await reject(RejectionCode.CONTENT_MISMATCH.value)

    try:
        await anyio.to_thread.run_sync(
            lambda: scoped.copy_verified(
                key, published, expected_sha256=expected_sha, max_bytes=config.limits.max_bytes
            )
        )
    except BlobDigestMismatch:
        return await reject(RejectionCode.CONTENT_MISMATCH.value)
    await in_context(
        maker,
        signer,
        ctx,
        lambda s: service.publish_profile(
            s,
            tenant,
            actor,
            dataset_id,
            version_id,
            profile_json=profile.model_dump_json(),
            contract_version=profile.contract_version,
            content_sha256=expected_sha,
            row_count=profile.row_count,
            column_count=profile.column_count,
            published_key=published,
            lease_token=token,
        ),
    )
    try:
        await anyio.to_thread.run_sync(lambda: scoped.delete(key))
    except OSError as exc:  # the purge lists both areas, so nothing is lost
        log.warning("dataset.quarantine_cleanup_failed", error_class=type(exc).__name__)
    log.info(
        "dataset.version_profiled",
        tenant_id=str(tenant),
        dataset_id=str(dataset_id),
        version_id=str(version_id),
        rows=profile.row_count,
        columns=profile.column_count,
    )
    return "profiled"
