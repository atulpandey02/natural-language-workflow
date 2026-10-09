"""Dataset processing by the ingest runtime (ADR-031).

``process_envelope`` takes one queue message and, only if it is a valid,
fresh, database-anchored work envelope (``nlw.datasets.envelope``), profiles that
ONE version:

1. verify the request row and claim the database-time lease, in one
   transaction (``QUARANTINED -> PROFILING``, or reclaim an expired lease);
2. stream the version's ONE immutable object
   (``versions/<ws>/<d>/<v>/source.csv``) into the isolated profiler process
   (``python -m nlw.ingest.runner``) while a background task renews the lease;
3. settle: publish (profile + ``PROFILED`` in one transaction) or reject with
   a closed code. Settling proves lease ownership; a lost lease abandons the
   work and publishes nothing.

ADR-033 D1: the ingest runtime is READ-ONLY on object storage. It never
uploads, overwrites, copies, moves, lists or deletes an object; "published"
is database state, and a rejected object stays immutable until the
operator's version-aware ``purge-rejected`` removes it (D2).

Every database step is its own short transaction under a FRESHLY signed
``dataset_ingest`` context for exactly that workspace and version
(``nlw_ingest``): RLS lets it see and change nothing else, and every
transition writes its authentic event (``actor_kind = service``, no user). The
storage key is never taken from the message: it is read from the version row
and checked against the server-derived key. No transaction is held open while
bytes stream.

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
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import BinaryIO, Literal

import anyio
import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from nlw.backup.recovery_lock import check_recovery_lock
from nlw.core.config import Settings
from nlw.datasets import envelope as envelopes
from nlw.datasets import service
from nlw.datasets.envelope import EnvelopeError, WorkEnvelope
from nlw.datasets.lifecycle import RejectionCode
from nlw.datasets.service import Actor, DatasetConflict, DatasetError
from nlw.ingest.strict import Profile2, StrictLimits
from nlw.storage.blob import BlobStore, TenantScopedBlobStore
from nlw.tenancy.session import set_ingest_context
from nlw.tenancy.signing import ContextSigner, Purpose

log = structlog.get_logger(__name__)

_MAX_RESULT_BYTES = 4 * 1024 * 1024
# The ingest runtime acts as a service with NO human identity (ADR-031).
ACTOR = Actor.service(None)


@dataclass(frozen=True)
class IngestionConfig:
    limits: StrictLimits
    memory_mb: int
    # Processing lease (database time): held for lease_ttl_s, renewed every
    # lease_renew_s while profiling runs. A crashed processor's lease expires
    # after at most lease_ttl_s and can then be reclaimed by a redelivery.
    lease_ttl_s: float = 120.0
    lease_renew_s: float = 30.0
    max_envelope_age_s: int = envelopes.MAX_ENVELOPE_AGE_S

    def __post_init__(self) -> None:
        if not 0 < self.lease_renew_s < self.lease_ttl_s <= service.MAX_LEASE_TTL_S:
            raise ValueError("need 0 < lease_renew_s < lease_ttl_s <= MAX_LEASE_TTL_S")
        if not 0 < self.max_envelope_age_s <= envelopes.MAX_ENVELOPE_AGE_S:
            raise ValueError("max_envelope_age_s out of range")


def config_from_settings(settings: Settings) -> IngestionConfig:
    return IngestionConfig(
        limits=StrictLimits(
            max_bytes=settings.dataset_max_upload_bytes,
            max_rows=settings.dataset_max_rows,
            max_columns=settings.dataset_max_columns,
            max_field_chars=settings.dataset_max_field_chars,
            timeout_s=float(settings.dataset_profile_timeout_s),
        ),
        memory_mb=settings.dataset_profile_memory_mb,
    )


# ------------------------------------------------------------------ transactions
async def in_ingest_context[T](
    maker: async_sessionmaker[AsyncSession],
    signer: ContextSigner,
    env: WorkEnvelope,
    fn: Callable[[AsyncSession], Awaitable[T]],
) -> T:
    """Run ``fn`` in ONE short transaction under a freshly signed ingest context
    for exactly the envelope's workspace and version.

    Every transaction (claim, renew, publish, reject) first consults the DR
    recovery lock, not only boot: a database restored while the runtime is up
    raises ``RecoveryLocked``/``RecoveryStateUnknown`` before anything changes,
    so in-flight work cannot settle against an un-enabled restore (its lease then
    expires, and processing resumes only after the operator enables runtimes)."""
    if signer.purpose is not Purpose.DATASET_INGEST:
        raise ValueError("the ingest runtime signs dataset_ingest contexts only")
    async with maker() as session, session.begin():
        await session.run_sync(lambda s: check_recovery_lock(s.connection()))
        await set_ingest_context(session, signer, env.tenant_id, env.version_id)
        return await fn(session)


_SQL_REQUEST = text(
    "SELECT dataset_id, content_sha256, envelope_sha256, "
    "(extract(epoch FROM requested_at) * 1000000)::bigint AS requested_at_us, "
    "(extract(epoch FROM now()) * 1000000)::bigint AS now_us "
    "FROM dataset_processing_requests "
    "WHERE id = :id AND tenant_id = :t AND version_id = :v"
)


async def verify_request(session: AsyncSession, env: WorkEnvelope, max_age_s: int) -> None:
    """The envelope must name a real request, field for field, and be fresh by
    the DATABASE clock. Raises ``EnvelopeError`` (nothing is changed)."""
    row = (
        await session.execute(
            _SQL_REQUEST, {"id": env.request_id, "t": env.tenant_id, "v": env.version_id}
        )
    ).first()
    if row is None:
        raise envelopes.TamperedEnvelope("no such processing request for this version")
    if (row.dataset_id, row.content_sha256, row.envelope_sha256, row.requested_at_us) != (
        env.dataset_id,
        env.content_sha256,
        env.envelope_sha256,
        env.requested_at_us,
    ):
        raise envelopes.TamperedEnvelope("envelope does not match its processing request")
    envelopes.check_fresh(env, now_us=int(row.now_us), max_age_s=max_age_s)


# ------------------------------------------------------------------ profiler
ProfilerStatus = Literal["profiled", "rejected"]


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
        # caller's cancellation (lease lost, shutdown) -- stops and REAPS the
        # child: no zombie, no orphan. Shielded so a second cancellation cannot
        # interrupt the cleanup itself.
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


# ------------------------------------------------------------------ processing
# "refused": the envelope was invalid, stale or forged (nothing changed).
ProcessResult = Literal["profiled", "rejected", "skipped", "refused"]


async def process_envelope(
    *,
    maker: async_sessionmaker[AsyncSession],
    signer: ContextSigner,
    store: BlobStore,
    config: IngestionConfig,
    message: str | bytes,
) -> ProcessResult:
    """Validate one queue message and profile its version (see the module
    docstring). Safe to deliver repeatedly and concurrently: only the delivery
    that wins the lease (or reclaims an expired one) profiles."""
    try:
        env = envelopes.parse(message)
    except EnvelopeError as exc:
        log.warning("dataset.envelope_refused", code=exc.code)
        return "refused"
    try:
        return await _process(maker=maker, signer=signer, store=store, config=config, env=env)
    except EnvelopeError as exc:
        log.warning("dataset.envelope_refused", code=exc.code, **env.ids())
        return "refused"
    except DatasetConflict as exc:
        # A deletion requested meanwhile wins: the lifecycle refuses the rest.
        log.info("dataset.processing_superseded", code=exc.code, **env.ids())
        return "skipped"


async def _process(
    *,
    maker: async_sessionmaker[AsyncSession],
    signer: ContextSigner,
    store: BlobStore,
    config: IngestionConfig,
    env: WorkEnvelope,
) -> ProcessResult:
    tenant, dataset_id, version_id = env.tenant_id, env.dataset_id, env.version_id
    scoped = TenantScopedBlobStore(store, tenant)
    token = uuid.uuid4()

    async def claim(
        s: AsyncSession,
    ) -> tuple[service.LeaseClaim, service.VersionRecord, str | None]:
        await verify_request(s, env, config.max_envelope_age_s)
        state, v = await service.acquire_processing_lease(
            s, tenant, ACTOR, dataset_id, version_id, token=token, ttl_s=config.lease_ttl_s
        )
        key = await service.storage_key(s, tenant, dataset_id, version_id)
        return state, v, key

    try:
        state, version, key = await in_ingest_context(maker, signer, env, claim)
    except DatasetError as exc:  # not found / not ACTIVE: nothing to do
        log.info("dataset.processing_not_possible", error_class=type(exc).__name__, **env.ids())
        return "skipped"
    if state not in ("acquired", "reclaimed"):
        return "skipped"
    if version.content_sha256 != env.content_sha256 or key is None:
        # The request row pinned this digest; a mismatch cannot be published.
        return await _reject(maker, signer, env, scoped, token, RejectionCode.CONTENT_MISMATCH)
    # The key is server-derived and bound to the version id by the database;
    # it must be exactly the version's one object key (never a caller's path).
    if key != scoped.object_key(dataset_id, version_id):
        return await _reject(maker, signer, env, scoped, token, RejectionCode.CONTENT_MISMATCH)

    lost = asyncio.Event()
    work = asyncio.create_task(
        _profile_and_settle(
            maker=maker,
            signer=signer,
            config=config,
            env=env,
            scoped=scoped,
            version=version,
            key=key,
            token=token,
        )
    )

    async def keep_lease() -> None:
        while True:
            await asyncio.sleep(config.lease_renew_s)
            renewed = await in_ingest_context(
                maker,
                signer,
                env,
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
            log.info("dataset.lease_lost", **env.ids())
            return "skipped"
        raise
    finally:
        renewer.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await renewer


async def _reject(
    maker: async_sessionmaker[AsyncSession],
    signer: ContextSigner,
    env: WorkEnvelope,
    scoped: TenantScopedBlobStore,
    token: uuid.UUID,
    code: RejectionCode,
) -> ProcessResult:
    await in_ingest_context(
        maker,
        signer,
        env,
        lambda s: service.reject_processing(
            s,
            env.tenant_id,
            ACTOR,
            env.dataset_id,
            env.version_id,
            token=token,
            rejection_code=code,
        ),
    )
    # The object stays immutable: only the operator's version-aware
    # ``purge-rejected`` removes it (ADR-033 D2). Nothing is deleted here.
    log.info("dataset.version_rejected", rejection_code=code.value, **env.ids())
    return "rejected"


async def _profile_and_settle(
    *,
    maker: async_sessionmaker[AsyncSession],
    signer: ContextSigner,
    config: IngestionConfig,
    env: WorkEnvelope,
    scoped: TenantScopedBlobStore,
    version: service.VersionRecord,
    key: str,
    token: uuid.UUID,
) -> ProcessResult:
    """The work done while holding the lease. Settling (publish or reject)
    proves ownership with ``token``; a lost lease surfaces as LEASE_LOST."""
    tenant, dataset_id, version_id = env.tenant_id, env.dataset_id, env.version_id
    expected_sha = env.content_sha256

    def reject(code: str) -> Awaitable[ProcessResult]:
        return _reject(maker, signer, env, scoped, token, RejectionCode(code))

    try:
        stored = await anyio.to_thread.run_sync(lambda: scoped.digest(key))
    except OSError:
        return await reject(RejectionCode.CONTENT_MISMATCH.value)
    if stored != (version.declared_size_bytes, expected_sha):
        return await reject(RejectionCode.CONTENT_MISMATCH.value)

    outcome = await run_profiler(lambda: scoped.open(key), config)
    if outcome.status != "profiled" or outcome.profile is None:
        return await reject(outcome.code or RejectionCode.PROCESSING_FAILED.value)
    profile = outcome.profile
    if profile.content_sha256 != expected_sha or profile.size_bytes != version.declared_size_bytes:
        return await reject(RejectionCode.CONTENT_MISMATCH.value)

    # Publishing is a database transition only: the object stays where it is.
    await in_ingest_context(
        maker,
        signer,
        env,
        lambda s: service.publish_profile(
            s,
            tenant,
            ACTOR,
            dataset_id,
            version_id,
            profile_json=profile.model_dump_json(),
            contract_version=profile.contract_version,
            content_sha256=expected_sha,
            row_count=profile.row_count,
            column_count=profile.column_count,
            lease_token=token,
        ),
    )
    log.info(
        "dataset.version_profiled",
        rows=profile.row_count,
        columns=profile.column_count,
        **env.ids(),
    )
    return "profiled"
