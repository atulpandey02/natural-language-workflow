"""Dataset upload and review routes (Phase 2B, ADR-030; ingest boundary ADR-031).

Mounted ONLY when ``DATASETS_API_ENABLED`` is true AND a dataset store is
configured (``DATASET_STORAGE_BACKEND=local``, which staging and production
refuse). Every route is admin/owner only:

- ``POST /datasets/{id}/versions``                     initiate (``Idempotency-Key``)
- ``PUT  /datasets/{id}/versions/{vid}/content``       raw ``text/csv`` body, streamed;
                                                        records an immutable processing
                                                        request and enqueues it
- ``POST /datasets/{id}/versions/{vid}/process``       re-dispatch a pending request
- ``GET  /datasets/{id}/versions/{vid}/profile``       the deterministic profile
- ``GET  /datasets/{id}/versions/{vid}/semantics``     confirmed revisions
- ``POST /datasets/{id}/versions/{vid}/semantics``     confirm a new revision
- ``POST /datasets/{id}/versions/{vid}/activate``      make it the active version

Tenant, actor, ids, numbers, statuses, storage keys and digests are always
server-derived; no client path, key or URL is accepted, and no storage key,
path or credential is ever returned. Another workspace's ids are 404.

The API NEVER profiles, takes a processing lease, inserts a profile, publishes
or rejects a version: the database refuses all of it for ``nlw_app``
(ADR-031). Processing belongs to the ingest runtime (``nlw_ingest``), which
consumes the envelope enqueued here. Commit-before-enqueue: the request is
durable before the message is sent; an enqueue failure is a 503 with the
request intact, re-driven by an idempotent retry of the upload, by
``POST .../process``, or by the operator sweep (``nlw.ops.datasets
dispatch-pending``). Delivery is at-least-once, processing idempotent.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncIterator
from typing import Any, NoReturn

import structlog
from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Request,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.api.deps import (
    _bearer,
    get_auth_provider,
    get_ctx_signer,
    get_current_user,
    get_session,
    get_tenant_context,
    rate_limit,
    require_role,
)
from nlw.api.routers.datasets import _raise, _version_out
from nlw.api.schemas import (
    DatasetVersionCreate,
    DatasetVersionOut,
    SemanticConfirmIn,
    SemanticRevisionOut,
)
from nlw.core.config import Settings
from nlw.datasets import ingestion, service
from nlw.datasets.envelope import WorkEnvelope, enqueue_envelope
from nlw.datasets.lifecycle import MetadataError
from nlw.datasets.processing_requests import ensure_processing_request
from nlw.datasets.semantics import SemanticMappingError, canonical_json, validate_mapping
from nlw.datasets.service import Actor, DatasetError
from nlw.storage.blob import BlobStore
from nlw.tenancy.context import Role, TenantContext, role_at_least
from nlw.tenancy.session import set_request_context
from nlw.tenancy.signing import Purpose

log = structlog.get_logger(__name__)
router = APIRouter()
_require_admin = require_role(Role.ADMIN)

# The ONLY path the global buffering body-size middleware lets through
# unbuffered; this route enforces its own (larger) streamed cap.
CONTENT_PATH = re.compile(r"^/datasets/[0-9a-fA-F-]{36}/versions/[0-9a-fA-F-]{36}/content$")


def _store(request: Request) -> BlobStore:
    store: BlobStore | None = request.app.state.dataset_store
    if store is None:  # pragma: no cover - the router is not mounted without a store
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "dataset storage unavailable")
    return store


def _semantic_error(exc: SemanticMappingError) -> NoReturn:
    raise HTTPException(
        status.HTTP_422_UNPROCESSABLE_ENTITY, {"code": exc.code, "message": str(exc)}
    ) from exc


def _enqueue(envelope: WorkEnvelope) -> None:
    """Send the envelope through the API's broker (the one ``nlw.worker.actors``
    configures for every enqueue). Never imports the ingest runtime."""
    import dramatiq

    import nlw.worker.actors  # noqa: F401  (configures the process's broker)

    enqueue_envelope(dramatiq.get_broker(), envelope)


def _dispatch(envelope: WorkEnvelope | None, dataset_id: uuid.UUID, version_id: uuid.UUID) -> None:
    """AFTER commit: enqueue (at-least-once). The committed request is the work
    item; a failure here loses nothing and is surfaced, never hidden."""
    if envelope is None:
        return
    try:
        _enqueue(envelope)
    except Exception as exc:  # infrastructure: the request stays durable
        log.error(
            "dataset.enqueue_failed",
            dataset_id=str(dataset_id),
            version_id=str(version_id),
            error_class=type(exc).__name__,
        )
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            {
                "code": "PROCESSING_NOT_QUEUED",
                "message": "the upload is stored and processing is requested, but it could "
                "not be queued; retry the request",
            },
        ) from None
    log.info("dataset.processing_requested", dataset_id=str(dataset_id), version_id=str(version_id))


@router.post(
    "/datasets/{dataset_id}/versions",
    response_model=DatasetVersionOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("datasets", "write"))],
)
async def initiate_upload(
    dataset_id: uuid.UUID,
    body: DatasetVersionCreate,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ctx: TenantContext = Depends(_require_admin),
    session: AsyncSession = Depends(get_session),
) -> DatasetVersionOut:
    """A new QUARANTINED version awaiting its bytes. Retrying with the same
    ``Idempotency-Key`` returns the same version."""
    _store(request)
    if idempotency_key is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            {"code": "IDEMPOTENCY_KEY_REQUIRED", "message": "Idempotency-Key header required"},
        )
    try:
        v = await service.create_version(
            session,
            ctx.tenant_id,
            Actor.user(ctx.user_id),
            dataset_id,
            original_filename=body.original_filename,
            media_type=body.media_type,
            declared_size_bytes=body.declared_size_bytes,
            idempotency_key=idempotency_key,
        )
    except (DatasetError, MetadataError) as exc:
        _raise(exc)
    return _version_out(v)


async def _short_admin_context(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
    x_workspace_id: str | None,
) -> TenantContext:
    """Authenticate and authorize in ONE short transaction that is committed
    before the body streams (no transaction is held open during an upload).
    Same checks and failure codes as ``require_role(Role.ADMIN)``."""
    maker = request.app.state.sessionmaker
    async with maker() as session, session.begin():
        user = await get_current_user(request, credentials, get_auth_provider(request), session)
        ctx = await get_tenant_context(request, x_workspace_id, user, session)
    if not role_at_least(ctx.role, Role.ADMIN):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
    await rate_limit("datasets", "write")(request, ctx)
    return ctx


@router.put(
    "/datasets/{dataset_id}/versions/{version_id}/content",
    response_model=DatasetVersionOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def upload_content(
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    x_workspace_id: str | None = Header(default=None),
) -> DatasetVersionOut:
    """Stream the CSV bytes (exactly the declared size) into quarantine, record
    them and an immutable processing request, then enqueue it for the ingest
    runtime. ``Content-Type`` is NOT trusted: the ingest runtime's profiler
    validates the bytes; the API never parses them."""
    ctx = await _short_admin_context(request, credentials, x_workspace_id)
    settings: Settings = request.app.state.settings
    # Advisory only (an early 413): the streamed cap below is authoritative.
    # ASCII digits only: ``str.isdigit`` also accepts e.g. superscripts.
    declared = request.headers.get("content-length", "")
    if (
        declared.isascii()
        and declared.isdigit()
        and int(declared) > settings.dataset_max_upload_bytes
    ):
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            {"code": "CONTENT_TOO_LARGE", "message": "the file exceeds the upload limit"},
        )

    async def chunks() -> AsyncIterator[bytes]:
        async for chunk in request.stream():
            if chunk:
                yield chunk

    try:
        v, envelope = await ingestion.store_content(
            maker=request.app.state.sessionmaker,
            signer=get_ctx_signer(request, Purpose.API_REQUEST),
            store=_store(request),
            ctx=ctx,
            dataset_id=dataset_id,
            version_id=version_id,
            chunks=chunks(),
            max_bytes=settings.dataset_max_upload_bytes,
        )
    except ingestion.ContentError as exc:
        raise HTTPException(
            exc.status, {"code": exc.code, "message": "the upload was refused"}
        ) from None
    except DatasetError as exc:
        _raise(exc)
    _dispatch(envelope, dataset_id, version_id)
    return _version_out(v)


@router.post(
    "/datasets/{dataset_id}/versions/{version_id}/process",
    response_model=DatasetVersionOut,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limit("datasets", "write"))],
)
async def process_upload(
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    request: Request,
    ctx: TenantContext = Depends(_require_admin),
) -> DatasetVersionOut:
    """Re-dispatch: (re)enqueue the version's processing request (recording a
    new one if the latest is no longer fresh). For a lost enqueue or a crashed
    processor whose lease expired; a no-op for anything already settled. It
    NEVER processes: the ingest runtime claims, profiles and settles."""
    _store(request)
    sessionmaker = request.app.state.sessionmaker
    try:
        async with sessionmaker() as session, session.begin():
            await set_request_context(session, get_ctx_signer(request, Purpose.API_REQUEST), ctx)
            v = await service.get_version(session, ctx.tenant_id, dataset_id, version_id)
            envelope = await ensure_processing_request(
                session, ctx.tenant_id, ctx.user_id, dataset_id, version_id
            )
    except DatasetError as exc:
        _raise(exc)
    _dispatch(envelope, dataset_id, version_id)  # after commit
    return _version_out(v)


@router.get("/datasets/{dataset_id}/versions/{version_id}/profile")
async def get_profile(
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    ctx: TenantContext = Depends(_require_admin),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    try:
        v = await service.get_version(session, ctx.tenant_id, dataset_id, version_id)
    except DatasetError as exc:
        _raise(exc)
    # A version being deleted is unusable for any purpose, review included.
    record = (
        None
        if v.status.value == "DELETING"
        else await service.get_profile(session, ctx.tenant_id, dataset_id, version_id)
    )
    if record is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            {"code": "PROFILE_NOT_AVAILABLE", "message": "no profile for this version"},
        )
    return dict(record.profile)


@router.get(
    "/datasets/{dataset_id}/versions/{version_id}/semantics",
    response_model=list[SemanticRevisionOut],
)
async def list_semantics(
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    ctx: TenantContext = Depends(_require_admin),
    session: AsyncSession = Depends(get_session),
) -> list[SemanticRevisionOut]:
    try:
        await service.get_version(session, ctx.tenant_id, dataset_id, version_id)
    except DatasetError as exc:
        _raise(exc)
    rows = await service.list_semantic_revisions(session, ctx.tenant_id, dataset_id, version_id)
    return [SemanticRevisionOut(**r.__dict__) for r in rows]


@router.post(
    "/datasets/{dataset_id}/versions/{version_id}/semantics",
    response_model=SemanticRevisionOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("datasets", "write"))],
)
async def confirm_semantics(
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    body: SemanticConfirmIn,
    ctx: TenantContext = Depends(_require_admin),
    session: AsyncSession = Depends(get_session),
) -> SemanticRevisionOut:
    """Confirm the column semantics for a PROFILED version (a new revision each
    time; earlier revisions stay). A person confirms: never automatic."""
    try:
        await service.get_version(session, ctx.tenant_id, dataset_id, version_id)
        profile = await service.get_profile(session, ctx.tenant_id, dataset_id, version_id)
        if profile is None:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                {"code": "PROFILE_NOT_AVAILABLE", "message": "the version is not profiled"},
            )
        mapping = validate_mapping(body.model_dump(), dict(profile.profile))
        rec = await service.confirm_semantics(
            session,
            ctx.tenant_id,
            Actor.user(ctx.user_id),
            dataset_id,
            version_id,
            mapping_json=canonical_json(mapping),
        )
    except SemanticMappingError as exc:
        _semantic_error(exc)
    except DatasetError as exc:
        _raise(exc)
    return SemanticRevisionOut(**rec.__dict__)


@router.post(
    "/datasets/{dataset_id}/versions/{version_id}/activate",
    response_model=DatasetVersionOut,
    dependencies=[Depends(rate_limit("datasets", "write"))],
)
async def activate(
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    ctx: TenantContext = Depends(_require_admin),
    session: AsyncSession = Depends(get_session),
) -> DatasetVersionOut:
    """PROFILED -> ACTIVE (the previous active version becomes SUPERSEDED).
    Requires confirmed semantics that still match the profile."""
    try:
        v = await service.activate_version(
            session, ctx.tenant_id, Actor.user(ctx.user_id), dataset_id, version_id
        )
    except DatasetError as exc:
        _raise(exc)
    return _version_out(v)
