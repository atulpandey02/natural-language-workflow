"""Dataset upload, profiling and review routes (Phase 2B, ADR-030).

Mounted ONLY when ``DATASETS_API_ENABLED`` is true AND a dataset store is
configured (``DATASET_STORAGE_BACKEND=local``, which staging and production
refuse). Every route is admin/owner only:

- ``POST /datasets/{id}/versions``                     initiate (``Idempotency-Key``)
- ``PUT  /datasets/{id}/versions/{vid}/content``       raw ``text/csv`` body, streamed
- ``POST /datasets/{id}/versions/{vid}/process``       (re)start profiling
- ``GET  /datasets/{id}/versions/{vid}/profile``       the deterministic profile
- ``GET  /datasets/{id}/versions/{vid}/semantics``     confirmed revisions
- ``POST /datasets/{id}/versions/{vid}/semantics``     confirm a new revision
- ``POST /datasets/{id}/versions/{vid}/activate``      make it the active version

Tenant, actor, ids, numbers, statuses, storage keys and digests are always
server-derived; no client path, key or URL is accepted, and no storage key,
path or credential is ever returned. Another workspace's ids are 404.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncIterator
from typing import Any, NoReturn

import structlog
from fastapi import (
    APIRouter,
    BackgroundTasks,
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
from nlw.datasets.lifecycle import MetadataError
from nlw.datasets.semantics import SemanticMappingError, canonical_json, validate_mapping
from nlw.datasets.service import Actor, DatasetError
from nlw.ingest.strict import StrictLimits
from nlw.storage.blob import BlobStore
from nlw.tenancy.context import Role, TenantContext, role_at_least
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


def ingestion_config(settings: Settings) -> ingestion.IngestionConfig:
    return ingestion.IngestionConfig(
        limits=StrictLimits(
            max_bytes=settings.dataset_max_upload_bytes,
            max_rows=settings.dataset_max_rows,
            max_columns=settings.dataset_max_columns,
            max_field_chars=settings.dataset_max_field_chars,
            timeout_s=float(settings.dataset_profile_timeout_s),
        ),
        memory_mb=settings.dataset_profile_memory_mb,
    )


def _semantic_error(exc: SemanticMappingError) -> NoReturn:
    raise HTTPException(
        status.HTTP_422_UNPROCESSABLE_ENTITY, {"code": exc.code, "message": str(exc)}
    ) from exc


async def _process_in_background(
    request: Request, ctx: TenantContext, d: uuid.UUID, v: uuid.UUID
) -> None:
    app = request.app
    try:
        result = await ingestion.process_version(
            maker=app.state.sessionmaker,
            signer=app.state.ctx_signers[Purpose.API_REQUEST],
            store=app.state.dataset_store,
            config=ingestion_config(app.state.settings),
            ctx=ctx,
            dataset_id=d,
            version_id=v,
        )
        log.info("dataset.processing_finished", dataset_id=str(d), version_id=str(v), result=result)
    except Exception as exc:  # the version stays PROFILING for an admin retry
        log.warning(
            "dataset.processing_error",
            dataset_id=str(d),
            version_id=str(v),
            error_class=type(exc).__name__,
        )


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
    background: BackgroundTasks,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    x_workspace_id: str | None = Header(default=None),
) -> DatasetVersionOut:
    """Stream the CSV bytes (exactly the declared size) into quarantine, then
    start profiling in the background. ``Content-Type`` is NOT trusted: the
    bytes themselves are validated by the profiler."""
    ctx = await _short_admin_context(request, credentials, x_workspace_id)
    settings: Settings = request.app.state.settings
    declared = request.headers.get("content-length")
    if (
        declared is not None
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
        v = await ingestion.store_content(
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
    if v.status.value == "QUARANTINED":
        background.add_task(_process_in_background, request, ctx, dataset_id, version_id)
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
    background: BackgroundTasks,
    ctx: TenantContext = Depends(_require_admin),
    session: AsyncSession = Depends(get_session),
) -> DatasetVersionOut:
    """Recovery for a crashed process: retry profiling for a version with content
    that is still QUARANTINED or whose PROFILING lease went stale, and remove
    bytes a crash left behind after a settled outcome (the quarantine copy of a
    published version, a rejected version's file). Otherwise a no-op."""
    _store(request)
    try:
        v = await service.get_version(session, ctx.tenant_id, dataset_id, version_id)
    except DatasetError as exc:
        _raise(exc)
    if v.has_content and v.status.value != "DELETING":
        background.add_task(_process_in_background, request, ctx, dataset_id, version_id)
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
