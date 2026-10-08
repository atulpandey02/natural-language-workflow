"""Dataset metadata routes (Phase 2A, ADR-029): metadata only.

Mounted ONLY when ``DATASETS_API_ENABLED`` is true, which staging and production
refuse (no upload or end-to-end deletion exists yet):

- ``GET    /datasets``                          list (member; paginated)
- ``POST   /datasets``                          create a container (admin/owner)
- ``GET    /datasets/{id}``                     read (member)
- ``DELETE /datasets/{id}``                     request deletion (admin/owner; idempotent)
- ``GET    /datasets/{id}/versions``            list versions (member; paginated)
- ``GET    /datasets/{id}/versions/{vid}``      read a version (member)
- ``DELETE /datasets/{id}/versions/{vid}``      request version deletion (admin/owner)

There is deliberately no route to create a version, upload bytes, move a version
through ingestion, activate it, or set any status: those are internal service
operations for the later upload/profiling/review work. Tenant, actor, status and
the active-version pointer are always server-derived. Another workspace's id is
indistinguishable from a nonexistent one (404). Nothing here is visible to the
planner.
"""

import uuid
from typing import NoReturn

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.api.deps import get_session, get_tenant_context, rate_limit, require_role
from nlw.api.schemas import DatasetCreate, DatasetOut, DatasetVersionOut
from nlw.datasets import service
from nlw.datasets.lifecycle import MetadataError
from nlw.datasets.service import (
    Actor,
    DatasetConflict,
    DatasetError,
    DatasetNotFound,
    DatasetRecord,
    DatasetVersionNotFound,
    VersionRecord,
)
from nlw.tenancy.context import Role, TenantContext

router = APIRouter()
_require_admin = require_role(Role.ADMIN)


def _raise(exc: DatasetError | MetadataError) -> NoReturn:
    if isinstance(exc, MetadataError):
        code = status.HTTP_422_UNPROCESSABLE_ENTITY
    elif isinstance(exc, (DatasetNotFound, DatasetVersionNotFound)):
        code = status.HTTP_404_NOT_FOUND
    elif isinstance(exc, DatasetConflict):
        code = status.HTTP_409_CONFLICT
    else:  # pragma: no cover - every DatasetError subclass is mapped above
        code = status.HTTP_400_BAD_REQUEST
    raise HTTPException(code, {"code": exc.code, "message": str(exc)}) from exc


def _dataset_out(d: DatasetRecord) -> DatasetOut:
    assert d.name is not None  # tombstones are never returned
    return DatasetOut(
        id=d.id,
        name=d.name,
        description=d.description,
        status=d.status.value,  # type: ignore[arg-type]
        active_version_id=d.active_version_id,
        version_count=d.last_version_number,
        created_by=d.created_by,
        created_at=d.created_at,
        updated_at=d.updated_at,
        deletion_requested_at=d.deletion_requested_at,
    )


def _version_out(v: VersionRecord) -> DatasetVersionOut:
    assert v.original_filename is not None  # tombstones are never returned
    return DatasetVersionOut(
        id=v.id,
        dataset_id=v.dataset_id,
        version_number=v.version_number,
        status=v.status.value,  # type: ignore[arg-type]
        original_filename=v.original_filename,
        media_type=v.media_type,
        declared_size_bytes=v.declared_size_bytes,
        content_sha256=v.content_sha256,
        rejection_code=v.rejection_code.value if v.rejection_code else None,
        created_by=v.created_by,
        created_at=v.created_at,
        activated_at=v.activated_at,
        superseded_at=v.superseded_at,
        rejected_at=v.rejected_at,
        deletion_requested_at=v.deletion_requested_at,
        has_content=v.has_content,
        profiling_started_at=v.profiling_started_at,
        profiled_at=v.profiled_at,
    )


@router.get("/datasets", response_model=list[DatasetOut])
async def list_datasets(
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100_000),
) -> list[DatasetOut]:
    rows = await service.list_datasets(session, ctx.tenant_id, limit=limit, offset=offset)
    return [_dataset_out(d) for d in rows]


@router.post(
    "/datasets",
    response_model=DatasetOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("datasets", "write"))],
)
async def create_dataset(
    body: DatasetCreate,
    ctx: TenantContext = Depends(_require_admin),
    session: AsyncSession = Depends(get_session),
) -> DatasetOut:
    try:
        d = await service.create_dataset(
            session,
            ctx.tenant_id,
            Actor.user(ctx.user_id),
            name=body.name,
            description=body.description,
        )
    except (DatasetError, MetadataError) as exc:
        _raise(exc)
    return _dataset_out(d)


@router.get("/datasets/{dataset_id}", response_model=DatasetOut)
async def get_dataset(
    dataset_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> DatasetOut:
    try:
        return _dataset_out(await service.get_dataset(session, ctx.tenant_id, dataset_id))
    except DatasetError as exc:
        _raise(exc)


@router.delete(
    "/datasets/{dataset_id}",
    response_model=DatasetOut,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limit("datasets", "write"))],
)
async def request_dataset_deletion(
    dataset_id: uuid.UUID,
    ctx: TenantContext = Depends(_require_admin),
    session: AsyncSession = Depends(get_session),
) -> DatasetOut:
    """Deletion REQUEST: the dataset and its versions become DELETING (unusable).
    The tombstone is a separate operator step; no stored objects exist yet."""
    try:
        d, _changed = await service.request_dataset_deletion(
            session, ctx.tenant_id, Actor.user(ctx.user_id), dataset_id
        )
    except DatasetError as exc:
        _raise(exc)
    return _dataset_out(d)


@router.get("/datasets/{dataset_id}/versions", response_model=list[DatasetVersionOut])
async def list_versions(
    dataset_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100_000),
) -> list[DatasetVersionOut]:
    try:
        rows = await service.list_versions(
            session, ctx.tenant_id, dataset_id, limit=limit, offset=offset
        )
    except DatasetError as exc:
        _raise(exc)
    return [_version_out(v) for v in rows]


@router.get("/datasets/{dataset_id}/versions/{version_id}", response_model=DatasetVersionOut)
async def get_version(
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    session: AsyncSession = Depends(get_session),
) -> DatasetVersionOut:
    try:
        await service.get_dataset(session, ctx.tenant_id, dataset_id)
        return _version_out(
            await service.get_version(session, ctx.tenant_id, dataset_id, version_id)
        )
    except DatasetError as exc:
        _raise(exc)


@router.delete(
    "/datasets/{dataset_id}/versions/{version_id}",
    response_model=DatasetVersionOut,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limit("datasets", "write"))],
)
async def request_version_deletion(
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    ctx: TenantContext = Depends(_require_admin),
    session: AsyncSession = Depends(get_session),
) -> DatasetVersionOut:
    try:
        v, _changed = await service.request_version_deletion(
            session, ctx.tenant_id, Actor.user(ctx.user_id), dataset_id, version_id
        )
    except DatasetError as exc:
        _raise(exc)
    return _version_out(v)
