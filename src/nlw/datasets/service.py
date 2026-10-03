"""Deterministic dataset lifecycle operations (ADR-029), metadata only.

Every function runs inside the caller's transaction, which must already carry a
signed request context for ``tenant_id`` (RLS then confines it to that
workspace; the explicit ``tenant_id`` predicates are defence in depth). Locks are
always taken dataset-row first, then version rows, so concurrent operations on a
dataset serialize without deadlock. Every state change is a compare-and-set
``UPDATE ... WHERE status = <expected>`` and appends exactly one
``dataset_events`` row in the same transaction. The database re-checks every
rule (migration ``0024_dataset_lifecycle``).

Nothing here reads or writes file bytes, storage objects or rows of customer
data, and nothing here is reachable from the planner.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.datasets.lifecycle import (
    DELETABLE_VERSION_STATES,
    VERSION_EVENT_FOR,
    ActorKind,
    DatasetStatus,
    EventType,
    ReasonCode,
    RejectionCode,
    VersionStatus,
    normalize_description,
    normalize_name,
    sanitize_filename,
    validate_declared_size,
    validate_media_type,
    version_transition_allowed,
)

_PG_UNIQUE_VIOLATION = "23505"


class DatasetError(Exception):
    """Base error with a stable code and a safe message."""

    code = "DATASET_ERROR"

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class DatasetNotFound(DatasetError):
    code = "DATASET_NOT_FOUND"


class DatasetVersionNotFound(DatasetError):
    code = "DATASET_VERSION_NOT_FOUND"


class DatasetConflict(DatasetError):
    code = "DATASET_CONFLICT"


@dataclass(frozen=True)
class Actor:
    kind: ActorKind
    user_id: uuid.UUID | None

    @classmethod
    def user(cls, user_id: uuid.UUID) -> Actor:
        return cls(ActorKind.USER, user_id)

    @classmethod
    def service(cls, user_id: uuid.UUID | None) -> Actor:
        return cls(ActorKind.SERVICE, user_id)


@dataclass(frozen=True)
class DatasetRecord:
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str | None
    description: str | None
    status: DatasetStatus
    active_version_id: uuid.UUID | None
    last_version_number: int
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime
    deletion_requested_at: datetime | None
    deleted_at: datetime | None


@dataclass(frozen=True)
class VersionRecord:
    id: uuid.UUID
    tenant_id: uuid.UUID
    dataset_id: uuid.UUID
    version_number: int
    status: VersionStatus
    original_filename: str | None
    media_type: str
    declared_size_bytes: int
    content_sha256: str | None
    rejection_code: RejectionCode | None
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime
    profiling_started_at: datetime | None
    profiled_at: datetime | None
    activated_at: datetime | None
    superseded_at: datetime | None
    rejected_at: datetime | None
    deletion_requested_at: datetime | None
    deleted_at: datetime | None


_DATASET_COLS = (
    "id, tenant_id, name, description, status, active_version_id, last_version_number, "
    "created_by, created_at, updated_at, deletion_requested_at, deleted_at"
)
# storage_object_key is deliberately never selected: it is internal and future.
_VERSION_COLS = (
    "id, tenant_id, dataset_id, version_number, status, original_filename, media_type, "
    "declared_size_bytes, content_sha256, rejection_code, created_by, created_at, updated_at, "
    "profiling_started_at, profiled_at, activated_at, superseded_at, rejected_at, "
    "deletion_requested_at, deleted_at"
)


# Every statement is a module-level constant with bound parameters only
# (tests/unit/test_sql_injection_guard.py); the column lists are fixed text.
_SQL_LIST_DATASETS = (
    "SELECT " + _DATASET_COLS + " FROM datasets WHERE tenant_id = :t "
    "AND status <> 'DELETED' ORDER BY created_at, id LIMIT :limit OFFSET :offset"
)
_SQL_GET_DATASET = (
    "SELECT " + _DATASET_COLS + " FROM datasets WHERE id = :d AND tenant_id = :t "
    "AND status <> 'DELETED'"
)
_SQL_GET_DATASET_FOR_UPDATE = _SQL_GET_DATASET + " FOR UPDATE"
_SQL_LIST_VERSIONS = (
    "SELECT " + _VERSION_COLS + " FROM dataset_versions WHERE tenant_id = :t "
    "AND dataset_id = :d AND status <> 'DELETED' ORDER BY version_number "
    "LIMIT :limit OFFSET :offset"
)
_SQL_GET_VERSION = (
    "SELECT " + _VERSION_COLS + " FROM dataset_versions WHERE id = :v AND dataset_id = :d "
    "AND tenant_id = :t AND status <> 'DELETED'"
)
_SQL_GET_VERSION_FOR_UPDATE = _SQL_GET_VERSION + " FOR UPDATE"
_SQL_INSERT_DATASET = (
    "INSERT INTO datasets (id, tenant_id, name, normalized_name, description, status, "
    "created_by) VALUES (:id, :t, :name, :key, :desc, 'ACTIVE', :by) RETURNING " + _DATASET_COLS
)
_SQL_INSERT_VERSION = (
    "INSERT INTO dataset_versions (id, tenant_id, dataset_id, version_number, status, "
    "original_filename, media_type, declared_size_bytes, created_by) VALUES "
    "(:id, :t, :d, :n, 'QUARANTINED', :fn, :mt, :size, :by) RETURNING " + _VERSION_COLS
)
_SQL_CAS_VERSION = (
    "UPDATE dataset_versions SET status = :dst, rejection_code = COALESCE(:code, rejection_code) "
    "WHERE id = :v AND dataset_id = :d AND tenant_id = :t AND status = :src "
    "RETURNING " + _VERSION_COLS
)
_SQL_DATASET_TO_DELETING = (
    "UPDATE datasets SET status = 'DELETING', active_version_id = NULL "
    "WHERE id = :d AND tenant_id = :t AND status = 'ACTIVE' RETURNING " + _DATASET_COLS
)


def _dataset(row: Any) -> DatasetRecord:
    m = dict(row._mapping)
    m["status"] = DatasetStatus(m["status"])
    return DatasetRecord(**m)


def _version(row: Any) -> VersionRecord:
    m = dict(row._mapping)
    m["status"] = VersionStatus(m["status"])
    m["rejection_code"] = RejectionCode(m["rejection_code"]) if m["rejection_code"] else None
    return VersionRecord(**m)


async def _event(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID | None,
    event_type: EventType,
    from_status: str | None,
    to_status: str,
    actor: Actor,
    reason_code: str | None = None,
) -> None:
    await session.execute(
        text(
            "INSERT INTO dataset_events (id, tenant_id, dataset_id, version_id, event_type, "
            "from_status, to_status, actor_kind, actor_user_id, reason_code) VALUES "
            "(:id, :tenant_id, :dataset_id, :version_id, :event_type, :from_status, "
            ":to_status, :actor_kind, :actor_user_id, :reason_code)"
        ),
        {
            "id": uuid.uuid4(),
            "tenant_id": tenant_id,
            "dataset_id": dataset_id,
            "version_id": version_id,
            "event_type": event_type.value,
            "from_status": from_status,
            "to_status": to_status,
            "actor_kind": actor.kind.value,
            "actor_user_id": actor.user_id,
            "reason_code": reason_code,
        },
    )


# --- reads (member) ---------------------------------------------------------


async def list_datasets(
    session: AsyncSession, tenant_id: uuid.UUID, *, limit: int, offset: int
) -> list[DatasetRecord]:
    """Live and DELETING datasets; tombstones are not listed."""
    rows = await session.execute(
        text(_SQL_LIST_DATASETS),
        {"t": tenant_id, "limit": limit, "offset": offset},
    )
    return [_dataset(r) for r in rows]


async def get_dataset(
    session: AsyncSession, tenant_id: uuid.UUID, dataset_id: uuid.UUID, *, for_update: bool = False
) -> DatasetRecord:
    """A visible, non-tombstoned dataset or ``DatasetNotFound`` (also for another
    tenant's id: invisible and nonexistent are indistinguishable)."""
    sql = _SQL_GET_DATASET_FOR_UPDATE if for_update else _SQL_GET_DATASET
    row = (
        await session.execute(
            text(sql),
            {"d": dataset_id, "t": tenant_id},
        )
    ).first()
    if row is None:
        raise DatasetNotFound("dataset not found")
    return _dataset(row)


async def list_versions(
    session: AsyncSession, tenant_id: uuid.UUID, dataset_id: uuid.UUID, *, limit: int, offset: int
) -> list[VersionRecord]:
    await get_dataset(session, tenant_id, dataset_id)
    rows = await session.execute(
        text(_SQL_LIST_VERSIONS),
        {"t": tenant_id, "d": dataset_id, "limit": limit, "offset": offset},
    )
    return [_version(r) for r in rows]


async def get_version(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    *,
    for_update: bool = False,
) -> VersionRecord:
    sql = _SQL_GET_VERSION_FOR_UPDATE if for_update else _SQL_GET_VERSION
    row = (
        await session.execute(
            text(sql),
            {"v": version_id, "d": dataset_id, "t": tenant_id},
        )
    ).first()
    if row is None:
        raise DatasetVersionNotFound("dataset version not found")
    return _version(row)


# --- container (admin) ------------------------------------------------------


async def create_dataset(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    actor: Actor,
    *,
    name: str,
    description: str | None,
) -> DatasetRecord:
    display, key = normalize_name(name)
    desc = normalize_description(description)
    dataset_id = uuid.uuid4()
    try:
        async with session.begin_nested():
            row = (
                await session.execute(
                    text(_SQL_INSERT_DATASET),
                    {
                        "id": dataset_id,
                        "t": tenant_id,
                        "name": display,
                        "key": key,
                        "desc": desc,
                        "by": actor.user_id,
                    },
                )
            ).one()
    except IntegrityError as exc:
        if getattr(exc.orig, "sqlstate", None) == _PG_UNIQUE_VIOLATION:
            raise DatasetConflict(
                "a dataset with this name already exists", "DATASET_NAME_TAKEN"
            ) from None
        raise
    await _event(
        session,
        tenant_id=tenant_id,
        dataset_id=dataset_id,
        version_id=None,
        event_type=EventType.DATASET_CREATED,
        from_status=None,
        to_status=DatasetStatus.ACTIVE.value,
        actor=actor,
    )
    return _dataset(row)


# --- versions (internal service; no route in this change) -------------------


async def create_version(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    actor: Actor,
    dataset_id: uuid.UUID,
    *,
    original_filename: str,
    media_type: str,
    declared_size_bytes: int,
) -> VersionRecord:
    """A QUARANTINED version with the next number from the dataset's atomic
    counter (the UPDATE row-locks the dataset; numbers are never reused)."""
    filename = sanitize_filename(original_filename)
    media = validate_media_type(media_type)
    size = validate_declared_size(declared_size_bytes)
    allocated = (
        await session.execute(
            text(
                "UPDATE datasets SET last_version_number = last_version_number + 1 "
                "WHERE id = :d AND tenant_id = :t AND status = 'ACTIVE' "
                "RETURNING last_version_number"
            ),
            {"d": dataset_id, "t": tenant_id},
        )
    ).scalar()
    if allocated is None:
        await get_dataset(session, tenant_id, dataset_id)  # NotFound if invisible
        raise DatasetConflict("the dataset is not accepting versions", "DATASET_NOT_ACTIVE")
    version_id = uuid.uuid4()
    row = (
        await session.execute(
            text(_SQL_INSERT_VERSION),
            {
                "id": version_id,
                "t": tenant_id,
                "d": dataset_id,
                "n": allocated,
                "fn": filename,
                "mt": media,
                "size": size,
                "by": actor.user_id,
            },
        )
    ).one()
    await _event(
        session,
        tenant_id=tenant_id,
        dataset_id=dataset_id,
        version_id=version_id,
        event_type=EventType.VERSION_CREATED,
        from_status=None,
        to_status=VersionStatus.QUARANTINED.value,
        actor=actor,
    )
    return _version(row)


async def _cas_version(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    *,
    src: VersionStatus,
    dst: VersionStatus,
    actor: Actor,
    rejection_code: RejectionCode | None = None,
    reason_code: str | None = None,
) -> VersionRecord:
    row = (
        await session.execute(
            text(_SQL_CAS_VERSION),
            {
                "dst": dst.value,
                "code": rejection_code.value if rejection_code else None,
                "v": version_id,
                "d": dataset_id,
                "t": tenant_id,
                "src": src.value,
            },
        )
    ).first()
    if row is None:  # the row is locked by the caller, so this is a lost CAS
        raise DatasetConflict("the version changed concurrently", "DATASET_VERSION_CONFLICT")
    await _event(
        session,
        tenant_id=tenant_id,
        dataset_id=dataset_id,
        version_id=version_id,
        event_type=VERSION_EVENT_FOR[dst],
        from_status=src.value,
        to_status=dst.value,
        actor=actor,
        reason_code=reason_code
        if reason_code is not None
        else (rejection_code.value if rejection_code else None),
    )
    return _version(row)


_INGEST_TARGETS = frozenset(
    {VersionStatus.PROFILING, VersionStatus.PROFILED, VersionStatus.REJECTED}
)


async def transition_version(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    actor: Actor,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    *,
    to: VersionStatus,
    rejection_code: RejectionCode | None = None,
) -> VersionRecord:
    """Ingestion/review transitions only: ``-> PROFILING``, ``-> PROFILED`` and
    ``-> REJECTED`` (with a constrained code). Activation and deletion have their
    own operations; there is no generic "set status"."""
    if to not in _INGEST_TARGETS:
        raise DatasetConflict("unsupported transition", "DATASET_VERSION_INVALID_TRANSITION")
    if (to is VersionStatus.REJECTED) != (rejection_code is not None):
        raise DatasetConflict(
            "a rejection needs exactly one rejection code", "DATASET_VERSION_INVALID_TRANSITION"
        )
    dataset = await get_dataset(session, tenant_id, dataset_id, for_update=True)
    if dataset.status is not DatasetStatus.ACTIVE:
        raise DatasetConflict("the dataset is being deleted", "DATASET_NOT_ACTIVE")
    version = await get_version(session, tenant_id, dataset_id, version_id, for_update=True)
    if not version_transition_allowed(version.status, to):
        raise DatasetConflict(
            f"cannot move a {version.status.value} version to {to.value}",
            "DATASET_VERSION_INVALID_TRANSITION",
        )
    return await _cas_version(
        session,
        tenant_id,
        dataset_id,
        version_id,
        src=version.status,
        dst=to,
        actor=actor,
        rejection_code=rejection_code,
    )


async def activate_version(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    actor: Actor,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
) -> VersionRecord:
    """Make a PROFILED version the dataset's single ACTIVE version, in one
    transaction: the previous ACTIVE version (if any) becomes SUPERSEDED and
    stays immutable and addressable."""
    dataset = await get_dataset(session, tenant_id, dataset_id, for_update=True)
    if dataset.status is not DatasetStatus.ACTIVE:
        raise DatasetConflict("the dataset is being deleted", "DATASET_NOT_ACTIVE")
    version = await get_version(session, tenant_id, dataset_id, version_id, for_update=True)
    if version.status is not VersionStatus.PROFILED:
        raise DatasetConflict(
            "only a PROFILED version can be activated", "DATASET_VERSION_NOT_ELIGIBLE"
        )
    if dataset.active_version_id is not None:
        await get_version(
            session, tenant_id, dataset_id, dataset.active_version_id, for_update=True
        )
        await _cas_version(
            session,
            tenant_id,
            dataset_id,
            dataset.active_version_id,
            src=VersionStatus.ACTIVE,
            dst=VersionStatus.SUPERSEDED,
            actor=actor,
        )
    activated = await _cas_version(
        session,
        tenant_id,
        dataset_id,
        version_id,
        src=VersionStatus.PROFILED,
        dst=VersionStatus.ACTIVE,
        actor=actor,
    )
    await session.execute(
        text(
            "UPDATE datasets SET active_version_id = :v WHERE id = :d AND tenant_id = :t "
            "AND status = 'ACTIVE'"
        ),
        {"v": version_id, "d": dataset_id, "t": tenant_id},
    )
    return activated


# --- deletion (admin) -------------------------------------------------------


async def request_dataset_deletion(
    session: AsyncSession, tenant_id: uuid.UUID, actor: Actor, dataset_id: uuid.UUID
) -> tuple[DatasetRecord, bool]:
    """ACTIVE -> DELETING, with every live version -> DELETING and the active
    pointer cleared, atomically. Returns (dataset, changed); a repeated request
    on a DELETING dataset changes nothing (idempotent)."""
    dataset = await get_dataset(session, tenant_id, dataset_id, for_update=True)
    if dataset.status is DatasetStatus.DELETING:
        return dataset, False
    live = (
        await session.execute(
            text(
                "SELECT id, status FROM dataset_versions WHERE dataset_id = :d AND tenant_id = :t "
                "AND status NOT IN ('DELETING', 'DELETED') ORDER BY version_number FOR UPDATE"
            ),
            {"d": dataset_id, "t": tenant_id},
        )
    ).all()
    for vid, status in live:
        await _cas_version(
            session,
            tenant_id,
            dataset_id,
            vid,
            src=VersionStatus(status),
            dst=VersionStatus.DELETING,
            actor=actor,
            reason_code=ReasonCode.DATASET_DELETION.value,
        )
    row = (
        await session.execute(
            text(_SQL_DATASET_TO_DELETING),
            {"d": dataset_id, "t": tenant_id},
        )
    ).one()
    await _event(
        session,
        tenant_id=tenant_id,
        dataset_id=dataset_id,
        version_id=None,
        event_type=EventType.DATASET_DELETION_REQUESTED,
        from_status=DatasetStatus.ACTIVE.value,
        to_status=DatasetStatus.DELETING.value,
        actor=actor,
        reason_code=ReasonCode.USER_REQUEST.value,
    )
    return _dataset(row), True


async def request_version_deletion(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    actor: Actor,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
) -> tuple[VersionRecord, bool]:
    """One version -> DELETING (idempotent). Deleting the ACTIVE version leaves
    the dataset without an active version; it is never silently replaced."""
    dataset = await get_dataset(session, tenant_id, dataset_id, for_update=True)
    version = await get_version(session, tenant_id, dataset_id, version_id, for_update=True)
    if version.status is VersionStatus.DELETING:
        return version, False
    if version.status not in DELETABLE_VERSION_STATES:  # pragma: no cover - DELETED is invisible
        raise DatasetConflict("the version cannot be deleted", "DATASET_VERSION_INVALID_TRANSITION")
    deleting = await _cas_version(
        session,
        tenant_id,
        dataset_id,
        version_id,
        src=version.status,
        dst=VersionStatus.DELETING,
        actor=actor,
        reason_code=ReasonCode.USER_REQUEST.value,
    )
    if dataset.active_version_id == version_id:
        await session.execute(
            text(
                "UPDATE datasets SET active_version_id = NULL WHERE id = :d AND tenant_id = :t "
                "AND active_version_id = :v"
            ),
            {"d": dataset_id, "t": tenant_id, "v": version_id},
        )
    return deleting, True
