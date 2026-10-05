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
data (``nlw.datasets.ingestion`` does that around these calls), and nothing here
is reachable from the planner.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

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
    validate_idempotency_key,
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
    has_content: bool = False


_DATASET_COLS = (
    "id, tenant_id, name, description, status, active_version_id, last_version_number, "
    "created_by, created_at, updated_at, deletion_requested_at, deleted_at"
)
# storage_object_key is deliberately never selected here: only whether content
# exists. The key itself is internal (see _SQL_GET_STORAGE_KEY) and never leaves
# the ingestion module.
_VERSION_COLS = (
    "id, tenant_id, dataset_id, version_number, status, original_filename, media_type, "
    "declared_size_bytes, content_sha256, rejection_code, created_by, created_at, updated_at, "
    "profiling_started_at, profiled_at, activated_at, superseded_at, rejected_at, "
    "deletion_requested_at, deleted_at, (storage_object_key IS NOT NULL) AS has_content"
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
_SQL_VERSION_BY_IDEMPOTENCY = (
    "SELECT " + _VERSION_COLS + " FROM dataset_versions WHERE tenant_id = :t "
    "AND dataset_id = :d AND upload_idempotency_key = :k"
)
_SQL_INSERT_VERSION_IDEMPOTENT = (
    "INSERT INTO dataset_versions (id, tenant_id, dataset_id, version_number, status, "
    "original_filename, media_type, declared_size_bytes, created_by, upload_idempotency_key) "
    "VALUES (:id, :t, :d, :n, 'QUARANTINED', :fn, :mt, :size, :by, :k) RETURNING " + _VERSION_COLS
)
_SQL_SET_CONTENT = (
    "UPDATE dataset_versions SET content_sha256 = :sha, storage_object_key = :key "
    "WHERE id = :v AND dataset_id = :d AND tenant_id = :t AND status = 'QUARANTINED' "
    "AND storage_object_key IS NULL AND content_sha256 IS NULL RETURNING " + _VERSION_COLS
)
_SQL_GET_STORAGE_KEY = (
    "SELECT storage_object_key FROM dataset_versions WHERE id = :v AND dataset_id = :d "
    "AND tenant_id = :t AND status <> 'DELETED'"
)
# Publication proves CURRENT lease ownership: the token must still be ours (a
# reclaimer replaces it) and the database refuses an expired lease.
_SQL_CAS_PUBLISH = (
    "UPDATE dataset_versions SET status = 'PROFILED', storage_object_key = :key "
    "WHERE id = :v AND dataset_id = :d AND tenant_id = :t AND status = 'PROFILING' "
    "AND processing_lease_token = :tok RETURNING " + _VERSION_COLS
)
# Processing lease primitives. Every expiry decision uses PostgreSQL's clock
# (now()); the application host's clock is never consulted. Each is ONE
# compare-and-set statement, so concurrent claimants cannot both succeed.
_SQL_LEASE_ACQUIRE = (
    "UPDATE dataset_versions SET status = 'PROFILING', processing_lease_token = :tok, "
    "processing_lease_expires_at = now() + make_interval(secs => :ttl) "
    "WHERE id = :v AND dataset_id = :d AND tenant_id = :t AND status = 'QUARANTINED' "
    "AND storage_object_key IS NOT NULL RETURNING " + _VERSION_COLS
)
_SQL_LEASE_RECLAIM = (
    "UPDATE dataset_versions SET processing_lease_token = :tok, "
    "processing_lease_expires_at = now() + make_interval(secs => :ttl) "
    "WHERE id = :v AND dataset_id = :d AND tenant_id = :t AND status = 'PROFILING' "
    "AND (processing_lease_token IS NULL OR processing_lease_expires_at < now()) "
    "RETURNING " + _VERSION_COLS
)
_SQL_LEASE_RENEW = (
    "UPDATE dataset_versions SET "
    "processing_lease_expires_at = now() + make_interval(secs => :ttl) "
    "WHERE id = :v AND dataset_id = :d AND tenant_id = :t AND status = 'PROFILING' "
    "AND processing_lease_token = :tok RETURNING id"
)
_SQL_LEASE_REJECT = (
    "UPDATE dataset_versions SET status = 'REJECTED', rejection_code = :code "
    "WHERE id = :v AND dataset_id = :d AND tenant_id = :t AND status = 'PROFILING' "
    "AND processing_lease_token = :tok RETURNING " + _VERSION_COLS
)
_SQL_INSERT_PROFILE = (
    "INSERT INTO dataset_profiles (version_id, tenant_id, dataset_id, contract_version, "
    "content_sha256, row_count, column_count, profile) VALUES "
    "(:v, :t, :d, :cv, :sha, :rows, :cols, CAST(:profile AS jsonb))"
)
_SQL_GET_PROFILE = (
    "SELECT p.contract_version, p.profile, p.created_at FROM dataset_profiles p "
    "JOIN dataset_versions v ON v.id = p.version_id AND v.tenant_id = p.tenant_id "
    "WHERE p.version_id = :v AND p.dataset_id = :d AND p.tenant_id = :t "
    "AND p.profile IS NOT NULL AND v.status <> 'DELETED'"
)
_SQL_LATEST_SEMANTICS = (
    "SELECT id, revision_number, mapping, confirmed_by, confirmed_at "
    "FROM dataset_semantic_revisions WHERE version_id = :v AND dataset_id = :d "
    "AND tenant_id = :t AND mapping IS NOT NULL ORDER BY revision_number DESC LIMIT 1"
)
_SQL_LIST_SEMANTICS = (
    "SELECT id, revision_number, mapping, confirmed_by, confirmed_at "
    "FROM dataset_semantic_revisions WHERE version_id = :v AND dataset_id = :d "
    "AND tenant_id = :t AND mapping IS NOT NULL ORDER BY revision_number"
)
_SQL_NEXT_SEMANTIC_NUMBER = (
    "SELECT coalesce(max(revision_number), 0) + 1 FROM dataset_semantic_revisions "
    "WHERE version_id = :v AND tenant_id = :t"
)
_SQL_INSERT_SEMANTICS = (
    "INSERT INTO dataset_semantic_revisions (id, tenant_id, dataset_id, version_id, "
    "revision_number, mapping, confirmed_by) VALUES "
    "(:id, :t, :d, :v, :n, CAST(:mapping AS jsonb), :by) "
    "RETURNING id, revision_number, mapping, confirmed_by, confirmed_at"
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
    idempotency_key: str | None = None,
) -> VersionRecord:
    """A QUARANTINED version with the next number from the dataset's atomic
    counter (numbers are never reused). With ``idempotency_key`` a retried
    request returns the SAME version: the dataset row is locked first, so two
    concurrent requests with one key serialize and the second finds the first's
    version. Reusing a key for a different file is a conflict."""
    filename = sanitize_filename(original_filename)
    media = validate_media_type(media_type)
    size = validate_declared_size(declared_size_bytes)
    if idempotency_key is not None:
        idempotency_key = validate_idempotency_key(idempotency_key)
        await get_dataset(session, tenant_id, dataset_id, for_update=True)
        existing = (
            await session.execute(
                text(_SQL_VERSION_BY_IDEMPOTENCY),
                {"t": tenant_id, "d": dataset_id, "k": idempotency_key},
            )
        ).first()
        if existing is not None:
            found = _version(existing)
            if (found.original_filename, found.declared_size_bytes) != (filename, size):
                raise DatasetConflict(
                    "the idempotency key was used for a different upload",
                    "IDEMPOTENCY_KEY_REUSED",
                )
            return found
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
    params = {
        "id": version_id,
        "t": tenant_id,
        "d": dataset_id,
        "n": allocated,
        "fn": filename,
        "mt": media,
        "size": size,
        "by": actor.user_id,
    }
    if idempotency_key is None:
        row = (await session.execute(text(_SQL_INSERT_VERSION), params)).one()
    else:
        row = (
            await session.execute(
                text(_SQL_INSERT_VERSION_IDEMPOTENT), {**params, "k": idempotency_key}
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


# PROFILING is entered only by acquire_processing_lease (it needs a lease),
# PROFILED only by publish_profile (it needs the profile row and the lease), and
# a PROFILING version is rejected only by its lease owner (reject_processing).
_INGEST_TARGETS = frozenset({VersionStatus.REJECTED})


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
    """Review rejection only: ``-> REJECTED`` with a constrained code, from a
    version nobody is processing. Processing transitions use the lease functions;
    activation and deletion have their own operations; there is no generic
    "set status"."""
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
    if version.status is VersionStatus.PROFILING or not version_transition_allowed(
        version.status, to
    ):
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
    await _require_confirmed_semantics(session, tenant_id, dataset_id, version_id)
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


# --- ingestion (internal service, admin authority; ADR-030) ---------------------


@dataclass(frozen=True)
class ProfileRecord:
    contract_version: str
    profile: dict[str, Any]
    created_at: datetime


@dataclass(frozen=True)
class SemanticRevisionRecord:
    id: uuid.UUID
    revision_number: int
    mapping: dict[str, Any]
    confirmed_by: uuid.UUID
    confirmed_at: datetime


def _semantics(row: Any) -> SemanticRevisionRecord:
    return SemanticRevisionRecord(**dict(row._mapping))


async def storage_key(
    session: AsyncSession, tenant_id: uuid.UUID, dataset_id: uuid.UUID, version_id: uuid.UUID
) -> str | None:
    """INTERNAL: the version's storage key, for the ingestion module only. Never
    returned by any route."""
    return (
        await session.execute(
            text(_SQL_GET_STORAGE_KEY), {"v": version_id, "d": dataset_id, "t": tenant_id}
        )
    ).scalar()


async def record_content(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    *,
    content_sha256: str,
    storage_object_key: str,
) -> VersionRecord:
    """Set the digest and quarantine key ONCE, while QUARANTINED (compare-and-set;
    the trigger also refuses any later change). Not a state transition: no event."""
    dataset = await get_dataset(session, tenant_id, dataset_id, for_update=True)
    if dataset.status is not DatasetStatus.ACTIVE:
        raise DatasetConflict("the dataset is being deleted", "DATASET_NOT_ACTIVE")
    version = await get_version(session, tenant_id, dataset_id, version_id, for_update=True)
    if version.has_content:
        if version.content_sha256 == content_sha256:
            return version  # an idempotent replay of the same bytes
        raise DatasetConflict("the version already has different content", "CONTENT_CONFLICT")
    if version.status is not VersionStatus.QUARANTINED:
        raise DatasetConflict("the version no longer accepts content", "DATASET_VERSION_CONFLICT")
    row = (
        await session.execute(
            text(_SQL_SET_CONTENT),
            {
                "sha": content_sha256,
                "key": storage_object_key,
                "v": version_id,
                "d": dataset_id,
                "t": tenant_id,
            },
        )
    ).first()
    if row is None:  # pragma: no cover - the row is locked above
        raise DatasetConflict("the version changed concurrently", "DATASET_VERSION_CONFLICT")
    return _version(row)


async def publish_profile(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    actor: Actor,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    *,
    profile_json: str,
    contract_version: str,
    content_sha256: str,
    row_count: int,
    column_count: int,
    published_key: str,
    lease_token: uuid.UUID,
) -> VersionRecord:
    """Record the immutable profile and move ``PROFILING -> PROFILED`` with the
    storage key moved to the ``datasets/`` area, in one transaction (one event).
    Only the CURRENT lease owner can publish (``LEASE_LOST`` otherwise, and the
    profile insert is rolled back). The database refuses PROFILED without this
    profile, without a live lease, and any other key move."""
    dataset = await get_dataset(session, tenant_id, dataset_id, for_update=True)
    if dataset.status is not DatasetStatus.ACTIVE:
        raise DatasetConflict("the dataset is being deleted", "DATASET_NOT_ACTIVE")
    version = await get_version(session, tenant_id, dataset_id, version_id, for_update=True)
    if version.status is not VersionStatus.PROFILING:
        raise DatasetConflict(
            f"cannot move a {version.status.value} version to PROFILED",
            "DATASET_VERSION_INVALID_TRANSITION",
        )
    if version.content_sha256 != content_sha256:
        raise DatasetConflict("the profile does not match the content", "CONTENT_MISMATCH")
    await session.execute(
        text(_SQL_INSERT_PROFILE),
        {
            "v": version_id,
            "t": tenant_id,
            "d": dataset_id,
            "cv": contract_version,
            "sha": content_sha256,
            "rows": row_count,
            "cols": column_count,
            "profile": profile_json,
        },
    )
    row = (
        await session.execute(
            text(_SQL_CAS_PUBLISH),
            {
                "key": published_key,
                "v": version_id,
                "d": dataset_id,
                "t": tenant_id,
                "tok": lease_token,
            },
        )
    ).first()
    if row is None:  # the row is locked above: only a lost lease gets here
        raise DatasetConflict("the processing lease was lost", "LEASE_LOST")
    await _event(
        session,
        tenant_id=tenant_id,
        dataset_id=dataset_id,
        version_id=version_id,
        event_type=EventType.VERSION_PROFILED,
        from_status=VersionStatus.PROFILING.value,
        to_status=VersionStatus.PROFILED.value,
        actor=actor,
    )
    return _version(row)


async def get_profile(
    session: AsyncSession, tenant_id: uuid.UUID, dataset_id: uuid.UUID, version_id: uuid.UUID
) -> ProfileRecord | None:
    """The version's profile (admin/owner only: RLS hides it from members)."""
    row = (
        await session.execute(
            text(_SQL_GET_PROFILE), {"v": version_id, "d": dataset_id, "t": tenant_id}
        )
    ).first()
    if row is None:
        return None
    return ProfileRecord(**dict(row._mapping))


async def list_semantic_revisions(
    session: AsyncSession, tenant_id: uuid.UUID, dataset_id: uuid.UUID, version_id: uuid.UUID
) -> list[SemanticRevisionRecord]:
    rows = await session.execute(
        text(_SQL_LIST_SEMANTICS), {"v": version_id, "d": dataset_id, "t": tenant_id}
    )
    return [_semantics(r) for r in rows]


async def confirm_semantics(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    actor: Actor,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    *,
    mapping_json: str,
) -> SemanticRevisionRecord:
    """Append a semantic revision for a PROFILED version, confirmed by ``actor``
    (RLS binds ``confirmed_by`` to the SIGNED user). The caller validates the
    mapping against the profile (``nlw.datasets.semantics``)."""
    if actor.user_id is None:
        raise DatasetConflict("semantics are confirmed by a person", "SEMANTICS_INVALID")
    await get_dataset(session, tenant_id, dataset_id, for_update=True)
    version = await get_version(session, tenant_id, dataset_id, version_id, for_update=True)
    if version.status is not VersionStatus.PROFILED:
        raise DatasetConflict(
            "semantics are confirmed only for a PROFILED version", "DATASET_VERSION_NOT_ELIGIBLE"
        )
    n = (
        await session.execute(text(_SQL_NEXT_SEMANTIC_NUMBER), {"v": version_id, "t": tenant_id})
    ).scalar()
    row = (
        await session.execute(
            text(_SQL_INSERT_SEMANTICS),
            {
                "id": uuid.uuid4(),
                "t": tenant_id,
                "d": dataset_id,
                "v": version_id,
                "n": n,
                "mapping": mapping_json,
                "by": actor.user_id,
            },
        )
    ).one()
    return _semantics(row)


async def _require_confirmed_semantics(
    session: AsyncSession, tenant_id: uuid.UUID, dataset_id: uuid.UUID, version_id: uuid.UUID
) -> None:
    from nlw.datasets.semantics import SemanticMappingError, validate_mapping

    latest = (
        await session.execute(
            text(_SQL_LATEST_SEMANTICS), {"v": version_id, "d": dataset_id, "t": tenant_id}
        )
    ).first()
    profile = await get_profile(session, tenant_id, dataset_id, version_id)
    if latest is None or profile is None:
        raise DatasetConflict("activation requires confirmed semantics", "SEMANTICS_NOT_CONFIRMED")
    try:
        validate_mapping(_semantics(latest).mapping, profile.profile)
    except SemanticMappingError as exc:
        raise DatasetConflict(
            "the confirmed semantics no longer match the profile", "SEMANTICS_INVALID"
        ) from exc


# --- processing lease (database time; ADR-030) -----------------------------------

LeaseClaim = Literal["acquired", "reclaimed", "busy", "not_claimable"]
MAX_LEASE_TTL_S = 900  # the database refuses a lease ending later than 15 minutes


async def acquire_processing_lease(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    actor: Actor,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    *,
    token: uuid.UUID,
    ttl_s: float,
) -> tuple[LeaseClaim, VersionRecord]:
    """Claim the right to profile a version, atomically, on PostgreSQL's clock:

    - ``acquired``: QUARANTINED-with-content -> PROFILING with our token (one
      event);
    - ``reclaimed``: a PROFILING version whose lease expired (or never had one)
      now carries our token (not a transition: no event);
    - ``busy``: someone else holds a live lease;
    - ``not_claimable``: any other state (nothing to process).

    Each attempt is a single compare-and-set UPDATE, so two concurrent
    claimants can never both succeed."""
    if not 0 < ttl_s <= MAX_LEASE_TTL_S:
        raise ValueError("lease ttl out of range")
    dataset = await get_dataset(session, tenant_id, dataset_id, for_update=True)
    if dataset.status is not DatasetStatus.ACTIVE:
        raise DatasetConflict("the dataset is being deleted", "DATASET_NOT_ACTIVE")
    params = {"tok": token, "ttl": ttl_s, "v": version_id, "d": dataset_id, "t": tenant_id}
    row = (await session.execute(text(_SQL_LEASE_ACQUIRE), params)).first()
    if row is not None:
        await _event(
            session,
            tenant_id=tenant_id,
            dataset_id=dataset_id,
            version_id=version_id,
            event_type=EventType.VERSION_PROFILING_STARTED,
            from_status=VersionStatus.QUARANTINED.value,
            to_status=VersionStatus.PROFILING.value,
            actor=actor,
        )
        return "acquired", _version(row)
    row = (await session.execute(text(_SQL_LEASE_RECLAIM), params)).first()
    if row is not None:
        return "reclaimed", _version(row)
    current = await get_version(session, tenant_id, dataset_id, version_id)
    return ("busy" if current.status is VersionStatus.PROFILING else "not_claimable"), current


async def renew_processing_lease(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    *,
    token: uuid.UUID,
    ttl_s: float,
) -> bool:
    """Extend our lease (database clock). False means ownership was lost: the
    version left PROFILING, or a reclaimer replaced the token."""
    if not 0 < ttl_s <= MAX_LEASE_TTL_S:
        raise ValueError("lease ttl out of range")
    row = (
        await session.execute(
            text(_SQL_LEASE_RENEW),
            {"tok": token, "ttl": ttl_s, "v": version_id, "d": dataset_id, "t": tenant_id},
        )
    ).first()
    return row is not None


async def reject_processing(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    actor: Actor,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
    *,
    token: uuid.UUID,
    rejection_code: RejectionCode,
) -> VersionRecord:
    """PROFILING -> REJECTED by the CURRENT lease owner only (one event)."""
    dataset = await get_dataset(session, tenant_id, dataset_id, for_update=True)
    if dataset.status is not DatasetStatus.ACTIVE:
        raise DatasetConflict("the dataset is being deleted", "DATASET_NOT_ACTIVE")
    row = (
        await session.execute(
            text(_SQL_LEASE_REJECT),
            {
                "code": rejection_code.value,
                "tok": token,
                "v": version_id,
                "d": dataset_id,
                "t": tenant_id,
            },
        )
    ).first()
    if row is None:
        raise DatasetConflict("the processing lease was lost", "LEASE_LOST")
    await _event(
        session,
        tenant_id=tenant_id,
        dataset_id=dataset_id,
        version_id=version_id,
        event_type=EventType.VERSION_REJECTED,
        from_status=VersionStatus.PROFILING.value,
        to_status=VersionStatus.REJECTED.value,
        actor=actor,
        reason_code=rejection_code.value,
    )
    return _version(row)
