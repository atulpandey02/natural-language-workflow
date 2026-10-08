"""Processing requests: the API side of the ingest boundary (ADR-031).

An admin's request to profile a version is recorded as an immutable
``dataset_processing_requests`` row under the admin's signed ``api_request``
context (RLS: admin/owner of the workspace, ``requested_by`` = the signed user).
The database stamps the time, checks the version has stored, unprocessed
content with this digest, and computes the envelope digest; the returned
``WorkEnvelope`` is what goes on the queue. The API never profiles.

The upload API (``nlw.api.routers.dataset_uploads``) records a request in the
same transaction that records the content, and enqueues the envelope only
after commit. The database row, not the queue message, is the work item: a
lost or failed enqueue is re-driven by ``ensure_processing_request`` (an
idempotent retry of the upload, or an explicit re-dispatch) and by the
operator sweep (``python -m nlw.ops.datasets dispatch-pending``). Delivery is
at-least-once; the ingest runtime's lease makes processing idempotent.
"""

from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.datasets import service
from nlw.datasets.envelope import MAX_ENVELOPE_AGE_S, WorkEnvelope
from nlw.datasets.lifecycle import VersionStatus
from nlw.datasets.service import DatasetConflict

_SQL_INSERT = text(
    "INSERT INTO dataset_processing_requests "
    "(id, tenant_id, dataset_id, version_id, content_sha256, requested_by, envelope_sha256) "
    "VALUES (:id, :t, :d, :v, :sha, :by, repeat('0', 64)) "
    "RETURNING (extract(epoch FROM requested_at) * 1000000)::bigint AS requested_at_us, "
    "envelope_sha256"
)


async def record_processing_request(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
) -> WorkEnvelope:
    """Record a request for ``version_id`` and return its work envelope. The
    caller enqueues it AFTER the transaction commits."""
    version = await service.get_version(session, tenant_id, dataset_id, version_id)
    if version.status not in (VersionStatus.QUARANTINED, VersionStatus.PROFILING) or (
        version.content_sha256 is None or not version.has_content
    ):
        raise DatasetConflict(
            "only a version with stored, unprocessed content can be processed",
            "DATASET_VERSION_NOT_PROCESSABLE",
        )
    request_id = uuid.uuid4()
    row = (
        await session.execute(
            _SQL_INSERT,
            {
                "id": request_id,
                "t": tenant_id,
                "d": dataset_id,
                "v": version_id,
                "sha": version.content_sha256,
                "by": user_id,
            },
        )
    ).one()
    return WorkEnvelope(
        request_id=request_id,
        tenant_id=tenant_id,
        dataset_id=dataset_id,
        version_id=version_id,
        content_sha256=version.content_sha256,
        requested_at_us=int(row.requested_at_us),
        envelope_sha256=str(row.envelope_sha256),
    )


# A request is reused only while comfortably fresh for the consumer (which
# refuses envelopes older than MAX_ENVELOPE_AGE_S by the database clock).
REUSE_MAX_AGE_S = MAX_ENVELOPE_AGE_S - 3600

_SQL_LATEST_FRESH = text(
    "SELECT id, content_sha256, envelope_sha256, "
    "(extract(epoch FROM requested_at) * 1000000)::bigint AS requested_at_us "
    "FROM dataset_processing_requests "
    "WHERE tenant_id = :t AND dataset_id = :d AND version_id = :v "
    "AND requested_at > now() - make_interval(secs => :age) "
    "ORDER BY requested_at DESC LIMIT 1"
)


async def ensure_processing_request(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    dataset_id: uuid.UUID,
    version_id: uuid.UUID,
) -> WorkEnvelope | None:
    """The envelope to (re)dispatch for a version awaiting processing, or None
    when there is nothing to process (already settled, deleting, no content).
    Reuses the latest fresh request (re-enqueueing it is harmless: the consumer
    re-verifies it and the lease makes processing idempotent); otherwise
    records a new one. Never processes anything itself."""
    version = await service.get_version(session, tenant_id, dataset_id, version_id)
    if version.status not in (VersionStatus.QUARANTINED, VersionStatus.PROFILING) or (
        version.content_sha256 is None or not version.has_content
    ):
        return None
    row = (
        await session.execute(
            _SQL_LATEST_FRESH,
            {"t": tenant_id, "d": dataset_id, "v": version_id, "age": REUSE_MAX_AGE_S},
        )
    ).first()
    if row is not None and row.content_sha256 == version.content_sha256:
        return WorkEnvelope(
            request_id=row.id,
            tenant_id=tenant_id,
            dataset_id=dataset_id,
            version_id=version_id,
            content_sha256=row.content_sha256,
            requested_at_us=int(row.requested_at_us),
            envelope_sha256=str(row.envelope_sha256),
        )
    return await record_processing_request(session, tenant_id, user_id, dataset_id, version_id)
