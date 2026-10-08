"""Processing requests: the API side of the ingest boundary (ADR-031).

An admin's request to profile a version is recorded as an immutable
``dataset_processing_requests`` row under the admin's signed ``api_request``
context (RLS: admin/owner of the workspace, ``requested_by`` = the signed user).
The database stamps the time, checks the version has stored, unprocessed
content with this digest, and computes the envelope digest; the returned
``WorkEnvelope`` is what goes on the queue. The API never profiles.

No route calls this yet: uploads stay disabled (owner decision O-6).
"""

from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from nlw.datasets import service
from nlw.datasets.envelope import WorkEnvelope
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
