"""Deletion receipts: a provider-neutral contract and a LOCAL FAKE (ADR-030).

When the operator purges a version's stored objects, one receipt per version
is appended to a deletion log that must live OUTSIDE the database, so a
database restore cannot erase the evidence that bytes were deleted. The purge
event in ``dataset_events`` records the receipt's sink, opaque id and
deletion-set digest; the tombstone then VERIFIES the receipt through this
interface and refuses to scrub anything it cannot verify.

The production provider is an open owner decision (O-3) and a launch gate.
The only implementation here is ``LocalFakeDeletionLog``: development and
tests only, refused in staging and production. **No real external deletion
log exists.**

Record format ``deletion-receipt-2`` (one JSON object per line, sorted keys):

===================  ==========================================================
receipt_version      ``"deletion-receipt-2"``
receipt_id           opaque id chosen by the sink
sink                 the sink's identifier (e.g. ``local-fake``)
environment          ``APP_ENV`` of the purge
tenant_id            workspace id
dataset_id           dataset id
version_id           version id
content_sha256       the version's recorded content digest (or ``null``)
objects_deleted      number of stored files removed (objects and partials)
object_ref_sha256    sorted SHA-256 digests of the removed storage keys (keys
                     are internal and never exported)
deletion_set_sha256  SHA-256 over the canonical binding of tenant, dataset,
                     version, content digest and object references
verified_absent      always ``true`` (written only after verification)
operator             the operator label given to the purge command
deleted_at           UTC ISO-8601 time of the deletion
===================  ==========================================================

Never recorded: names, filenames, labels, cell values, storage paths or keys,
credentials.
"""

from __future__ import annotations

import enum
import hashlib
import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

RECEIPT_VERSION = "deletion-receipt-2"
LOCAL_FAKE_SINK = "local-fake"
_DEPLOYED = ("staging", "production")


class DeletionLogUnavailable(RuntimeError):
    """No usable deletion log: purging (and tombstoning) must not proceed."""


def deletion_set_digest(
    *,
    tenant_id: str,
    dataset_id: str,
    version_id: str,
    content_sha256: str | None,
    object_ref_sha256: list[str],
) -> str:
    """The digest a receipt attests: binds the workspace, dataset, version,
    content digest and the exact set of removed objects."""
    canonical = json.dumps(
        {
            "tenant_id": tenant_id,
            "dataset_id": dataset_id,
            "version_id": version_id,
            "content_sha256": content_sha256,
            "object_ref_sha256": sorted(object_ref_sha256),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class DeletionReceipt:
    sink: str
    environment: str
    tenant_id: str
    dataset_id: str
    version_id: str
    content_sha256: str | None
    objects_deleted: int
    object_ref_sha256: list[str]
    deletion_set_sha256: str
    operator: str
    verified_absent: bool = True
    receipt_version: str = RECEIPT_VERSION
    receipt_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    deleted_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @classmethod
    def for_version(
        cls,
        *,
        sink: str,
        environment: str,
        tenant_id: uuid.UUID,
        dataset_id: uuid.UUID,
        version_id: uuid.UUID,
        content_sha256: str | None,
        deleted_keys: list[str],
        operator: str,
    ) -> DeletionReceipt:
        refs = sorted(hashlib.sha256(k.encode()).hexdigest() for k in deleted_keys)
        return cls(
            sink=sink,
            environment=environment,
            tenant_id=str(tenant_id),
            dataset_id=str(dataset_id),
            version_id=str(version_id),
            content_sha256=content_sha256,
            objects_deleted=len(deleted_keys),
            object_ref_sha256=refs,
            deletion_set_sha256=deletion_set_digest(
                tenant_id=str(tenant_id),
                dataset_id=str(dataset_id),
                version_id=str(version_id),
                content_sha256=content_sha256,
                object_ref_sha256=refs,
            ),
            operator=operator,
        )

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class ExpectedReceipt:
    """What the database says a version's receipt must attest."""

    sink: str
    receipt_id: str
    tenant_id: uuid.UUID
    dataset_id: uuid.UUID
    version_id: uuid.UUID
    content_sha256: str | None
    deletion_set_sha256: str
    not_before: datetime  # the deletion request


class ReceiptCheck(enum.StrEnum):
    VERIFIED = "VERIFIED"
    MISSING = "MISSING"
    SINK_MISMATCH = "SINK_MISMATCH"
    WORKSPACE_MISMATCH = "WORKSPACE_MISMATCH"
    DATASET_MISMATCH = "DATASET_MISMATCH"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    STALE = "STALE"
    MALFORMED = "MALFORMED"
    UNVERIFIABLE = "UNVERIFIABLE"


def check_receipt(record: dict[str, Any] | None, expected: ExpectedReceipt) -> ReceiptCheck:
    """Provider-neutral verification of one stored receipt record."""
    if record is None:
        return ReceiptCheck.MISSING
    try:
        if (
            record.get("receipt_version") != RECEIPT_VERSION
            or record.get("verified_absent") is not True
        ):
            return ReceiptCheck.MALFORMED
        if record["sink"] != expected.sink:
            return ReceiptCheck.SINK_MISMATCH
        if record["tenant_id"] != str(expected.tenant_id):
            return ReceiptCheck.WORKSPACE_MISMATCH
        if record["dataset_id"] != str(expected.dataset_id):
            return ReceiptCheck.DATASET_MISMATCH
        if record["version_id"] != str(expected.version_id):
            return ReceiptCheck.VERSION_MISMATCH
        recomputed = deletion_set_digest(
            tenant_id=record["tenant_id"],
            dataset_id=record["dataset_id"],
            version_id=record["version_id"],
            content_sha256=record["content_sha256"],
            object_ref_sha256=list(record["object_ref_sha256"]),
        )
        if (
            record["content_sha256"] != expected.content_sha256
            or record["deletion_set_sha256"] != expected.deletion_set_sha256
            or recomputed != expected.deletion_set_sha256
        ):
            return ReceiptCheck.DIGEST_MISMATCH
        deleted_at = datetime.fromisoformat(record["deleted_at"])
        if deleted_at < expected.not_before:
            return ReceiptCheck.STALE
    except (KeyError, TypeError, ValueError):
        return ReceiptCheck.MALFORMED
    return ReceiptCheck.VERIFIED


class DeletionLog(Protocol):
    sink_id: str

    def append(self, receipt: DeletionReceipt) -> str:
        """Durably append the receipt; return its id. Must raise on failure."""

    def verify(self, expected: ExpectedReceipt) -> ReceiptCheck:
        """Look the receipt up in the sink and check it against ``expected``."""


class UnconfiguredDeletionLog:
    sink_id = "unconfigured"

    def append(self, receipt: DeletionReceipt) -> str:
        raise DeletionLogUnavailable(
            "no deletion log is configured (the external deletion log is a launch gate)"
        )

    def verify(self, expected: ExpectedReceipt) -> ReceiptCheck:
        return ReceiptCheck.UNVERIFIABLE


class LocalFakeDeletionLog:
    """Development/test fake: an append-only JSON-lines file. NOT a real
    external deletion log; refused in staging and production."""

    sink_id = LOCAL_FAKE_SINK

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def append(self, receipt: DeletionReceipt) -> str:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (receipt.to_json() + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        return receipt.receipt_id

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line]

    def verify(self, expected: ExpectedReceipt) -> ReceiptCheck:
        try:
            records = self.read_all()
        except (OSError, ValueError):
            return ReceiptCheck.UNVERIFIABLE
        found = [r for r in records if r.get("receipt_id") == expected.receipt_id]
        return check_receipt(found[-1] if found else None, expected)


def deletion_log_from_settings(kind: str, path: str | None, app_env: str) -> DeletionLog:
    """The configured log. The local fake is refused in staging/production even
    if a caller bypasses ``Settings`` validation."""
    if kind == "local":
        if app_env in _DEPLOYED:
            raise DeletionLogUnavailable("the local fake deletion log is refused when deployed")
        if path:
            return LocalFakeDeletionLog(path)
    return UnconfiguredDeletionLog()
