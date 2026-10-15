"""Deletion receipts: a provider-neutral contract and a LOCAL FAKE (ADR-030).

When the operator purges a version's stored objects, one receipt per version
is appended to a deletion log that must live OUTSIDE the database, so a
database restore cannot erase the evidence that bytes were deleted. The purge
event in ``dataset_events`` records the receipt's sink, opaque id and
deletion-set digest; the tombstone then VERIFIES the receipt through this
interface and refuses to scrub anything it cannot verify.

Providers (owner decision O-3, ADR-034):

- ``S3DeletionLog`` (``nlw.datasets.deletion_log_s3``): one write-once object per
  receipt in a dedicated S3 Object Lock bucket. It is implemented and tested
  against an in-memory S3 only; **it has NOT RUN against AWS**, and its
  bucket and grants are review templates (``docs/runbooks/
  deletion-receipt-log-provisioning.md``);
- ``LocalFakeDeletionLog``: development and tests only, refused in staging and
  production.

Every provider can be checked BEFORE a purge deletes anything (``preflight``),
looks receipts up by id (``verify``) and lists them (``refs`` / ``read``) for
reconciliation and for re-applying deletions after a database restore.

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
object_ref_sha256    sorted SHA-256 digests of the removed storage items (the
                     key plus, on S3, the object version, delete-marker or
                     upload id); keys and S3 version ids are never exported
deletion_set_sha256  SHA-256 over the canonical binding of tenant, dataset,
                     version, content digest and object references
verified_absent      always ``true`` (written only after verification)
operator             the operator label given to the purge command
deleted_at           UTC ISO-8601 time of the deletion
===================  ==========================================================

Never recorded: names, filenames, labels, cell values, storage paths or keys,
credentials.

Record format ``workspace-offboarding-receipt-1`` (ADR-037), one per offboarded
workspace, in the same log:

=======================  ======================================================
receipt_version          ``"workspace-offboarding-receipt-1"``
receipt_id               opaque id chosen by the sink
sink                     the sink's identifier
environment              ``APP_ENV`` of the offboarding
tenant_id                workspace id
datasets_tombstoned      number of the workspace's datasets, all DELETED
dataset_ids_sha256       SHA-256 over the sorted dataset ids (ids not exported)
table_counts             rows removed per purged table (table name -> count)
offboarding_set_sha256   SHA-256 over the canonical binding of the workspace,
                         its datasets and the table counts
verified_absent          always ``true`` (written only once every purged table
                         holds no row of the workspace)
operator                 the operator label given to the command
offboarded_at            UTC ISO-8601 time
=======================  ======================================================
"""

from __future__ import annotations

import enum
import hashlib
import json
import os
import re
import uuid
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

RECEIPT_VERSION = "deletion-receipt-2"
WORKSPACE_RECEIPT_VERSION = "workspace-offboarding-receipt-1"
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


def dataset_ids_digest(dataset_ids: list[uuid.UUID] | list[str]) -> str:
    return hashlib.sha256(",".join(sorted(str(d) for d in dataset_ids)).encode()).hexdigest()


def offboarding_set_digest(
    *, tenant_id: str, datasets_tombstoned: int, dataset_ids_sha256: str,
    table_counts: dict[str, int],
) -> str:  # fmt: skip
    """The digest a workspace receipt attests: binds the workspace, its
    datasets and the rows removed from each purged table."""
    canonical = json.dumps(
        {
            "tenant_id": tenant_id,
            "datasets_tombstoned": datasets_tombstoned,
            "dataset_ids_sha256": dataset_ids_sha256,
            "table_counts": table_counts,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class WorkspaceReceipt:
    sink: str
    environment: str
    tenant_id: str
    datasets_tombstoned: int
    dataset_ids_sha256: str
    table_counts: dict[str, int]
    offboarding_set_sha256: str
    operator: str
    verified_absent: bool = True
    receipt_version: str = WORKSPACE_RECEIPT_VERSION
    receipt_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    offboarded_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @classmethod
    def for_workspace(
        cls, *, sink: str, environment: str, tenant_id: uuid.UUID,
        dataset_ids: list[uuid.UUID], table_counts: dict[str, int], operator: str,
    ) -> WorkspaceReceipt:  # fmt: skip
        ids = dataset_ids_digest(dataset_ids)
        counts = {k: int(v) for k, v in sorted(table_counts.items())}
        return cls(
            sink=sink,
            environment=environment,
            tenant_id=str(tenant_id),
            datasets_tombstoned=len(dataset_ids),
            dataset_ids_sha256=ids,
            table_counts=counts,
            offboarding_set_sha256=offboarding_set_digest(
                tenant_id=str(tenant_id),
                datasets_tombstoned=len(dataset_ids),
                dataset_ids_sha256=ids,
                table_counts=counts,
            ),  # fmt: skip
            operator=operator,
        )

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True, order=True)
class WorkspaceReceiptRef:
    tenant_id: uuid.UUID
    receipt_id: str


@dataclass(frozen=True)
class ExpectedWorkspaceReceipt:
    """What the database says a workspace's offboarding receipt must attest."""

    sink: str
    receipt_id: str
    tenant_id: uuid.UUID
    offboarding_set_sha256: str
    not_before: datetime  # the offboarding request


def check_workspace_receipt(
    record: dict[str, Any] | None, expected: ExpectedWorkspaceReceipt
) -> ReceiptCheck:
    """Provider-neutral verification of one stored workspace receipt."""
    if record is None:
        return ReceiptCheck.MISSING
    try:
        if (
            record.get("receipt_version") != WORKSPACE_RECEIPT_VERSION
            or record.get("verified_absent") is not True
            or record.get("receipt_id") != expected.receipt_id
        ):
            return ReceiptCheck.MALFORMED
        if record["sink"] != expected.sink:
            return ReceiptCheck.SINK_MISMATCH
        if record["tenant_id"] != str(expected.tenant_id):
            return ReceiptCheck.WORKSPACE_MISMATCH
        counts = record["table_counts"]
        if not isinstance(counts, dict) or not all(
            isinstance(k, str) and type(v) is int and v >= 0 for k, v in counts.items()
        ):
            return ReceiptCheck.MALFORMED
        datasets = record["datasets_tombstoned"]
        if type(datasets) is not int or datasets < 0:
            return ReceiptCheck.MALFORMED
        recomputed = offboarding_set_digest(
            tenant_id=record["tenant_id"], datasets_tombstoned=datasets,
            dataset_ids_sha256=str(record["dataset_ids_sha256"]), table_counts=counts,
        )  # fmt: skip
        if (
            record["offboarding_set_sha256"] != expected.offboarding_set_sha256
            or recomputed != expected.offboarding_set_sha256
        ):
            return ReceiptCheck.DIGEST_MISMATCH
        if datetime.fromisoformat(record["offboarded_at"]) < expected.not_before:
            return ReceiptCheck.STALE
    except (KeyError, TypeError, ValueError):
        return ReceiptCheck.MALFORMED
    return ReceiptCheck.VERIFIED


def workspace_receipt_self_consistent(record: dict[str, Any] | None) -> bool:
    """A listed workspace receipt that attests its own digest (used when there
    is no database expectation, e.g. re-applying after a restore)."""
    if record is None:
        return False
    try:
        expected = ExpectedWorkspaceReceipt(
            sink=str(record["sink"]),
            receipt_id=str(record["receipt_id"]),
            tenant_id=uuid.UUID(str(record["tenant_id"])),
            offboarding_set_sha256=str(record["offboarding_set_sha256"]),
            not_before=datetime.fromisoformat(str(record["offboarded_at"])),
        )
    except (KeyError, TypeError, ValueError):
        return False
    return check_workspace_receipt(record, expected) is ReceiptCheck.VERIFIED


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


@dataclass(frozen=True, order=True)
class ReceiptRef:
    """Where a receipt is filed: its version and its id (ids only)."""

    tenant_id: uuid.UUID
    dataset_id: uuid.UUID
    version_id: uuid.UUID
    receipt_id: str


# Receipt ids are chosen by this code (uuid4) but checked on every read, since
# they become storage keys and database values.
RECEIPT_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")  # always ``fullmatch``


class ReceiptCheck(enum.StrEnum):
    VERIFIED = "VERIFIED"
    MISSING = "MISSING"
    # The sink holds the receipt but no longer protects it (S3: no Object Lock
    # retention, or retention already over).
    NOT_RETAINED = "NOT_RETAINED"
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
    # Objects in the sink that are not receipts, found by the last ``refs``.
    unexpected_objects: int

    def preflight(self) -> None:
        """Raise ``DeletionLogUnavailable`` unless a receipt could be stored and
        protected now. Called before anything is physically deleted."""

    def append(self, receipt: DeletionReceipt) -> str:
        """Durably append the receipt; return its id. Must raise on failure."""

    def verify(self, expected: ExpectedReceipt) -> ReceiptCheck:
        """Look the receipt up in the sink and check it against ``expected``."""

    def refs(self) -> Iterator[ReceiptRef]:
        """Every receipt the sink holds (ids only). Raises ``DeletionLogUnavailable``."""

    def read(self, ref: ReceiptRef) -> dict[str, Any] | None:
        """One receipt's record, or ``None`` if absent. Raises ``DeletionLogUnavailable``."""

    def append_workspace(self, receipt: WorkspaceReceipt) -> str:
        """Durably append a workspace offboarding receipt; return its id."""

    def verify_workspace(self, expected: ExpectedWorkspaceReceipt) -> ReceiptCheck:
        """Look a workspace receipt up and check it against ``expected``."""

    def workspace_refs(self) -> Iterator[WorkspaceReceiptRef]:
        """Every workspace receipt (ids only). Raises ``DeletionLogUnavailable``."""

    def read_workspace(self, ref: WorkspaceReceiptRef) -> dict[str, Any] | None:
        """One workspace receipt, or ``None``. Raises ``DeletionLogUnavailable``."""


_UNCONFIGURED = "no deletion log is configured (the external deletion log is a launch gate)"


class UnconfiguredDeletionLog:
    sink_id = "unconfigured"
    unexpected_objects = 0

    def preflight(self) -> None:
        raise DeletionLogUnavailable(_UNCONFIGURED)

    def append(self, receipt: DeletionReceipt) -> str:
        raise DeletionLogUnavailable(_UNCONFIGURED)

    def verify(self, expected: ExpectedReceipt) -> ReceiptCheck:
        return ReceiptCheck.UNVERIFIABLE

    def refs(self) -> Iterator[ReceiptRef]:
        raise DeletionLogUnavailable(_UNCONFIGURED)

    def read(self, ref: ReceiptRef) -> dict[str, Any] | None:
        raise DeletionLogUnavailable(_UNCONFIGURED)

    def append_workspace(self, receipt: WorkspaceReceipt) -> str:
        raise DeletionLogUnavailable(_UNCONFIGURED)

    def verify_workspace(self, expected: ExpectedWorkspaceReceipt) -> ReceiptCheck:
        return ReceiptCheck.UNVERIFIABLE

    def workspace_refs(self) -> Iterator[WorkspaceReceiptRef]:
        raise DeletionLogUnavailable(_UNCONFIGURED)

    def read_workspace(self, ref: WorkspaceReceiptRef) -> dict[str, Any] | None:
        raise DeletionLogUnavailable(_UNCONFIGURED)


class LocalFakeDeletionLog:
    """Development/test fake: an append-only JSON-lines file. NOT a real
    external deletion log; refused in staging and production."""

    sink_id = LOCAL_FAKE_SINK

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.unexpected_objects = 0

    def preflight(self) -> None:
        directory = self.path.parent
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            raise DeletionLogUnavailable("the local deletion log is not writable") from None
        if not os.access(directory, os.W_OK) or (
            self.path.exists() and not os.access(self.path, os.W_OK)
        ):
            raise DeletionLogUnavailable("the local deletion log is not writable")

    def append(self, receipt: DeletionReceipt | WorkspaceReceipt) -> str:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (receipt.to_json() + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        return receipt.receipt_id

    def read_all(self) -> list[dict[str, Any]]:
        """Every line as a record. Any line that is not a JSON object (including
        one nested too deeply to parse) makes the whole file unreadable
        (``ValueError``): the fake never guesses past a corrupt line."""
        if not self.path.exists():
            return []
        records: list[dict[str, Any]] = []
        for line in self.path.read_text().splitlines():
            if not line:
                continue
            try:
                record = json.loads(line)
            except RecursionError:
                raise ValueError("a deletion log line nests too deeply") from None
            if not isinstance(record, dict):
                raise ValueError("a deletion log line is not an object")
            records.append(record)
        return records

    def verify(self, expected: ExpectedReceipt) -> ReceiptCheck:
        try:
            records = self.read_all()
        except (OSError, ValueError):
            return ReceiptCheck.UNVERIFIABLE
        found = [r for r in records if r.get("receipt_id") == expected.receipt_id]
        return check_receipt(found[-1] if found else None, expected)

    def refs(self) -> Iterator[ReceiptRef]:
        try:
            records = self.read_all()
        except (OSError, ValueError):
            raise DeletionLogUnavailable("the local deletion log is unreadable") from None
        seen: set[ReceiptRef] = set()
        self.unexpected_objects = 0
        for r in records:
            if _workspace_ref_of(r) is not None:
                continue  # a workspace receipt: listed by ``workspace_refs``
            ref = _ref_of(r)
            if ref is None:
                self.unexpected_objects += 1
            elif ref not in seen:
                seen.add(ref)
                yield ref

    def read(self, ref: ReceiptRef) -> dict[str, Any] | None:
        try:
            records = self.read_all()
        except (OSError, ValueError):
            raise DeletionLogUnavailable("the local deletion log is unreadable") from None
        found = [r for r in records if r.get("receipt_id") == ref.receipt_id]
        return found[-1] if found else None

    def append_workspace(self, receipt: WorkspaceReceipt) -> str:
        return self.append(receipt)

    def verify_workspace(self, expected: ExpectedWorkspaceReceipt) -> ReceiptCheck:
        try:
            records = self.read_all()
        except (OSError, ValueError):
            return ReceiptCheck.UNVERIFIABLE
        found = [r for r in records if r.get("receipt_id") == expected.receipt_id]
        return check_workspace_receipt(found[-1] if found else None, expected)

    def workspace_refs(self) -> Iterator[WorkspaceReceiptRef]:
        try:
            records = self.read_all()
        except (OSError, ValueError):
            raise DeletionLogUnavailable("the local deletion log is unreadable") from None
        seen: set[WorkspaceReceiptRef] = set()
        for r in records:
            ref = _workspace_ref_of(r)
            if ref is not None and ref not in seen:
                seen.add(ref)
                yield ref

    def read_workspace(self, ref: WorkspaceReceiptRef) -> dict[str, Any] | None:
        try:
            records = self.read_all()
        except (OSError, ValueError):
            raise DeletionLogUnavailable("the local deletion log is unreadable") from None
        found = [
            r for r in records
            if r.get("receipt_id") == ref.receipt_id and _workspace_ref_of(r) == ref
        ]  # fmt: skip
        return found[-1] if found else None


def _workspace_ref_of(record: dict[str, Any]) -> WorkspaceReceiptRef | None:
    """The workspace receipt a record is, or ``None``."""
    if record.get("receipt_version") != WORKSPACE_RECEIPT_VERSION:
        return None
    try:
        rid = str(record["receipt_id"])
        if not RECEIPT_ID.fullmatch(rid):
            return None
        return WorkspaceReceiptRef(uuid.UUID(str(record["tenant_id"])), rid)
    except (KeyError, TypeError, ValueError):
        return None


def _ref_of(record: dict[str, Any]) -> ReceiptRef | None:
    """The filing reference a record names, or ``None`` if it is malformed."""
    try:
        rid = str(record["receipt_id"])
        if not RECEIPT_ID.fullmatch(rid):
            return None
        return ReceiptRef(
            uuid.UUID(str(record["tenant_id"])),
            uuid.UUID(str(record["dataset_id"])),
            uuid.UUID(str(record["version_id"])),
            rid,
        )
    except (KeyError, TypeError, ValueError):
        return None


def deletion_log_from_settings(kind: str, path: str | None, app_env: str) -> DeletionLog:
    """The configured file-based log (``local``), or none. The local fake is
    refused in staging/production even if a caller bypasses ``Settings``
    validation. ``s3`` needs the operator's credentials, so the operator
    commands build it (``nlw.ops.datasets``); this package never imports
    storage or credential code."""
    if kind == "s3":
        raise DeletionLogUnavailable("the S3 deletion log is built by the operator commands")
    if kind == "local":
        if app_env in _DEPLOYED:
            raise DeletionLogUnavailable("the local fake deletion log is refused when deployed")
        if path:
            return LocalFakeDeletionLog(path)
    return UnconfiguredDeletionLog()
