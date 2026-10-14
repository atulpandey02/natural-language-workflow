"""The external deletion log on S3 Object Lock (owner decision O-3, ADR-034).

One immutable object per receipt in a DEDICATED bucket
(``nlw-<env>-deletion-receipts-<account>-us-east-1``), separate from the
dataset bucket, the audit bucket and the database backups:

    receipts/<workspace>/<dataset>/<version>/<receipt_id>.json

- ``append`` writes the canonical ``deletion-receipt-2`` JSON exactly once:
  ``If-None-Match: *`` (never over an existing receipt), a SHA-256 checksum S3
  verifies, and SSE-S3. It then reads the stored version back and requires the
  bucket's default Object Lock retention to be on it; anything else fails the
  purge (the receipt object, if written, stays for review);
- ``preflight`` confirms the bucket has Object Lock with a default retention
  BEFORE the purge deletes anything;
- ``verify`` fetches the receipt by the ids the database expects (never by id
  alone), requires an intact checksum and live retention, then applies the
  provider-neutral ``check_receipt``;
- ``refs`` / ``read`` list and read receipts for reconciliation and for
  re-applying deletions after a database restore.

The operator role writes and reads receipts; nothing in this code deletes,
overwrites or changes the retention of one, and the bucket policy denies those
to every principal except the audit administrator (who still cannot shorten
COMPLIANCE retention). Errors never carry the bucket, a key or a credential.

NOT RUN against AWS: tested with an in-memory S3 (``tests/unit/receipt_s3_fake.py``).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any, Protocol

from nlw.datasets.deletion_log import (
    RECEIPT_ID,
    DeletionLogUnavailable,
    DeletionReceipt,
    ExpectedReceipt,
    ReceiptCheck,
    ReceiptRef,
    check_receipt,
)

PREFIX = "receipts/"
MAX_RECEIPT_BYTES = 64 * 1024
# A receipt is a flat object holding one list: anything nested deeper is not a
# receipt, and is refused BEFORE parsing (a deeply nested document would
# otherwise exhaust the parser's recursion limit).
MAX_JSON_DEPTH = 4
RETENTION_MODES = frozenset({"GOVERNANCE", "COMPLIANCE"})
# Listing bound: far above any pilot volume; reaching it refuses the listing.
_PAGE = 1000
_MAX_PAGES = 1000
BUCKET = re.compile(
    r"^nlw-(?P<env>local|dev|staging|production)-deletion-receipts-(?P<account>\d{12})"
    r"-us-east-1(?:-[a-z0-9]{1,16})?$"
)
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_KEY = re.compile(
    rf"receipts/(?P<t>{_UUID})/(?P<d>{_UUID})/(?P<v>{_UUID})/(?P<r>[A-Za-z0-9._:-]{{1,128}})\.json"
)


_NOT_ASKED = "the deletion log listing is not what was asked for"


class ReceiptUnreadable(DeletionLogUnavailable):
    """A receipt exists but cannot be trusted (``check`` says why)."""

    def __init__(self, check: ReceiptCheck) -> None:
        super().__init__(f"the receipt is {check.value}")
        self.check = check


class S3ReceiptClient(Protocol):
    """The subset of the boto3 S3 client this log uses (keyword arguments)."""

    def get_object_lock_configuration(self, **kw: Any) -> dict[str, Any]: ...
    def put_object(self, **kw: Any) -> dict[str, Any]: ...
    def head_object(self, **kw: Any) -> dict[str, Any]: ...
    def get_object(self, **kw: Any) -> dict[str, Any]: ...
    def list_objects_v2(self, **kw: Any) -> dict[str, Any]: ...


def sink_for(bucket: str) -> str:
    """The sink id recorded with every purge event: binds receipts to THIS bucket."""
    if BUCKET.fullmatch(bucket) is None:
        raise DeletionLogUnavailable(
            "the deletion log bucket must be nlw-<env>-deletion-receipts-<account>-us-east-1"
        )
    sink = f"s3.{bucket}"
    if len(sink) > 64:
        raise DeletionLogUnavailable("the deletion log bucket name is too long for a sink id")
    return sink


def receipt_key(ref: ReceiptRef) -> str:
    if not RECEIPT_ID.fullmatch(ref.receipt_id):
        raise DeletionLogUnavailable("malformed receipt id")
    return f"{PREFIX}{ref.tenant_id}/{ref.dataset_id}/{ref.version_id}/{ref.receipt_id}.json"


def _code(exc: BaseException) -> tuple[str, int]:
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return "", 0
    err = response.get("Error") or {}
    meta = response.get("ResponseMetadata") or {}
    try:
        status = int(meta.get("HTTPStatusCode") or 0)
    except (TypeError, ValueError):
        status = 0
    return str(err.get("Code") or ""), status


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def json_depth_within(body: bytes, limit: int = MAX_JSON_DEPTH) -> bool:
    """Whether the JSON text's array/object nesting stays within ``limit``
    (brackets inside strings are ignored). Linear, no recursion."""
    depth = 0
    in_string = escaped = False
    for byte in body:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # quote
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):  # [ {
            depth += 1
            if depth > limit:
                return False
        elif byte in (0x5D, 0x7D):  # ] }
            depth -= 1
    return True


def parse_receipt(body: bytes) -> dict[str, Any] | None:
    """The receipt object, or ``None`` for anything that is not one: oversized,
    too deeply nested, not JSON, or not an object. Never raises."""
    if len(body) > MAX_RECEIPT_BYTES or not json_depth_within(body):
        return None
    try:
        record = json.loads(body)
    except (ValueError, RecursionError):
        return None
    return record if isinstance(record, dict) else None


def _retained(response: dict[str, Any], now: datetime) -> bool:
    until = response.get("ObjectLockRetainUntilDate")
    return (
        response.get("ObjectLockMode") in RETENTION_MODES
        and isinstance(until, datetime)
        and until.tzinfo is not None
        and until > now
    )


class S3DeletionLog:
    def __init__(self, client: S3ReceiptClient, bucket: str) -> None:
        self.sink_id = sink_for(bucket)
        self._s3 = client
        self._bucket = bucket
        # Objects under receipts/ that are not receipts (reported, never read).
        self.unexpected_objects = 0

    # --- before deleting anything -------------------------------------------------

    def preflight(self) -> None:
        try:
            cfg = self._s3.get_object_lock_configuration(Bucket=self._bucket)[
                "ObjectLockConfiguration"
            ]
            retention = cfg["Rule"]["DefaultRetention"]
            ok = (
                cfg.get("ObjectLockEnabled") == "Enabled"
                and retention.get("Mode") in RETENTION_MODES
                and (int(retention.get("Days") or 0) > 0 or int(retention.get("Years") or 0) > 0)
            )
        except (KeyError, TypeError, ValueError):
            ok = False
        except Exception as exc:
            code, _ = _code(exc)
            raise DeletionLogUnavailable(
                "the deletion log's Object Lock could not be confirmed "
                f"({code or type(exc).__name__})"
            ) from None
        if not ok:
            raise DeletionLogUnavailable(
                "the deletion log bucket has no Object Lock default retention"
            )

    # --- write once -----------------------------------------------------------------

    def append(self, receipt: DeletionReceipt) -> str:
        ref = ReceiptRef(
            uuid.UUID(receipt.tenant_id),
            uuid.UUID(receipt.dataset_id),
            uuid.UUID(receipt.version_id),
            receipt.receipt_id,
        )
        if receipt.sink != self.sink_id:
            raise DeletionLogUnavailable("the receipt names another sink")
        key = receipt_key(ref)
        body = receipt.to_json().encode()
        checksum = _sha256_b64(body)
        try:
            put = self._s3.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=body,
                ContentType="application/json",
                ChecksumSHA256=checksum,
                IfNoneMatch="*",
                ServerSideEncryption="AES256",
            )
            version = put.get("VersionId")
            if not version or put.get("ChecksumSHA256") != checksum:
                raise DeletionLogUnavailable("the deletion log did not confirm the receipt")
            head = self._s3.head_object(
                Bucket=self._bucket, Key=key, VersionId=version, ChecksumMode="ENABLED"
            )
        except DeletionLogUnavailable:
            raise
        except Exception as exc:
            code, status = _code(exc)
            if code == "PreconditionFailed" or status == 412:
                raise DeletionLogUnavailable("a receipt with this id already exists") from None
            raise DeletionLogUnavailable(
                f"the receipt could not be written ({code or type(exc).__name__})"
            ) from None
        if head.get("ChecksumSHA256") != checksum or head.get("ContentLength") != len(body):
            raise DeletionLogUnavailable("the stored receipt does not match what was written")
        if not _retained(head, datetime.now(UTC)):
            raise DeletionLogUnavailable("the receipt was stored without Object Lock retention")
        return receipt.receipt_id

    # --- read -----------------------------------------------------------------------

    def _fetch(self, ref: ReceiptRef) -> tuple[dict[str, Any] | None, ReceiptCheck]:
        try:
            key = receipt_key(ref)
        except DeletionLogUnavailable:
            return None, ReceiptCheck.MALFORMED
        try:
            got = self._s3.get_object(Bucket=self._bucket, Key=key, ChecksumMode="ENABLED")
            body = got["Body"].read(MAX_RECEIPT_BYTES + 1)
        except Exception as exc:
            code, status = _code(exc)
            if code in ("NoSuchKey", "NotFound") or status == 404:
                return None, ReceiptCheck.MISSING
            return None, ReceiptCheck.UNVERIFIABLE
        if len(body) > MAX_RECEIPT_BYTES or got.get("ChecksumSHA256") != _sha256_b64(body):
            return None, ReceiptCheck.MALFORMED
        if not _retained(got, datetime.now(UTC)):
            return None, ReceiptCheck.NOT_RETAINED
        record = parse_receipt(body)
        if record is None or record.get("receipt_id") != ref.receipt_id:
            return None, ReceiptCheck.MALFORMED
        return record, ReceiptCheck.VERIFIED

    def verify(self, expected: ExpectedReceipt) -> ReceiptCheck:
        if expected.sink != self.sink_id:
            return ReceiptCheck.SINK_MISMATCH
        record, status = self._fetch(
            ReceiptRef(
                expected.tenant_id, expected.dataset_id, expected.version_id, expected.receipt_id
            )
        )
        if record is None:
            return status
        return check_receipt(record, expected)

    def read(self, ref: ReceiptRef) -> dict[str, Any] | None:
        record, status = self._fetch(ref)
        if status is ReceiptCheck.MISSING:
            return None
        if record is None:
            raise ReceiptUnreadable(status)
        return record

    def refs(self) -> Iterator[ReceiptRef]:
        """Every receipt, listed in full or not at all: a listing that is not
        exactly what was asked for (prefix echo, encoding, a key outside
        ``receipts/``, a truncated page without a token, a repeated token, or
        more than ``_MAX_PAGES`` pages) raises before the caller acts on it.
        Objects under ``receipts/`` that are not receipts are counted in
        ``unexpected_objects`` and never read."""
        token: str | None = None
        seen_tokens: set[str] = set()
        self.unexpected_objects = 0
        for _ in range(_MAX_PAGES):
            kw: dict[str, Any] = {"Bucket": self._bucket, "Prefix": PREFIX, "MaxKeys": _PAGE}
            if token:
                kw["ContinuationToken"] = token
            try:
                page = self._s3.list_objects_v2(**kw)
            except Exception as exc:
                code, _ = _code(exc)
                raise DeletionLogUnavailable(
                    f"the deletion log could not be listed ({code or type(exc).__name__})"
                ) from None
            if page.get("Prefix") != PREFIX or page.get("EncodingType"):
                raise DeletionLogUnavailable(_NOT_ASKED)
            for item in page.get("Contents") or []:
                key = str(item.get("Key", ""))
                if not key.startswith(PREFIX):
                    raise DeletionLogUnavailable(_NOT_ASKED)
                m = _KEY.fullmatch(key)
                if m is None:
                    self.unexpected_objects += 1
                    continue
                yield ReceiptRef(uuid.UUID(m["t"]), uuid.UUID(m["d"]), uuid.UUID(m["v"]), m["r"])
            if not page.get("IsTruncated"):
                return
            token = page.get("NextContinuationToken")
            if not token:
                raise DeletionLogUnavailable("the deletion log listing is truncated")
            if token in seen_tokens:
                raise DeletionLogUnavailable("the deletion log listing does not advance")
            seen_tokens.add(token)
        raise DeletionLogUnavailable("the deletion log listing exceeds its bound")
