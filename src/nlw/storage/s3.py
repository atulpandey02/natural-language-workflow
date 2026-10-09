"""AWS S3 dataset object store (ADR-033, owner decision O-2).

One immutable object per dataset version (``versions/<ws>/<d>/<v>/source.csv``),
created exactly once and never modified, copied or moved by runtime code.

Writes (the upload API):

- every creation request names ``ServerSideEncryption=aws:kms``, the exact
  configured KMS key ARN and ``BucketKeyEnabled`` (the bucket policy denies any
  request that does not), and carries ``If-None-Match: *``;
- objects up to ``PART_SIZE`` are ONE ``PutObject`` with the whole-file
  ``ChecksumSHA256`` (verified by S3); larger ones are a multipart upload with
  a ``ChecksumSHA256`` per part and a locally computed COMPOSITE checksum
  compared with S3's at completion (S3 offers SHA-256 only as a composite for
  multipart uploads). The whole-file SHA-256 is always computed here while
  streaming; it is what the database records;
- the byte cap is enforced while reading, the expected size is checked BEFORE
  the object is finalized (a mismatch aborts; nothing is created), and every
  failure path aborts the multipart upload;
- the response must report ``aws:kms`` with the configured key and the
  expected checksum; anything else is refused (the object, if any, is left
  for the operator's ``verify-objects``: runtime code never deletes);
- ``412`` (the key exists) and, after one retry, ``409`` (a concurrent
  conditional write) raise ``BlobExistsError`` with this writer's size,
  SHA-256 and fingerprint, so the caller can compare with ``attributes``.

Reads: the ingest runtime only ``open``s (``GetObject``); the API only uses
``attributes`` (``GetObjectAttributes``, metadata, never content). The
operator alone lists versions and purges (``ListObjectVersions``,
``ListMultipartUploads``, ``DeleteObject`` with a ``VersionId``,
``AbortMultipartUpload``).

Nothing here logs or returns a bucket, key, ARN, request id or credential:
failures surface as ``BlobUnavailable`` with author-controlled messages.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable, Iterator
from typing import Any, BinaryIO, Protocol

import structlog

from nlw.storage.blob import (
    AREAS,
    LOCAL_FINGERPRINT,
    BlobExistsError,
    BlobKeyError,
    BlobSizeMismatch,
    BlobTooLargeError,
    BlobUnavailable,
    validate_key,
)

log = structlog.get_logger(__name__)

PART_SIZE = 8 * 1024 * 1024
_READ = 1 << 20
COMPOSITE_FINGERPRINT = "sha256-composite:"


class S3Client(Protocol):
    """The subset of the boto3 S3 client this store uses (keyword arguments)."""

    def put_object(self, **kw: Any) -> dict[str, Any]: ...
    def create_multipart_upload(self, **kw: Any) -> dict[str, Any]: ...
    def upload_part(self, **kw: Any) -> dict[str, Any]: ...
    def complete_multipart_upload(self, **kw: Any) -> dict[str, Any]: ...
    def abort_multipart_upload(self, **kw: Any) -> dict[str, Any]: ...
    def get_object(self, **kw: Any) -> dict[str, Any]: ...
    def head_object(self, **kw: Any) -> dict[str, Any]: ...
    def get_object_attributes(self, **kw: Any) -> dict[str, Any]: ...
    def list_object_versions(self, **kw: Any) -> dict[str, Any]: ...
    def list_multipart_uploads(self, **kw: Any) -> dict[str, Any]: ...
    def delete_object(self, **kw: Any) -> dict[str, Any]: ...


def _error_code(exc: BaseException) -> tuple[str, int]:
    """(code, http status) of a botocore ``ClientError``-shaped exception."""
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return "", 0
    err = response.get("Error") or {}
    meta = response.get("ResponseMetadata") or {}
    try:
        status = int(meta.get("HTTPStatusCode") or err.get("Code") or 0)
    except (TypeError, ValueError):
        status = 0
    return str(err.get("Code") or ""), status


def _is(exc: BaseException, *codes: str, status: int | None = None) -> bool:
    code, http = _error_code(exc)
    return code in codes or (status is not None and http == status)


def _b64(digest: bytes) -> str:
    return base64.b64encode(digest).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.split("-", 1)[0], validate=True)


def composite_fingerprint(part_digests: list[bytes]) -> str:
    """The S3 COMPOSITE SHA-256 of a multipart upload: SHA-256 over the
    concatenated part digests, with the part count."""
    return (
        f"{COMPOSITE_FINGERPRINT}{hashlib.sha256(b''.join(part_digests)).hexdigest()}"
        f"-{len(part_digests)}"
    )


def single_fingerprint(sha256_hex: str) -> str:
    """A single-request object's fingerprint IS its whole-file SHA-256 (the
    same form the local store uses)."""
    return LOCAL_FINGERPRINT + sha256_hex


class _Body:
    """A read-only stream over ``GetObject``'s body that refuses to return more
    than ``limit`` bytes (a truncation guard; the profiler re-hashes)."""

    def __init__(self, body: Any, limit: int | None) -> None:
        self._body = body
        self._limit = limit
        self._read = 0

    def read(self, n: int = -1) -> bytes:
        try:
            chunk = bytes(self._body.read(n if n >= 0 else None))
        except Exception as exc:  # network trouble mid-stream
            raise BlobUnavailable(f"object stream failed ({type(exc).__name__})") from None
        self._read += len(chunk)
        if self._limit is not None and self._read > self._limit:
            raise BlobTooLargeError("object exceeds the byte cap")
        return chunk

    def close(self) -> None:
        close = getattr(self._body, "close", None)
        if callable(close):
            close()

    def __enter__(self) -> _Body:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class S3BlobStore:
    """``BlobStore`` on one S3 bucket (ADR-033). ``client`` is a boto3 S3
    client built by ``nlw.storage.s3_credentials`` (pinned credentials)."""

    def __init__(
        self,
        client: S3Client,
        *,
        bucket: str,
        kms_key_arn: str,
        prefix: str = "versions",
        part_size: int = PART_SIZE,
        read_limit: int | None = None,
    ) -> None:
        if part_size < 5 * 1024 * 1024:
            raise ValueError("S3 multipart parts are at least 5 MiB")
        if prefix != "versions":
            raise ValueError("the dataset object prefix is 'versions' (ADR-033 D4)")
        self._s3 = client
        self._bucket = bucket
        self._kms = kms_key_arn
        self._part = part_size
        self._read_limit = read_limit

    # --- helpers ---------------------------------------------------------------
    def _key(self, key: str) -> str:
        validate_key(key.removesuffix("/"))
        if key.split("/", 1)[0] not in AREAS:
            raise BlobKeyError("unknown storage area")
        return key

    def _call(self, op: str, fn: Callable[..., dict[str, Any]], **kw: Any) -> dict[str, Any]:
        try:
            return fn(Bucket=self._bucket, **kw)
        except (BlobExistsError, FileNotFoundError):
            raise
        except Exception as exc:
            code, status = _error_code(exc)
            if code in ("NoSuchKey", "NotFound", "NoSuchVersion") or status == 404:
                raise FileNotFoundError(f"{op}: no such object") from None
            log.warning("dataset.s3_call_failed", op=op, error_class=type(exc).__name__,
                        error_code=code or None)  # fmt: skip
            raise BlobUnavailable(f"{op} failed") from None

    def _encryption(self) -> dict[str, Any]:
        return {
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": self._kms,
            "BucketKeyEnabled": True,
        }

    def _check_stored(self, response: dict[str, Any], checksum: str) -> None:
        if (
            response.get("ServerSideEncryption") != "aws:kms"
            or response.get("SSEKMSKeyId") != self._kms
        ):
            raise BlobUnavailable("the stored object is not encrypted with the configured key")
        got = str(response.get("ChecksumSHA256") or "")
        if got.split("-", 1)[0] != checksum.split("-", 1)[0]:
            raise BlobUnavailable("the stored object's checksum does not match")

    def _read_part(self, stream: BinaryIO, *, total: int, max_bytes: int) -> bytes:
        """Up to one part, enforcing the cap while reading (never buffering more
        than one part plus one read)."""
        buf = bytearray()
        while len(buf) < self._part:
            chunk = stream.read(min(_READ, self._part - len(buf)))
            if not chunk:
                break
            buf += chunk
            if total + len(buf) > max_bytes:
                raise BlobTooLargeError("stream exceeds the byte cap")
        return bytes(buf)

    # --- BlobStore ---------------------------------------------------------------
    def put_stream(
        self, key: str, stream: BinaryIO, *, max_bytes: int, expected_size: int | None = None
    ) -> tuple[int, str]:
        key = self._key(key)
        whole = hashlib.sha256()
        first = self._read_part(stream, total=0, max_bytes=max_bytes)
        whole.update(first)
        second = self._read_part(stream, total=len(first), max_bytes=max_bytes)
        if not second:
            if expected_size is not None and len(first) != expected_size:
                raise BlobSizeMismatch("the stream is not the expected size", size=len(first))
            return self._put_single(key, first, whole.hexdigest())
        return self._put_multipart(key, stream, first, second, whole, max_bytes, expected_size)

    def _put_single(self, key: str, data: bytes, sha: str) -> tuple[int, str]:
        checksum = _b64(bytes.fromhex(sha))
        for attempt in (1, 2):
            try:
                response = self._s3.put_object(
                    Bucket=self._bucket,
                    Key=key,
                    Body=data,
                    ContentLength=len(data),
                    ContentType="text/csv",
                    ChecksumSHA256=checksum,
                    IfNoneMatch="*",
                    **self._encryption(),
                )
                break
            except Exception as exc:
                if _is(exc, "ConditionalRequestConflict", status=409) and attempt == 1:
                    continue  # a concurrent conditional write: retry once
                if _is(exc, "PreconditionFailed", "ConditionalRequestConflict", status=412) or (
                    _is(exc, status=409)
                ):
                    raise BlobExistsError(
                        "an object already exists at this key",
                        size=len(data),
                        sha256=sha,
                        fingerprint=single_fingerprint(sha),
                    ) from None
                log.warning("dataset.s3_call_failed", op="put_object",
                            error_class=type(exc).__name__)  # fmt: skip
                raise BlobUnavailable("put_object failed") from None
        self._check_stored(response, checksum)
        return len(data), sha

    def _put_multipart(
        self,
        key: str,
        stream: BinaryIO,
        first: bytes,
        second: bytes,
        whole: Any,
        max_bytes: int,
        expected_size: int | None,
    ) -> tuple[int, str]:
        created = self._call(
            "create_multipart_upload",
            self._s3.create_multipart_upload,
            Key=key,
            ContentType="text/csv",
            ChecksumAlgorithm="SHA256",
            **self._encryption(),
        )
        upload_id = str(created["UploadId"])
        completed = False
        try:
            parts: list[dict[str, Any]] = []
            digests: list[bytes] = []
            size = 0
            data = first
            pending = second
            while data:
                number = len(parts) + 1
                digest = hashlib.sha256(data).digest()
                response = self._call(
                    "upload_part",
                    self._s3.upload_part,
                    Key=key,
                    UploadId=upload_id,
                    PartNumber=number,
                    Body=data,
                    ContentLength=len(data),
                    ChecksumAlgorithm="SHA256",
                    ChecksumSHA256=_b64(digest),
                )
                if response.get("ChecksumSHA256") not in (None, _b64(digest)):
                    raise BlobUnavailable("a part's checksum does not match")
                parts.append(
                    {"PartNumber": number, "ETag": response["ETag"], "ChecksumSHA256": _b64(digest)}
                )
                digests.append(digest)
                size += len(data)
                if pending:
                    whole.update(pending)
                data, pending = pending, b""
                if data and not pending:
                    pending = self._read_part(stream, total=size + len(data), max_bytes=max_bytes)
            if expected_size is not None and size != expected_size:
                raise BlobSizeMismatch("the stream is not the expected size", size=size)
            sha = whole.hexdigest()
            fingerprint = composite_fingerprint(digests)
            expected_checksum = _b64(hashlib.sha256(b"".join(digests)).digest())
            response = self._complete(key, upload_id, parts, size, sha, fingerprint)
            completed = True
            self._check_stored(response, expected_checksum)
            return size, sha
        finally:
            if not completed:
                self._abort(key, upload_id)

    def _complete(
        self,
        key: str,
        upload_id: str,
        parts: list[dict[str, Any]],
        size: int,
        sha: str,
        fingerprint: str,
    ) -> dict[str, Any]:
        for attempt in (1, 2):
            try:
                return self._s3.complete_multipart_upload(
                    Bucket=self._bucket,
                    Key=key,
                    UploadId=upload_id,
                    MultipartUpload={"Parts": parts},
                    IfNoneMatch="*",
                )
            except Exception as exc:
                if _is(exc, "ConditionalRequestConflict", status=409) and attempt == 1:
                    continue  # a concurrent conditional write: retry once
                if _is(exc, "PreconditionFailed", "ConditionalRequestConflict", status=412) or (
                    _is(exc, "ConditionalRequestConflict", status=409)
                ):
                    raise BlobExistsError(
                        "an object already exists at this key",
                        size=size,
                        sha256=sha,
                        fingerprint=fingerprint,
                    ) from None
                log.warning("dataset.s3_call_failed", op="complete_multipart_upload",
                            error_class=type(exc).__name__)  # fmt: skip
                raise BlobUnavailable("complete_multipart_upload failed") from None
        raise AssertionError("unreachable")  # pragma: no cover

    def _abort(self, key: str, upload_id: str) -> None:
        try:
            self._s3.abort_multipart_upload(Bucket=self._bucket, Key=key, UploadId=upload_id)
        except Exception as exc:  # the lifecycle rule removes it eventually
            log.warning("dataset.s3_abort_failed", error_class=type(exc).__name__)

    def open(self, key: str) -> BinaryIO:
        response = self._call("get_object", self._s3.get_object, Key=self._key(key))
        return _Body(response["Body"], self._read_limit)  # type: ignore[return-value]

    def digest(self, key: str) -> tuple[int, str]:
        h = hashlib.sha256()
        size = 0
        with self.open(key) as body:
            while chunk := body.read(_READ):
                size += len(chunk)
                h.update(chunk)
        return size, h.hexdigest()

    def attributes(self, key: str) -> tuple[int, str]:
        response = self._call(
            "get_object_attributes",
            self._s3.get_object_attributes,
            Key=self._key(key),
            ObjectAttributes=["ObjectSize", "Checksum", "ObjectParts"],
        )
        size = int(response["ObjectSize"])
        checksum = (response.get("Checksum") or {}).get("ChecksumSHA256")
        if not checksum:
            raise BlobUnavailable("the object carries no SHA-256 checksum")
        digest = _unb64(str(checksum)).hex()
        kind = (response.get("Checksum") or {}).get("ChecksumType")
        parts = (response.get("ObjectParts") or {}).get("TotalPartsCount")
        if kind == "COMPOSITE" or "-" in str(checksum) or parts:
            count = parts or int(str(checksum).rsplit("-", 1)[1])
            return size, f"{COMPOSITE_FINGERPRINT}{digest}-{int(count)}"
        return size, single_fingerprint(digest)

    def exists(self, key: str) -> bool:
        try:
            self._call("head_object", self._s3.head_object, Key=self._key(key))
        except FileNotFoundError:
            return False
        return True

    def list_prefix(self, prefix: str) -> Iterator[str]:
        """OPERATOR: every version, delete marker and in-progress upload."""
        self._key(prefix)
        kw: dict[str, Any] = {"Prefix": prefix}
        while True:
            page = self._call("list_object_versions", self._s3.list_object_versions, **kw)
            for v in page.get("Versions") or []:
                yield f"{v['Key']}#v={v['VersionId']}"
            for m in page.get("DeleteMarkers") or []:
                yield f"{m['Key']}#m={m['VersionId']}"
            if not page.get("IsTruncated"):
                break
            kw = {
                "Prefix": prefix,
                "KeyMarker": page["NextKeyMarker"],
                "VersionIdMarker": page["NextVersionIdMarker"],
            }
        kw = {"Prefix": prefix}
        while True:
            page = self._call("list_multipart_uploads", self._s3.list_multipart_uploads, **kw)
            for u in page.get("Uploads") or []:
                yield f"{u['Key']}#u={u['UploadId']}"
            if not page.get("IsTruncated"):
                break
            kw = {
                "Prefix": prefix,
                "KeyMarker": page["NextKeyMarker"],
                "UploadIdMarker": page["NextUploadIdMarker"],
            }

    def purge_prefix(self, prefix: str) -> list[str]:
        """OPERATOR: abort every upload, delete every version and delete marker
        (``DeleteObject`` WITH a ``VersionId``: physical removal)."""
        removed: list[str] = []
        for item in list(self.list_prefix(prefix)):
            key, _, ref = item.partition("#")
            kind, _, ident = ref.partition("=")
            if kind == "u":
                self._call(
                    "abort_multipart_upload", self._s3.abort_multipart_upload,
                    Key=key, UploadId=ident,
                )  # fmt: skip
            else:
                self._call("delete_object", self._s3.delete_object, Key=key, VersionId=ident)
            removed.append(item)
        return removed

    def list_area(self, area: str) -> Iterator[str]:
        if area not in AREAS:
            raise BlobKeyError("unknown storage area")
        return self.list_prefix(f"{area}/")
