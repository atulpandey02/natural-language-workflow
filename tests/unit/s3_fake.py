"""A deterministic in-memory S3 for the dataset store tests (no network, no AWS).

Models exactly what ``nlw.storage.s3`` relies on, with the ADR-033 bucket
policy enforced so a client mistake fails the way AWS would:

- a VERSIONED bucket: every put adds a version; ``DeleteObject`` without a
  version id adds a delete marker; with a version id it removes that version;
- conditional creation (``IfNoneMatch='*'``): 412 ``PreconditionFailed`` when a
  current version exists; an injectable one-off 409 ``ConditionalRequestConflict``;
- the bucket policy's denies (403 ``AccessDenied``): a creation request without
  ``ServerSideEncryption='aws:kms'`` and the exact environment key, or (for
  ``PutObject``/``CompleteMultipartUpload``) without ``IfNoneMatch``;
- SHA-256 checksums: whole-object for a single put (verified against the body),
  per part plus COMPOSITE (SHA-256 of the concatenated part digests, ``-N``)
  for a multipart upload;
- ``GetObjectAttributes`` (size, checksum, part count), listing with pagination.

Every call is recorded in ``calls`` (operation names), per client view, so a
test can prove which operations the API, the ingest runtime and the operator
use.
"""

from __future__ import annotations

import base64
import hashlib
import io
import itertools
from dataclasses import dataclass, field
from typing import Any

from botocore.exceptions import ClientError

ACCOUNT = "111122223333"
KEY_ARN = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/11111111-2222-3333-4444-555555555555"
OTHER_KEY_ARN = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/99999999-8888-7777-6666-555555555555"
BUCKET = f"nlw-local-datasets-{ACCOUNT}-us-east-1"


def error(code: str, status: int, op: str) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": "fake"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        op,
    )


def b64(digest: bytes) -> str:
    return base64.b64encode(digest).decode()


@dataclass
class Version:
    version_id: str
    data: bytes | None  # None: a delete marker
    checksum: str = ""
    checksum_type: str = "FULL_OBJECT"
    parts: int | None = None
    sse: str = ""
    kms: str = ""


@dataclass
class Upload:
    key: str
    sse: str
    kms: str
    parts: dict[int, tuple[bytes, str]] = field(default_factory=dict)


class FakeBucket:
    """The shared bucket state. Use ``client()`` for a recording view."""

    def __init__(self, *, kms_key_arn: str = KEY_ARN, page_size: int = 1000) -> None:
        self.kms = kms_key_arn
        self.objects: dict[str, list[Version]] = {}
        self.uploads: dict[str, Upload] = {}
        self._ids = itertools.count(1)
        self.page_size = page_size
        self.conflict_next: list[str] = []  # ops that answer 409 once
        self.tamper_response: dict[str, Any] = {}  # fields overridden in write responses

    def client(self) -> FakeS3:
        return FakeS3(self)

    def current(self, key: str) -> Version | None:
        versions = self.objects.get(key) or []
        if not versions or versions[-1].data is None:
            return None
        return versions[-1]

    def next_id(self) -> str:
        return f"v{next(self._ids):06d}"


class FakeS3:
    """A recording client view over a ``FakeBucket`` (boto3 S3 client API)."""

    def __init__(self, bucket: FakeBucket) -> None:
        self.b = bucket
        self.calls: list[str] = []

    # --- policy -----------------------------------------------------------------
    def _encryption_policy(self, op: str, kw: dict[str, Any]) -> None:
        if kw.get("ServerSideEncryption") != "aws:kms":
            raise error("AccessDenied", 403, op)  # DenyMissing/WrongSseAlgorithm
        if kw.get("SSEKMSKeyId") != self.b.kms:
            raise error("AccessDenied", 403, op)  # DenyMissing/WrongSseKmsKey

    def _conflict(self, op: str) -> None:
        if op in self.b.conflict_next:
            self.b.conflict_next.remove(op)
            raise error("ConditionalRequestConflict", 409, op)

    def _respond(self, out: dict[str, Any]) -> dict[str, Any]:
        return {**out, **self.b.tamper_response}

    # --- writes -----------------------------------------------------------------
    def put_object(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("put_object")
        self._encryption_policy("PutObject", kw)
        if kw.get("IfNoneMatch") != "*":
            raise error("AccessDenied", 403, "PutObject")  # DenyUnconditionalCreate
        self._conflict("put_object")
        key, body = kw["Key"], bytes(kw["Body"])
        if kw.get("ChecksumSHA256") and kw["ChecksumSHA256"] != b64(hashlib.sha256(body).digest()):
            raise error("BadDigest", 400, "PutObject")
        if self.b.current(key) is not None:
            raise error("PreconditionFailed", 412, "PutObject")
        checksum = b64(hashlib.sha256(body).digest())
        v = Version(self.b.next_id(), body, checksum, "FULL_OBJECT", None, "aws:kms", self.b.kms)
        self.b.objects.setdefault(key, []).append(v)
        return self._respond({"ETag": '"e"', "ChecksumSHA256": checksum, "ChecksumType":
                              "FULL_OBJECT", "ServerSideEncryption": "aws:kms",
                              "SSEKMSKeyId": self.b.kms, "BucketKeyEnabled": True,
                              "VersionId": v.version_id})  # fmt: skip

    def create_multipart_upload(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("create_multipart_upload")
        self._encryption_policy("CreateMultipartUpload", kw)
        upload_id = f"u{next(self.b._ids):06d}"
        self.b.uploads[upload_id] = Upload(kw["Key"], "aws:kms", kw["SSEKMSKeyId"])
        return {"UploadId": upload_id}

    def upload_part(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("upload_part")
        up = self.b.uploads.get(kw["UploadId"])
        if up is None or up.key != kw["Key"]:
            raise error("NoSuchUpload", 404, "UploadPart")
        body = bytes(kw["Body"])
        checksum = b64(hashlib.sha256(body).digest())
        if kw.get("ChecksumSHA256") not in (None, checksum):
            raise error("BadDigest", 400, "UploadPart")
        up.parts[int(kw["PartNumber"])] = (body, checksum)
        return {"ETag": f'"p{kw["PartNumber"]}"', "ChecksumSHA256": checksum}

    def complete_multipart_upload(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("complete_multipart_upload")
        if kw.get("IfNoneMatch") != "*":
            raise error("AccessDenied", 403, "CompleteMultipartUpload")
        self._conflict("complete_multipart_upload")
        up = self.b.uploads.get(kw["UploadId"])
        if up is None:
            raise error("NoSuchUpload", 404, "CompleteMultipartUpload")
        if self.b.current(up.key) is not None:
            raise error("PreconditionFailed", 412, "CompleteMultipartUpload")
        listed = kw["MultipartUpload"]["Parts"]
        numbers = [p["PartNumber"] for p in listed]
        if numbers != sorted(up.parts) or any(
            p.get("ChecksumSHA256") != up.parts[p["PartNumber"]][1] for p in listed
        ):
            raise error("InvalidPart", 400, "CompleteMultipartUpload")
        data = b"".join(up.parts[n][0] for n in numbers)
        digests = b"".join(base64.b64decode(up.parts[n][1]) for n in numbers)
        checksum = f"{b64(hashlib.sha256(digests).digest())}-{len(numbers)}"
        v = Version(self.b.next_id(), data, checksum, "COMPOSITE", len(numbers), up.sse, up.kms)
        self.b.objects.setdefault(up.key, []).append(v)
        del self.b.uploads[kw["UploadId"]]
        return self._respond({"ETag": '"m"', "ChecksumSHA256": checksum, "ChecksumType":
                              "COMPOSITE", "ServerSideEncryption": up.sse, "SSEKMSKeyId": up.kms,
                              "BucketKeyEnabled": True, "VersionId": v.version_id})  # fmt: skip

    def abort_multipart_upload(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("abort_multipart_upload")
        self.b.uploads.pop(kw["UploadId"], None)
        return {}

    # --- reads ------------------------------------------------------------------
    def get_object(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("get_object")
        v = self.b.current(kw["Key"])
        if v is None or v.data is None:
            raise error("NoSuchKey", 404, "GetObject")
        return {"Body": io.BytesIO(v.data), "ContentLength": len(v.data)}

    def head_object(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("head_object")
        v = self.b.current(kw["Key"])
        if v is None or v.data is None:
            raise error("404", 404, "HeadObject")
        return {"ContentLength": len(v.data)}

    def get_object_attributes(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("get_object_attributes")
        v = self.b.current(kw["Key"])
        if v is None or v.data is None:
            raise error("NoSuchKey", 404, "GetObjectAttributes")
        out: dict[str, Any] = {
            "ObjectSize": len(v.data),
            # AWS reports a composite checksum WITHOUT the part-count suffix here.
            "Checksum": {
                "ChecksumSHA256": v.checksum.split("-")[0],
                "ChecksumType": v.checksum_type,
            },  # fmt: skip
        }
        if v.parts:
            out["ObjectParts"] = {"TotalPartsCount": v.parts}
        return out

    # --- operator ---------------------------------------------------------------
    def list_object_versions(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("list_object_versions")
        prefix = kw.get("Prefix", "")
        rows = [
            (key, v)
            for key in sorted(self.b.objects)
            if key.startswith(prefix)
            for v in self.b.objects[key]
        ]
        start = 0
        if "KeyMarker" in kw:
            marker = (kw["KeyMarker"], kw["VersionIdMarker"])
            start = next(i for i, (k, v) in enumerate(rows) if (k, v.version_id) == marker) + 1
        page, rest = rows[start : start + self.b.page_size], rows[start + self.b.page_size :]
        out: dict[str, Any] = {
            "Versions": [
                {"Key": k, "VersionId": v.version_id} for k, v in page if v.data is not None
            ],
            "DeleteMarkers": [
                {"Key": k, "VersionId": v.version_id} for k, v in page if v.data is None
            ],
            "IsTruncated": bool(rest),
        }
        if rest:
            out["NextKeyMarker"], out["NextVersionIdMarker"] = page[-1][0], page[-1][1].version_id
        return out

    def list_multipart_uploads(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("list_multipart_uploads")
        prefix = kw.get("Prefix", "")
        return {
            "Uploads": [
                {"Key": u.key, "UploadId": uid}
                for uid, u in sorted(self.b.uploads.items())
                if u.key.startswith(prefix)
            ],
            "IsTruncated": False,
        }

    def delete_object(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("delete_object")
        key, vid = kw["Key"], kw.get("VersionId")
        versions = self.b.objects.get(key, [])
        if vid is None:  # an unversioned delete only hides the object
            versions.append(Version(self.b.next_id(), None))
            self.b.objects[key] = versions
            return {"DeleteMarker": True}
        self.b.objects[key] = [v for v in versions if v.version_id != vid]
        if not self.b.objects[key]:
            del self.b.objects[key]
        return {"VersionId": vid}
