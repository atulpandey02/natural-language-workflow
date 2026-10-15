"""A deterministic in-memory S3 for the deletion-receipt log (no network, no AWS).

Models exactly what ``nlw.datasets.deletion_log_s3`` relies on, with the
ADR-034 bucket rules enforced so a client mistake fails the way AWS would:

- Object Lock: a versioned bucket whose DEFAULT retention (mode, days) is
  applied to every new object version; a retained version cannot be deleted;
- the bucket policy (``receipt-bucket-policy``): a ``PutObject`` by anyone but
  the operator role, without ``IfNoneMatch='*'`` or without
  ``ServerSideEncryption='AES256'`` is denied;
  dataset runtime roles (``api``, ``ingest``, ``bootstrap``) are denied
  everything; deletion and retention changes are denied to everyone but the
  audit administrator;
- the operator's grants (``role-operator-receipts``), see ``OPERATOR_GRANTS``;
- conditional creation (412 when a current version exists), SHA-256 checksums
  (verified on put, returned with ``ChecksumMode='ENABLED'``), retention fields
  returned only to a caller allowed ``s3:GetObjectRetention``, and
  ``ListObjectsV2`` pagination.

Test hooks (things AWS would not let the operator do): ``corrupt``,
``expire_retention``, ``set_lock``, ``plant``.
"""

from __future__ import annotations

import base64
import hashlib
import io
import itertools
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

ACCOUNT = "111122223333"
BUCKET = f"nlw-local-deletion-receipts-{ACCOUNT}-us-east-1"

# The operator role's receipt grants, by S3 action (role-operator-receipts in
# docs/runbooks/deletion-receipt-log-provisioning.md; a unit test pins them).
OPERATOR_GRANTS = {
    "s3:PutObject": "receipts/",
    "s3:GetObject": "receipts/",
    "s3:GetObjectVersion": "receipts/",
    "s3:GetObjectRetention": "receipts/",
    "s3:ListBucket": "receipts/",  # s3:prefix condition
    "s3:GetBucketObjectLockConfiguration": "",  # the bucket
}
RUNTIME_ROLES = ("api", "ingest", "bootstrap")
# Principals whose IDENTITY policy allows anything here (an account
# administrator, a broad automation role). The bucket policy still binds them.
BROAD_ROLES = (None, "audit-admin", "account-admin")


def error(code: str, status: int, op: str) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": "fake"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        op,
    )


def b64sha(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


@dataclass
class Stored:
    version_id: str
    data: bytes
    checksum: str
    sse: str
    mode: str | None
    retain_until: datetime | None


class ReceiptBucket:
    def __init__(
        self, *, mode: str | None = "GOVERNANCE", days: int = 30, page_size: int = 1000
    ) -> None:
        self.lock_enabled = mode is not None
        self.mode = mode
        self.days = days
        self.objects: dict[str, list[Stored]] = {}
        self.page_size = page_size
        self._ids = itertools.count(1)

    def client(self, role: str | None = "operator") -> FakeReceiptS3:
        return FakeReceiptS3(self, role)

    # --- test hooks -------------------------------------------------------------
    def corrupt(self, key: str, data: bytes) -> None:
        self.objects[key][-1].data = data  # bytes changed, recorded checksum kept

    def expire_retention(self, key: str) -> None:
        self.objects[key][-1].retain_until = datetime.now(UTC) - timedelta(seconds=1)

    def set_lock(self, mode: str | None, days: int = 30) -> None:
        self.lock_enabled, self.mode, self.days = mode is not None, mode, days

    def plant(self, key: str, data: bytes) -> None:
        """An object written outside this code (e.g. by a misconfigured tool)."""
        self.objects.setdefault(key, []).append(self._stored(data, "AES256"))

    def _stored(self, data: bytes, sse: str) -> Stored:
        until = datetime.now(UTC) + timedelta(days=self.days) if self.lock_enabled else None
        return Stored(f"r{next(self._ids):06d}", data, b64sha(data), sse, self.mode, until)


class FakeReceiptS3:
    def __init__(self, bucket: ReceiptBucket, role: str | None) -> None:
        self.b = bucket
        self.role = role
        self.calls: list[str] = []
        self.denied: list[str] = []

    def _deny(self, op: str) -> ClientError:
        self.denied.append(op)
        return error("AccessDenied", 403, op)

    def _authorize(self, op: str, action: str, *, key: str = "", prefix: str | None = None) -> None:
        self.calls.append(op)
        if self.role in RUNTIME_ROLES:
            raise self._deny(op)  # bucket policy: DenyDatasetRuntimeRoles
        if self.role in BROAD_ROLES:
            return
        assert self.role == "operator", self.role
        scope = OPERATOR_GRANTS.get(action)
        if scope is None:
            raise self._deny(op)
        target = prefix if prefix is not None else key
        if scope and not str(target).startswith(scope):
            raise self._deny(op)

    def _can_read_retention(self) -> bool:
        return self.role in BROAD_ROLES or "s3:GetObjectRetention" in OPERATOR_GRANTS

    def _bucket(self, kw: dict[str, Any], op: str) -> None:
        if kw.get("Bucket") != BUCKET:
            raise error("NoSuchBucket", 404, op)

    # --- API ----------------------------------------------------------------------

    def get_object_lock_configuration(self, **kw: Any) -> dict[str, Any]:
        self._authorize("get_object_lock_configuration", "s3:GetBucketObjectLockConfiguration")
        self._bucket(kw, "GetObjectLockConfiguration")
        if not self.b.lock_enabled:
            raise error("ObjectLockConfigurationNotFoundError", 404, "GetObjectLockConfiguration")
        return {
            "ObjectLockConfiguration": {
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": self.b.mode, "Days": self.b.days}},
            }
        }

    def put_object(self, **kw: Any) -> dict[str, Any]:
        key = kw["Key"]
        self._authorize("put_object", "s3:PutObject", key=key)
        self._bucket(kw, "PutObject")
        if self.role != "operator":
            raise self._deny("put_object")  # bucket policy: DenyReceiptWritesExceptOperator
        if kw.get("IfNoneMatch") != "*" or kw.get("ServerSideEncryption") != "AES256":
            raise self._deny("put_object")  # bucket policy
        body = kw["Body"]
        data = body if isinstance(body, bytes) else body.read()
        if kw.get("ChecksumSHA256") and kw["ChecksumSHA256"] != b64sha(data):
            raise error("BadDigest", 400, "PutObject")
        if self.b.objects.get(key):
            raise error("PreconditionFailed", 412, "PutObject")
        stored = self.b._stored(data, "AES256")
        self.b.objects.setdefault(key, []).append(stored)
        return {"VersionId": stored.version_id, "ChecksumSHA256": stored.checksum}

    def _find(self, kw: dict[str, Any], op: str) -> Stored:
        versions = self.b.objects.get(kw["Key"]) or []
        if "VersionId" in kw:
            versions = [v for v in versions if v.version_id == kw["VersionId"]]
        if not versions:
            raise error("NoSuchKey", 404, op)
        return versions[-1]

    def _meta(self, s: Stored, kw: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {"ContentLength": len(s.data), "VersionId": s.version_id}
        if kw.get("ChecksumMode") == "ENABLED":
            out["ChecksumSHA256"] = s.checksum
        if self._can_read_retention() and s.mode is not None:
            out["ObjectLockMode"] = s.mode
            out["ObjectLockRetainUntilDate"] = s.retain_until
        return out

    def head_object(self, **kw: Any) -> dict[str, Any]:
        action = "s3:GetObjectVersion" if "VersionId" in kw else "s3:GetObject"
        self._authorize("head_object", action, key=kw["Key"])
        self._bucket(kw, "HeadObject")
        return self._meta(self._find(kw, "HeadObject"), kw)

    def get_object(self, **kw: Any) -> dict[str, Any]:
        action = "s3:GetObjectVersion" if "VersionId" in kw else "s3:GetObject"
        self._authorize("get_object", action, key=kw["Key"])
        self._bucket(kw, "GetObject")
        s = self._find(kw, "GetObject")
        return {**self._meta(s, kw), "Body": io.BytesIO(s.data)}

    def list_objects_v2(self, **kw: Any) -> dict[str, Any]:
        prefix = kw.get("Prefix", "")
        self._authorize("list_objects_v2", "s3:ListBucket", prefix=prefix or "\0")
        self._bucket(kw, "ListObjectsV2")
        keys = sorted(k for k in self.b.objects if k.startswith(prefix))
        start = int(kw.get("ContinuationToken") or 0)
        size = min(int(kw.get("MaxKeys", 1000)), self.b.page_size)
        page = keys[start : start + size]
        out: dict[str, Any] = {
            "Prefix": prefix,
            "Contents": [{"Key": k} for k in page],
            "IsTruncated": start + size < len(keys),
        }
        if out["IsTruncated"]:
            out["NextContinuationToken"] = str(start + size)
        return out

    def delete_object(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("delete_object")
        if self.role != "audit-admin":
            raise self._deny("delete_object")  # not granted + bucket policy
        s = self._find(kw, "DeleteObject")
        if s.retain_until is not None and s.retain_until > datetime.now(UTC):
            raise error("AccessDenied", 403, "DeleteObject")  # Object Lock
        self.b.objects[kw["Key"]].remove(s)
        return {}


# --- IAM (ConfirmOwnRolePath in role-operator-receipts) ---------------------------------

# The operator may call iam:GetRole on exactly its own path-/ role ARN.
IAM_GRANTS = {"iam:GetRole": "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator"}


class FakeIAM:
    """``get_role`` as IAM evaluates ``ConfirmOwnRolePath``: the grant names the
    path-/ ARN, so a role created at another path is AccessDenied."""

    def __init__(self, *, env: str = "local", path: str = "/", account: str = ACCOUNT) -> None:
        self.env, self.path, self.account = env, path, account
        self.calls: list[str] = []

    def get_role(self, **kw: Any) -> dict[str, Any]:
        self.calls.append("get_role")
        name = kw["RoleName"]
        arn = f"arn:aws:iam::{self.account}:role{self.path}{name}"
        granted = (
            IAM_GRANTS["iam:GetRole"].replace("<ACCOUNT>", self.account).replace("<ENV>", self.env)
        )
        if arn != granted:
            raise error("AccessDenied", 403, "GetRole")
        return {"Role": {"RoleName": name, "Path": self.path, "Arn": arn}}
