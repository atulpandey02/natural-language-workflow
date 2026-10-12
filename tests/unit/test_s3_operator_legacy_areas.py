"""The operator's purge and verification on S3 never ask S3 about the legacy
areas (D6 blocker found during review finding F5).

The operator role may list object versions only under ``versions/*``
(``ListVersionsBounded``). The legacy ``quarantine/`` and ``datasets/`` areas
are local development data from before ADR-033: nothing writes them to S3, so
``S3BlobStore`` answers them as empty WITHOUT a request instead of being
denied. Every prefix is also listed before anything is removed, so a listing
failure can never follow a deletion. The fake applies the operator role's IAM
grants (``FakeBucket.client(role="operator")``). No network, no AWS."""

from __future__ import annotations

import importlib.util
import io
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

import nlw.storage.s3 as s3mod
from nlw.storage.blob import (
    AREAS,
    LEGACY_AREAS,
    BlobKeyError,
    BlobUnavailable,
    TenantScopedBlobStore,
)
from nlw.storage.s3 import S3BlobStore

_spec = importlib.util.spec_from_file_location("s3_fake", Path(__file__).with_name("s3_fake.py"))
assert _spec and _spec.loader
fake = sys.modules.get("s3_fake") or importlib.util.module_from_spec(_spec)
if "s3_fake" not in sys.modules:
    sys.modules["s3_fake"] = fake
    _spec.loader.exec_module(fake)

PART = 5 * 1024 * 1024


def _stores() -> tuple[Any, Any, S3BlobStore, S3BlobStore]:
    """(bucket, operator client, API-side writer store, operator store)."""
    bucket = fake.FakeBucket()
    writer = S3BlobStore(bucket.client(), bucket=fake.BUCKET, kms_key_arn=fake.KEY_ARN,
                         part_size=PART)  # fmt: skip
    op_client = bucket.client(role="operator")
    operator = S3BlobStore(op_client, bucket=fake.BUCKET, kms_key_arn=fake.KEY_ARN,
                           part_size=PART)  # fmt: skip
    return bucket, op_client, writer, operator


def _version(writer: S3BlobStore, tenant: uuid.UUID) -> tuple[uuid.UUID, uuid.UUID, str]:
    d, v = uuid.uuid4(), uuid.uuid4()
    key = TenantScopedBlobStore(writer, tenant).object_key(d, v)
    writer.put_stream(key, io.BytesIO(b"a,b\n1,2\n"), max_bytes=100)
    return d, v, key


def test_the_fake_operator_role_is_denied_listing_outside_versions() -> None:
    """The fake really enforces ``ListVersionsBounded``: the bug this file
    guards against reproduces against it."""
    _, client, _, _ = _stores()
    for prefix in ("quarantine/", "datasets/x/", ""):
        with pytest.raises(Exception, match="AccessDenied"):
            client.list_object_versions(Bucket=fake.BUCKET, Prefix=prefix)
    client.list_object_versions(Bucket=fake.BUCKET, Prefix="versions/")
    client.list_multipart_uploads(Bucket=fake.BUCKET, Prefix="quarantine/")  # bucket-wide


def test_a_version_purge_with_the_operator_role_succeeds_and_verifies() -> None:
    bucket, client, writer, operator = _stores()
    tenant = uuid.uuid4()
    d, v, key = _version(writer, tenant)
    left = writer._s3.create_multipart_upload(
        Bucket=fake.BUCKET, Key=key, ServerSideEncryption="aws:kms", SSEKMSKeyId=fake.KEY_ARN
    )["UploadId"]
    scoped = TenantScopedBlobStore(operator, tenant)
    removed, verified = scoped.delete_version_and_verify(d, v)
    assert verified and len(removed) == 2 and any(r.endswith(f"#u={left}") for r in removed)
    assert key not in bucket.objects and not bucket.uploads
    assert client.denied == []
    assert scoped.delete_version_and_verify(d, v) == ([], True)  # idempotent


def test_a_dataset_purge_with_the_operator_role_succeeds_and_verifies() -> None:
    bucket, client, writer, operator = _stores()
    tenant = uuid.uuid4()
    d, _, _ = _version(writer, tenant)
    scoped = TenantScopedBlobStore(operator, tenant)
    assert scoped.delete_dataset_and_verify(d)
    assert not bucket.objects and client.denied == []


def test_every_area_listing_works_with_the_operator_role_and_legacy_areas_cost_no_request() -> None:
    """``verify-objects`` lists every area. ``versions`` used to fail before
    any request (``versions/`` is not a key); legacy areas used to be denied."""
    _, client, writer, operator = _stores()
    _, _, key = _version(writer, uuid.uuid4())
    items = {area: list(operator.list_area(area)) for area in AREAS}
    assert [i.partition("#")[0] for i in items["versions"]] == [key]
    assert all(items[a] == [] for a in LEGACY_AREAS)
    assert client.denied == []
    assert client.calls == ["list_object_versions", "list_multipart_uploads"]  # versions only


@pytest.mark.parametrize("area", LEGACY_AREAS)
def test_legacy_keys_are_never_sent_to_s3(area: str) -> None:
    _, client, _, operator = _stores()
    t, d, v = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    key = f"{area}/{t}/{d}/{v}"
    assert operator.exists(key) is False  # verify-objects: reported missing, not an error
    assert list(operator.list_prefix(key)) == [] and operator.purge_prefix(key) == []
    assert list(operator.list_prefix(f"{area}/{t}/{d}/")) == []
    for op in (operator.open, operator.attributes, operator.digest):
        with pytest.raises(BlobKeyError):
            op(key)
    with pytest.raises(BlobKeyError):
        operator.put_stream(key, io.BytesIO(b"x"), max_bytes=1)
    assert client.calls == []


@pytest.mark.parametrize(
    "prefix",
    ["quarantine/../x/", "datasets//x", "quarantine/X/", "other/", "versions", "quarantine", ""],
)
def test_malformed_listing_prefixes_are_still_refused(prefix: str) -> None:
    _, client, _, operator = _stores()
    with pytest.raises(BlobKeyError):
        list(operator.list_prefix(prefix))
    assert client.calls == []


def test_a_listing_failure_never_follows_a_deletion(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every prefix is listed before anything is removed: if a later listing
    fails, the object is still there (no bytes gone without a receipt)."""
    bucket, client, writer, operator = _stores()
    tenant = uuid.uuid4()
    d, v, key = _version(writer, tenant)
    monkeypatch.setattr(S3BlobStore, "_in_s3", lambda self, prefix: True)  # ask S3 anyway
    scoped = TenantScopedBlobStore(operator, tenant)
    for purge in (lambda: scoped.delete_version_and_verify(d, v),
                  lambda: scoped.delete_dataset_and_verify(d)):  # fmt: skip
        with pytest.raises(BlobUnavailable):
            purge()
        assert bucket.current(key) is not None
        assert "delete_object" not in client.calls and "abort_multipart_upload" not in client.calls
    assert set(client.denied) == {"list_object_versions"}


def test_negative_control_asking_s3_about_legacy_areas_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without ``_in_s3`` answering legacy areas locally, the operator purge
    is denied: the D6 blocker this change removes."""
    monkeypatch.setattr(S3BlobStore, "_in_s3", lambda self, prefix: True)
    with pytest.raises(BlobUnavailable):
        test_a_version_purge_with_the_operator_role_succeeds_and_verifies()


def test_the_store_module_names_no_other_area_check() -> None:
    src = Path(s3mod.__file__).read_text()
    assert src.count("def _in_s3(") == 1 and "if not self._in_s3(prefix):" in src
