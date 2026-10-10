"""The S3 dataset store (ADR-033) against a deterministic fake and botocore's
Stubber. No network, no AWS."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import sys
import uuid
from pathlib import Path
from typing import Any

import boto3
import pytest
import structlog
from botocore.config import Config
from botocore.stub import Stubber

from nlw.storage.blob import (
    BlobExistsError,
    BlobSizeMismatch,
    BlobTooLargeError,
    BlobUnavailable,
    TenantScopedBlobStore,
)
from nlw.storage.s3 import PART_SIZE, S3BlobStore, composite_fingerprint

_spec = importlib.util.spec_from_file_location("s3_fake", Path(__file__).with_name("s3_fake.py"))
assert _spec and _spec.loader
fake = importlib.util.module_from_spec(_spec)
sys.modules["s3_fake"] = fake
_spec.loader.exec_module(fake)

MiB = 1024 * 1024
PART = 5 * MiB  # the S3 minimum; small parts keep the tests fast


def _store(bucket: Any | None = None, **kw: Any) -> tuple[S3BlobStore, Any, Any]:
    b = bucket or fake.FakeBucket()
    client = b.client()
    store = S3BlobStore(client, bucket=fake.BUCKET, kms_key_arn=fake.KEY_ARN, part_size=PART, **kw)
    return store, client, b


def _data(n: int, seed: int = 1) -> bytes:
    block = hashlib.sha256(str(seed).encode()).digest()
    return (block * (n // len(block) + 1))[:n]


# --- single-request uploads --------------------------------------------------------------


def test_a_small_file_is_one_conditional_encrypted_put_with_its_whole_sha256() -> None:
    store, client, bucket = _store()
    key = f"versions/{uuid.uuid4()}/{uuid.uuid4()}/{uuid.uuid4()}/source.csv"
    data = b"region,amount\nnorth,1\n"
    size, sha = store.put_stream(key, io.BytesIO(data), max_bytes=100, expected_size=len(data))
    assert (size, sha) == (len(data), hashlib.sha256(data).hexdigest())
    assert client.calls == ["put_object"]
    v = bucket.current(key)
    assert v.data == data and (v.sse, v.kms) == ("aws:kms", fake.KEY_ARN)
    assert store.attributes(key) == (len(data), "sha256:" + sha)


def test_the_put_request_shape_is_exact() -> None:
    """Stubber validates against the real S3 model and the exact parameters."""
    s3 = boto3.client("s3", region_name="us-east-1", aws_access_key_id="x",
                      aws_secret_access_key="y", aws_session_token="z",
                      config=Config(retries={"max_attempts": 0}))  # fmt: skip
    data = b"a,b\n1,2\n"
    checksum = base64.b64encode(hashlib.sha256(data).digest()).decode()
    key = f"versions/{uuid.uuid4()}/{uuid.uuid4()}/{uuid.uuid4()}/source.csv"
    with Stubber(s3) as stub:
        stub.add_response(
            "put_object",
            {
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": fake.KEY_ARN,
                "ChecksumSHA256": checksum,
            },  # fmt: skip
            {
                "Bucket": fake.BUCKET,
                "Key": key,
                "Body": data,
                "ContentLength": len(data),
                "ContentType": "text/csv",
                "ChecksumSHA256": checksum,
                "IfNoneMatch": "*",
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": fake.KEY_ARN,
                "BucketKeyEnabled": True,
            },  # fmt: skip
        )
        store = S3BlobStore(s3, bucket=fake.BUCKET, kms_key_arn=fake.KEY_ARN)
        store.put_stream(key, io.BytesIO(data), max_bytes=100)
        stub.assert_no_pending_responses()


# --- multipart uploads -------------------------------------------------------------------


def test_a_large_file_is_a_conditional_multipart_upload_with_a_composite_checksum() -> None:
    store, client, bucket = _store()
    key = f"versions/{uuid.uuid4()}/{uuid.uuid4()}/{uuid.uuid4()}/source.csv"
    data = _data(2 * PART + 123)
    size, sha = store.put_stream(
        key, io.BytesIO(data), max_bytes=len(data), expected_size=len(data)
    )
    assert (size, sha) == (len(data), hashlib.sha256(data).hexdigest())  # whole-file SHA-256
    assert client.calls == ["create_multipart_upload", *["upload_part"] * 3,
                            "complete_multipart_upload"]  # fmt: skip
    parts = [data[i : i + PART] for i in range(0, len(data), PART)]
    expected = composite_fingerprint([hashlib.sha256(p).digest() for p in parts])
    assert store.attributes(key) == (len(data), expected)
    assert bucket.current(key).data == data and not bucket.uploads


def test_the_multipart_request_shapes_are_exact() -> None:
    s3 = boto3.client("s3", region_name="us-east-1", aws_access_key_id="x",
                      aws_secret_access_key="y", aws_session_token="z")  # fmt: skip
    data = _data(PART + 10)
    parts = [data[:PART], data[PART:]]
    digests = [hashlib.sha256(p).digest() for p in parts]
    b64 = [base64.b64encode(d).decode() for d in digests]
    composite = base64.b64encode(hashlib.sha256(b"".join(digests)).digest()).decode() + "-2"
    key = f"versions/{uuid.uuid4()}/{uuid.uuid4()}/{uuid.uuid4()}/source.csv"
    with Stubber(s3) as stub:
        stub.add_response(
            "create_multipart_upload", {"UploadId": "u1"},
            {"Bucket": fake.BUCKET, "Key": key, "ContentType": "text/csv",
             "ChecksumAlgorithm": "SHA256", "ServerSideEncryption": "aws:kms",
             "SSEKMSKeyId": fake.KEY_ARN, "BucketKeyEnabled": True},
        )  # fmt: skip
        for n, (part, c) in enumerate(zip(parts, b64, strict=True), start=1):
            stub.add_response(
                "upload_part", {"ETag": f'"p{n}"', "ChecksumSHA256": c},
                {"Bucket": fake.BUCKET, "Key": key, "UploadId": "u1", "PartNumber": n,
                 "Body": part, "ContentLength": len(part), "ChecksumAlgorithm": "SHA256",
                 "ChecksumSHA256": c},
            )  # fmt: skip
        stub.add_response(
            "complete_multipart_upload",
            {"ChecksumSHA256": composite, "ServerSideEncryption": "aws:kms",
             "SSEKMSKeyId": fake.KEY_ARN},
            {"Bucket": fake.BUCKET, "Key": key, "UploadId": "u1", "IfNoneMatch": "*",
             "MultipartUpload": {"Parts": [
                 {"PartNumber": n, "ETag": f'"p{n}"', "ChecksumSHA256": c}
                 for n, c in enumerate(b64, start=1)]}},
        )  # fmt: skip
        store = S3BlobStore(s3, bucket=fake.BUCKET, kms_key_arn=fake.KEY_ARN, part_size=PART)
        store.put_stream(key, io.BytesIO(data), max_bytes=len(data))
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("size", [PART + 1, 3 * PART])
def test_exceeding_the_cap_or_the_expected_size_aborts_and_stores_nothing(size: int) -> None:
    store, client, bucket = _store()
    key = f"versions/{uuid.uuid4()}/{uuid.uuid4()}/{uuid.uuid4()}/source.csv"
    with pytest.raises(BlobTooLargeError):
        store.put_stream(key, io.BytesIO(_data(size)), max_bytes=size - 1)
    with pytest.raises(BlobSizeMismatch):
        store.put_stream(key, io.BytesIO(_data(size)), max_bytes=size, expected_size=size + 5)
    assert not bucket.objects and not bucket.uploads  # nothing created, every upload aborted
    assert "complete_multipart_upload" not in client.calls


def test_a_small_file_over_the_cap_or_short_is_never_put() -> None:
    store, client, bucket = _store()
    key = f"versions/{uuid.uuid4()}/{uuid.uuid4()}/{uuid.uuid4()}/source.csv"
    with pytest.raises(BlobTooLargeError):
        store.put_stream(key, io.BytesIO(b"x" * 11), max_bytes=10)
    with pytest.raises(BlobSizeMismatch):
        store.put_stream(key, io.BytesIO(b"x" * 9), max_bytes=10, expected_size=10)
    assert client.calls == [] and not bucket.objects


def test_a_failure_mid_upload_aborts_the_multipart_upload() -> None:
    store, client, bucket = _store()
    key = f"versions/{uuid.uuid4()}/{uuid.uuid4()}/{uuid.uuid4()}/source.csv"

    class Broken(io.BytesIO):
        def read(self, n: int | None = -1) -> bytes:
            if self.tell() >= 2 * PART + MiB:  # after the upload was created
                raise ConnectionResetError("client went away")
            return super().read(n)

    with pytest.raises(ConnectionResetError):
        store.put_stream(key, Broken(_data(3 * PART)), max_bytes=3 * PART)
    assert "abort_multipart_upload" in client.calls and not bucket.uploads
    assert not bucket.objects


# --- encryption and integrity ------------------------------------------------------------


def test_a_request_without_the_exact_key_is_denied_by_the_bucket_policy() -> None:
    """The fake enforces the ADR-033 bucket policy: only the configured key
    passes. A store configured with another key cannot write at all."""
    bucket = fake.FakeBucket()
    wrong = S3BlobStore(bucket.client(), bucket=fake.BUCKET, kms_key_arn=fake.OTHER_KEY_ARN,
                        part_size=PART)  # fmt: skip
    key = f"versions/{uuid.uuid4()}/{uuid.uuid4()}/{uuid.uuid4()}/source.csv"
    for data in (b"a\n", _data(PART + 1)):
        with pytest.raises(BlobUnavailable):
            wrong.put_stream(key, io.BytesIO(data), max_bytes=len(data))
    assert not bucket.objects and not bucket.uploads


@pytest.mark.parametrize(
    "tamper",
    [
        {"ServerSideEncryption": "AES256"},
        {"SSEKMSKeyId": fake.OTHER_KEY_ARN},
        {"ChecksumSHA256": base64.b64encode(b"\0" * 32).decode()},
    ],
)
@pytest.mark.parametrize("size", [10, PART + 1])
def test_a_stored_object_that_reports_other_encryption_or_checksum_is_refused(
    tamper: dict[str, str], size: int
) -> None:
    store, _, bucket = _store()
    bucket.tamper_response = tamper
    key = f"versions/{uuid.uuid4()}/{uuid.uuid4()}/{uuid.uuid4()}/source.csv"
    with pytest.raises(BlobUnavailable):
        store.put_stream(key, io.BytesIO(_data(size)), max_bytes=size)


# --- conditional writes, retries and adoption --------------------------------------------


@pytest.mark.parametrize("size", [10, 2 * PART + 7])
def test_an_existing_object_is_never_replaced_and_identical_bytes_are_recognised(
    size: int,
) -> None:
    store, _, bucket = _store()
    key = f"versions/{uuid.uuid4()}/{uuid.uuid4()}/{uuid.uuid4()}/source.csv"
    data = _data(size)
    store.put_stream(key, io.BytesIO(data), max_bytes=size)
    with pytest.raises(BlobExistsError) as same:
        store.put_stream(key, io.BytesIO(data), max_bytes=size)
    assert (same.value.size, same.value.fingerprint) == store.attributes(key)  # adoptable
    with pytest.raises(BlobExistsError) as other:
        store.put_stream(key, io.BytesIO(_data(size, seed=2)), max_bytes=size)
    assert (other.value.size, other.value.fingerprint) != store.attributes(key)  # a conflict
    assert len(bucket.objects[key]) == 1 and bucket.current(key).data == data
    assert not bucket.uploads


@pytest.mark.parametrize(("op", "size"), [("put_object", 10), ("complete_multipart_upload",
                                                                   PART + 1)])  # fmt: skip
def test_a_concurrent_write_conflict_is_retried_once(op: str, size: int) -> None:
    store, client, bucket = _store()
    key = f"versions/{uuid.uuid4()}/{uuid.uuid4()}/{uuid.uuid4()}/source.csv"
    bucket.conflict_next = [op]
    assert store.put_stream(key, io.BytesIO(_data(size)), max_bytes=size)[0] == size
    assert client.calls.count(op) == 2
    bucket.conflict_next = [op, op]  # twice: reported as a conflict, nothing replaced
    key2 = f"versions/{uuid.uuid4()}/{uuid.uuid4()}/{uuid.uuid4()}/source.csv"
    with pytest.raises(BlobExistsError):
        store.put_stream(key2, io.BytesIO(_data(size)), max_bytes=size)
    assert not bucket.uploads


def test_the_store_refuses_keys_outside_the_dataset_areas() -> None:
    store, client, _ = _store()
    for bad in ("../x", "other/a/b/c", "versions/../x", "versions//x"):
        with pytest.raises(ValueError):
            store.put_stream(bad, io.BytesIO(b"x"), max_bytes=1)
    assert client.calls == []
    with pytest.raises(ValueError):
        S3BlobStore(fake.FakeBucket().client(), bucket=fake.BUCKET, kms_key_arn=fake.KEY_ARN,
                    prefix="quarantine")  # fmt: skip


# --- version-aware purge -----------------------------------------------------------------


def test_the_operator_purge_removes_every_version_marker_and_upload() -> None:
    bucket = fake.FakeBucket(page_size=2)  # exercise pagination
    store, client, _ = _store(bucket)
    scoped = TenantScopedBlobStore(store, uuid.uuid4())
    d, v = uuid.uuid4(), uuid.uuid4()
    key = scoped.object_key(d, v)
    store.put_stream(key, io.BytesIO(b"one"), max_bytes=10)
    client.delete_object(Bucket=fake.BUCKET, Key=key)  # a delete marker: NOT deletion
    store.put_stream(key, io.BytesIO(b"two"), max_bytes=10)  # a second version
    client.create_multipart_upload(
        Bucket=fake.BUCKET, Key=key, ServerSideEncryption="aws:kms", SSEKMSKeyId=fake.KEY_ARN
    )  # an abandoned upload; fmt: skip
    items = scoped.list_version(d, v)
    assert len(items) == 4 and sum("#v=" in i for i in items) == 2
    assert sum("#m=" in i for i in items) == 1 and sum("#u=" in i for i in items) == 1
    removed, verified = scoped.delete_version_and_verify(d, v)
    assert verified and sorted(removed) == sorted(items)
    assert key not in bucket.objects and not bucket.uploads
    assert scoped.delete_version_and_verify(d, v) == ([], True)  # idempotent


def test_reads_are_bounded_and_missing_objects_are_not_found() -> None:
    store, _, _ = _store(read_limit=10)
    key = f"versions/{uuid.uuid4()}/{uuid.uuid4()}/{uuid.uuid4()}/source.csv"
    for op in (store.open, store.attributes, store.digest):
        with pytest.raises(FileNotFoundError):
            op(key)
    assert not store.exists(key)
    store.put_stream(key, io.BytesIO(b"x" * 11), max_bytes=11)
    with store.open(key) as body, pytest.raises(BlobTooLargeError):
        body.read(-1)


def test_failures_never_log_keys_buckets_content_or_credentials(
    capsys: pytest.CaptureFixture[str],
) -> None:
    structlog.configure(processors=[structlog.processors.JSONRenderer()])
    bucket = fake.FakeBucket()
    wrong = S3BlobStore(bucket.client(), bucket=fake.BUCKET, kms_key_arn=fake.OTHER_KEY_ARN)
    tenant, d, v = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    key = f"versions/{tenant}/{d}/{v}/source.csv"
    secret = b"customer-secret-value"
    with pytest.raises(BlobUnavailable) as exc:
        wrong.put_stream(key, io.BytesIO(secret), max_bytes=100)
    text = capsys.readouterr().out + capsys.readouterr().err + str(exc.value)
    for needle in (str(tenant), str(d), str(v), fake.BUCKET, fake.KEY_ARN, fake.OTHER_KEY_ARN,
                   "customer-secret", "source.csv"):  # fmt: skip
        assert needle not in text, needle
    structlog.reset_defaults()


def test_part_size_and_multipart_threshold() -> None:
    assert 8 * MiB == PART_SIZE
    with pytest.raises(ValueError):
        S3BlobStore(fake.FakeBucket().client(), bucket=fake.BUCKET, kms_key_arn=fake.KEY_ARN,
                    part_size=MiB)  # fmt: skip
