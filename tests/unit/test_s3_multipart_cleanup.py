"""The operator's multipart-upload cleanup on S3 (ADR-033, review finding F5).

AWS's Service Authorization Reference lists NO ``s3:prefix`` condition key for
``s3:ListBucketMultipartUploads`` (resource: the bucket only), so the operator
role's listing cannot be confined by IAM and is granted on the whole bucket.
The prefix is enforced in ``S3BlobStore``: only uploads inside the requested
version or dataset prefix are ever aborted, and a response that is not exactly
what was asked for refuses the listing before anything is removed. No network,
no AWS: a deterministic fake and botocore's Stubber."""

from __future__ import annotations

import importlib.util
import io
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import boto3
import pytest
import structlog
from botocore.config import Config
from botocore.stub import Stubber

import nlw.storage.s3 as s3mod
from nlw.storage.blob import BlobKeyError, BlobUnavailable, TenantScopedBlobStore
from nlw.storage.s3 import S3BlobStore, upload_in_prefix

_spec = importlib.util.spec_from_file_location("s3_fake", Path(__file__).with_name("s3_fake.py"))
assert _spec and _spec.loader
fake = sys.modules.get("s3_fake") or importlib.util.module_from_spec(_spec)
if "s3_fake" not in sys.modules:
    sys.modules["s3_fake"] = fake
    _spec.loader.exec_module(fake)

PART = 5 * 1024 * 1024


def _setup(page_size: int = 1000) -> tuple[Any, S3BlobStore, Any, TenantScopedBlobStore]:
    bucket = fake.FakeBucket(page_size=page_size)
    client = bucket.client()
    store = S3BlobStore(client, bucket=fake.BUCKET, kms_key_arn=fake.KEY_ARN, part_size=PART)
    return bucket, store, client, TenantScopedBlobStore(store, uuid.uuid4())


def _upload(client: Any, key: str) -> str:
    return str(
        client.create_multipart_upload(
            Bucket=fake.BUCKET, Key=key, ServerSideEncryption="aws:kms", SSEKMSKeyId=fake.KEY_ARN
        )["UploadId"]
    )


def _neighbours(client: Any, scoped: TenantScopedBlobStore, d: uuid.UUID, v: uuid.UUID) -> set[str]:
    """Uploads that are NOT the target version's: another version of the same
    dataset, another dataset, another tenant, another version's legacy copy,
    and a key that shares the version id as a string prefix."""
    t = scoped.tenant_id
    other_v, other_d = uuid.uuid4(), uuid.uuid4()
    keys = [
        f"versions/{t}/{d}/{other_v}/source.csv",
        f"versions/{t}/{other_d}/{v}/source.csv",
        f"versions/{uuid.uuid4()}/{d}/{v}/source.csv",
        f"quarantine/{t}/{d}/{other_v}",
        f"versions/{t}/{d}/{v}-x/source.csv",
    ]
    return {_upload(client, k) for k in keys}


# --- 3. uploads outside the target prefix are ignored and never aborted -------------------


def _purge_version_with_neighbours() -> tuple[Any, set[str], set[str]]:
    bucket, _, client, scoped = _setup()
    d, v = uuid.uuid4(), uuid.uuid4()
    own = {_upload(client, scoped.object_key(d, v)) for _ in range(3)}
    foreign = _neighbours(client, scoped, d, v)
    removed, verified = scoped.delete_version_and_verify(d, v)
    assert verified
    assert {r.partition("#u=")[2] for r in removed if "#u=" in r} == own
    return bucket, own, foreign


def test_only_the_target_versions_uploads_are_aborted() -> None:
    bucket, own, foreign = _purge_version_with_neighbours()
    assert {uid for _, uid in bucket.aborted} == own
    assert set(bucket.uploads) == foreign  # every neighbour is still in progress


def test_a_look_alike_sibling_of_an_exact_key_prefix_is_ignored() -> None:
    """S3 matches ``Prefix`` as a plain string: ``…/<id>`` also returns
    ``…/<id>-x/…``. The store treats a prefix without a trailing slash as ONE
    exact key."""
    bucket, store, client, scoped = _setup()
    t, d, v = scoped.tenant_id, uuid.uuid4(), uuid.uuid4()
    exact = f"quarantine/{t}/{d}/{v}"
    mine = _upload(client, exact)
    sibling = _upload(client, f"{exact}-x")
    below = _upload(client, f"{exact}/part")
    assert {i.partition("#u=")[2] for i in store.list_prefix(exact)} == {mine, below}
    store.purge_prefix(exact)
    assert set(bucket.uploads) == {sibling}


def test_an_upload_s3_returns_outside_the_prefix_refuses_the_listing_before_any_abort() -> None:
    bucket, _, client, scoped = _setup()
    d, v = uuid.uuid4(), uuid.uuid4()
    own = _upload(client, scoped.object_key(d, v))
    stray = f"versions/{uuid.uuid4()}/{d}/{v}/source.csv"
    _upload(client, stray)

    def leak(kw: dict[str, Any], out: dict[str, Any]) -> dict[str, Any]:
        out["Uploads"].append({"Key": stray, "UploadId": "u999999"})
        return out

    bucket.uploads_response = leak
    with pytest.raises(BlobUnavailable, match="unexpected_key"):
        scoped.delete_version_and_verify(d, v)
    assert bucket.aborted == [] and own in bucket.uploads  # nothing at all was removed


# --- 4. encoded, Unicode and look-alike keys cannot pass the filter ----------------------

P = "versions/11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222/" \
    "33333333-3333-4333-8333-333333333333/"  # fmt: skip


@pytest.mark.parametrize(
    "key",
    [
        P.replace("/", "%2F", 1) + "source.csv",  # percent-encoded separator
        P.replace("versions", "VERSIONS") + "source.csv",  # case
        P.replace("versions", "versіons") + "source.csv",  # Cyrillic i
        P.replace("versions", "ｖersions") + "source.csv",  # fullwidth v (NFKC look-alike)
        P[:-1] + "∕source.csv",  # division slash instead of '/'
        P[:-1] + "%2Fsource.csv",
        P[:-2] + "4/source.csv",  # a neighbouring version id
        "/" + P + "source.csv",
        " " + P + "source.csv",
        "",
    ],
)
def test_keys_not_starting_with_the_exact_prefix_are_refused(key: str) -> None:
    with pytest.raises(BlobKeyError):
        upload_in_prefix(key, P)


@pytest.mark.parametrize(
    "suffix",
    [
        "%2e%2e/x",  # encoded traversal
        "../../../x",  # traversal
        "source.csv/",  # empty last segment
        "a//b",
        "Source.csv",  # uppercase is never a derived key
        "sourceе.csv",  # Cyrillic e
        "source.csv​",  # zero-width space
        "source.csv\x00",
        "source.csv\n",
        ".hidden",
        "",  # the prefix itself, a "directory"
    ],
)
def test_malformed_keys_inside_the_prefix_are_refused(suffix: str) -> None:
    with pytest.raises(BlobKeyError):
        upload_in_prefix(P + suffix, P)


def test_well_formed_keys_inside_the_prefix_are_accepted() -> None:
    assert upload_in_prefix(P + "source.csv", P)
    exact = P + "source.csv"
    assert upload_in_prefix(exact, exact)
    assert not upload_in_prefix(exact + "-x", exact)  # sibling: ignored, not refused


@pytest.mark.parametrize(
    "key",
    [P.replace("/", "%2F", 1) + "source.csv", P + "%2e%2e/x", P + "sourceе.csv"],
)
def test_a_tampered_listing_with_an_encoded_or_unicode_key_aborts_nothing(key: str) -> None:
    bucket, store, client, _ = _setup()
    own = _upload(client, P + "source.csv")
    bucket.uploads_response = lambda kw, out: {
        **out, "Uploads": [*out["Uploads"], {"Key": key, "UploadId": "u999999"}]
    }  # fmt: skip
    with pytest.raises(BlobUnavailable):
        store.purge_prefix(P)
    assert bucket.aborted == [] and own in bucket.uploads


# --- 5. pagination cannot escape the prefix -----------------------------------------------


def test_paginated_listing_aborts_every_own_upload_and_no_other() -> None:
    bucket, _, client, scoped = _setup(page_size=2)
    d, v = uuid.uuid4(), uuid.uuid4()
    own = {_upload(client, scoped.object_key(d, v)) for _ in range(7)}
    foreign = _neighbours(client, scoped, d, v)
    removed, verified = scoped.delete_version_and_verify(d, v)
    assert verified and {r.partition("#u=")[2] for r in removed if "#u=" in r} == own
    assert set(bucket.uploads) == foreign
    assert client.calls.count("list_multipart_uploads") >= 4 + 1  # 7 own / 2 per page, re-verify


def _paged(bucket: Any, client: Any, n: int = 5) -> set[str]:
    bucket.page_size = 2
    return {_upload(client, P + "source.csv") for _ in range(n)}


@pytest.mark.parametrize(
    ("reason", "tamper"),
    [
        ("bad_pagination", lambda kw, o: {**o, "NextKeyMarker": "versions/zzz/source.csv"}
         if o["IsTruncated"] else o),
        ("bad_pagination", lambda kw, o: {**o, "NextKeyMarker": "quarantine/a/b"}
         if o["IsTruncated"] else o),
        ("bad_pagination", lambda kw, o: {k: x for k, x in o.items() if k != "NextKeyMarker"}),
        ("bad_pagination", lambda kw, o: {k: x for k, x in o.items()
                                          if k != "NextUploadIdMarker"}),
        ("bad_pagination", lambda kw, o: {**o, "NextUploadIdMarker": "a b"}
         if o["IsTruncated"] else o),
        ("partial_response", lambda kw, o: {k: x for k, x in o.items() if k != "IsTruncated"}),
        ("partial_response", lambda kw, o: {**o, "IsTruncated": "false"}),
        ("partial_response", lambda kw, o: {**o, "Uploads": None}),
        ("unexpected_response", lambda kw, o: {**o, "EncodingType": "url"}),
        ("unexpected_response", lambda kw, o: {**o, "Prefix": "versions/"}),
        ("malformed_upload", lambda kw, o: {**o, "Uploads": [*o["Uploads"], "x"]}),
        ("malformed_upload", lambda kw, o: {**o, "Uploads": [{"Key": P + "source.csv"}]}),
        ("malformed_upload", lambda kw, o: {**o, "Uploads": [
            {"Key": P + "source.csv", "UploadId": "u1#v=evil"}]}),
    ],
)  # fmt: skip
def test_a_malformed_or_escaping_page_refuses_the_listing(
    reason: str, tamper: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
) -> None:
    bucket, store, client, _ = _setup()
    own = _paged(bucket, client)
    bucket.uploads_response = tamper
    with pytest.raises(BlobUnavailable, match=reason):
        store.purge_prefix(P)
    assert bucket.aborted == [] and own <= set(bucket.uploads)


def test_a_marker_that_does_not_move_is_refused() -> None:
    bucket, store, client, _ = _setup()
    _paged(bucket, client)
    first: dict[str, Any] = {}

    def stuck(kw: dict[str, Any], out: dict[str, Any]) -> dict[str, Any]:
        if not first:
            first.update(out)
        return {**first}  # every page repeats the first one

    bucket.uploads_response = stuck
    with pytest.raises(BlobUnavailable, match="bad_pagination"):
        list(store.list_prefix(P))
    assert client.calls.count("list_multipart_uploads") == 2


def test_an_endless_listing_is_bounded_and_refused() -> None:
    bucket, store, client, _ = _setup()
    count = iter(range(10**6))

    def endless(kw: dict[str, Any], out: dict[str, Any]) -> dict[str, Any]:
        n = next(count)
        uid = f"u{n:06d}"
        return {"Prefix": P, "Uploads": [{"Key": P + "source.csv", "UploadId": uid}],
                "IsTruncated": True, "NextKeyMarker": P + "source.csv",
                "NextUploadIdMarker": uid}  # fmt: skip

    bucket.uploads_response = endless
    with pytest.raises(BlobUnavailable, match="too_many_pages"):
        store.purge_prefix(P)
    assert client.calls.count("list_multipart_uploads") == s3mod._MAX_UPLOAD_PAGES
    assert bucket.aborted == []


def test_the_listing_request_shape_is_exact_and_never_url_encoded() -> None:
    """Stubber validates against the real S3 model: a bounded page, the exact
    prefix, the markers on the next page, and never ``EncodingType``."""
    s3 = boto3.client("s3", region_name="us-east-1", aws_access_key_id="x",
                      aws_secret_access_key="y", aws_session_token="z",
                      config=Config(retries={"max_attempts": 0}))  # fmt: skip
    key = P + "source.csv"
    store = S3BlobStore(s3, bucket=fake.BUCKET, kms_key_arn=fake.KEY_ARN)
    with Stubber(s3) as stub:
        stub.add_response("list_object_versions", {"IsTruncated": False},
                          {"Bucket": fake.BUCKET, "Prefix": P})  # fmt: skip
        stub.add_response(
            "list_multipart_uploads",
            {"Prefix": P, "Uploads": [{"Key": key, "UploadId": "a1"}], "IsTruncated": True,
             "NextKeyMarker": key, "NextUploadIdMarker": "a1"},
            {"Bucket": fake.BUCKET, "Prefix": P, "MaxUploads": 1000},
        )  # fmt: skip
        stub.add_response(
            "list_multipart_uploads",
            {"Prefix": P, "Uploads": [{"Key": key, "UploadId": "a0"}], "IsTruncated": False},
            {"Bucket": fake.BUCKET, "Prefix": P, "MaxUploads": 1000, "KeyMarker": key,
             "UploadIdMarker": "a1"},
        )  # fmt: skip
        assert list(store.list_prefix(P)) == [f"{key}#u=a1", f"{key}#u=a0"]
        stub.assert_no_pending_responses()


# --- 6. a partial failure is safely retryable ---------------------------------------------


def test_a_failed_abort_leaves_the_rest_for_a_rerun_which_completes() -> None:
    bucket, _, client, scoped = _setup()
    d, v = uuid.uuid4(), uuid.uuid4()
    key = scoped.object_key(d, v)
    own = sorted(_upload(client, key) for _ in range(3))
    foreign = _neighbours(client, scoped, d, v)
    bucket.abort_fail_next = [own[1]]
    with pytest.raises(BlobUnavailable, match="abort_multipart_upload failed"):
        scoped.delete_version_and_verify(d, v)
    assert own[1] in bucket.uploads and own[0] not in bucket.uploads  # partial, not lost
    removed, verified = scoped.delete_version_and_verify(d, v)  # the re-run
    assert verified and sorted(r.partition("#u=")[2] for r in removed) == own[1:]
    assert set(bucket.uploads) == foreign


def test_an_upload_that_vanished_between_listing_and_abort_is_not_an_error() -> None:
    """The lifecycle rule or a concurrent run may abort it first: S3 answers
    ``NoSuchUpload`` (404). The purge goes on; verification re-lists."""
    bucket, _, client, scoped = _setup()
    d, v = uuid.uuid4(), uuid.uuid4()
    key = scoped.object_key(d, v)
    kept = _upload(client, key)
    once = [True]

    def ghost(kw: dict[str, Any], out: dict[str, Any]) -> dict[str, Any]:
        if once and once.pop():
            out["Uploads"].append({"Key": key, "UploadId": "u999999"})  # already gone
        return out

    bucket.uploads_response = ghost
    removed, verified = scoped.delete_version_and_verify(d, v)
    assert verified and [r.partition("#u=")[2] for r in removed] == [kept]


def test_a_refused_listing_logs_and_reports_no_key_bucket_or_upload_id(
    capsys: pytest.CaptureFixture[str],
) -> None:
    structlog.configure(processors=[structlog.processors.JSONRenderer()])
    try:
        bucket, store, client, _ = _setup()
        stray = f"versions/{uuid.uuid4()}/{uuid.uuid4()}/{uuid.uuid4()}/source.csv"
        bucket.uploads_response = lambda kw, out: {
            **out, "Uploads": [{"Key": stray, "UploadId": "secretuploadid42"}]
        }  # fmt: skip
        with pytest.raises(BlobUnavailable) as exc:
            store.purge_prefix(P)
        text = capsys.readouterr().out + str(exc.value)
        assert "dataset.s3_listing_refused" in text
        for needle in (stray, P, fake.BUCKET, "secretuploadid42", "source.csv"):
            assert needle not in text, needle
    finally:
        structlog.reset_defaults()


# --- 9. negative control: without the application filter the safety test fails -----------


def test_negative_control_without_the_prefix_filter_a_neighbour_is_aborted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``upload_in_prefix`` is the ONLY thing between a bucket-wide listing
    and an abort. Replaced by an accept-everything stub, the look-alike
    sibling is aborted: the assertion in
    ``test_a_look_alike_sibling_of_an_exact_key_prefix_is_ignored`` fails."""
    monkeypatch.setattr(s3mod, "upload_in_prefix", lambda key, prefix: True)
    with pytest.raises(AssertionError):
        test_a_look_alike_sibling_of_an_exact_key_prefix_is_ignored()


def test_negative_control_without_the_prefix_filter_a_stray_upload_is_aborted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(s3mod, "upload_in_prefix", lambda key, prefix: True)
    with pytest.raises((AssertionError, pytest.fail.Exception)):
        test_an_upload_s3_returns_outside_the_prefix_refuses_the_listing_before_any_abort()


def test_the_store_has_one_prefix_filter_and_uses_it() -> None:
    """The negative controls patch the module attribute: the listing must look
    it up there (not a captured copy) for them to mean anything."""
    src = Path(s3mod.__file__).read_text()
    assert src.count("upload_in_prefix(key, prefix)") == 1
    assert "def upload_in_prefix(" in src


def test_uploads_are_never_listed_with_a_url_encoding_request() -> None:
    _, store, client, _ = _setup()
    seen: list[dict[str, Any]] = []
    real = client.list_multipart_uploads

    def spy(**kw: Any) -> dict[str, Any]:
        seen.append(kw)
        return dict(real(**kw))

    client.list_multipart_uploads = spy
    list(store.list_prefix(P))
    assert seen and all("EncodingType" not in kw for kw in seen)
    assert all(kw["Prefix"] == P and kw["MaxUploads"] == 1000 for kw in seen)


def test_a_store_written_upload_is_cleaned_by_the_version_purge() -> None:
    """End to end on the fake: an upload the API abandoned (crash before its
    own abort) is found and aborted by the operator's version purge."""
    bucket, store, client, scoped = _setup()
    d, v = uuid.uuid4(), uuid.uuid4()
    store.put_stream(scoped.object_key(d, v), io.BytesIO(b"a,b\n"), max_bytes=10)
    left = _upload(client, scoped.object_key(d, v))
    removed, verified = scoped.delete_version_and_verify(d, v)
    assert verified and any(r.endswith(f"#u={left}") for r in removed)
    assert not bucket.uploads and not bucket.objects
