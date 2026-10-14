"""The S3 Object Lock deletion log (ADR-034, owner decision O-3) against an
in-memory S3 that enforces the reviewed bucket policy and operator grants.
No network, no AWS."""

from __future__ import annotations

import importlib.util
import json
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

_spec = importlib.util.spec_from_file_location(
    "receipt_s3_fake", Path(__file__).with_name("receipt_s3_fake.py")
)
assert _spec is not None and _spec.loader is not None
fake = importlib.util.module_from_spec(_spec)
sys.modules["receipt_s3_fake"] = fake
_spec.loader.exec_module(fake)

from nlw.datasets import deletion_log_s3  # noqa: E402
from nlw.datasets.deletion_log import (  # noqa: E402
    DeletionLogUnavailable,
    DeletionReceipt,
    ExpectedReceipt,
    ReceiptCheck,
    ReceiptRef,
)
from nlw.datasets.deletion_log_s3 import (  # noqa: E402
    MAX_JSON_DEPTH,
    MAX_RECEIPT_BYTES,
    ReceiptUnreadable,
    S3DeletionLog,
    json_depth_within,
    parse_receipt,
    receipt_key,
    sink_for,
)

T, D, V = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
DIGEST = "c" * 64
SINK = f"s3.{fake.BUCKET}"


def _log(bucket: Any = None, role: str | None = "operator") -> S3DeletionLog:
    b = bucket or fake.ReceiptBucket()
    return S3DeletionLog(b.client(role), fake.BUCKET)


def _receipt(**over: object) -> DeletionReceipt:
    r = DeletionReceipt.for_version(
        sink=SINK, environment="local", tenant_id=T, dataset_id=D, version_id=V,
        content_sha256=DIGEST, deleted_keys=[f"versions/{T}/{D}/{V}/source.csv#v=abc"],
        operator="op",
    )  # fmt: skip
    return DeletionReceipt(**{**r.__dict__, **over})


def _expected(r: DeletionReceipt, **over: object) -> ExpectedReceipt:
    base = {
        "sink": SINK, "receipt_id": r.receipt_id, "tenant_id": T, "dataset_id": D,
        "version_id": V, "content_sha256": DIGEST, "deletion_set_sha256": r.deletion_set_sha256,
        "not_before": datetime.now(UTC) - timedelta(minutes=5),
    }  # fmt: skip
    return ExpectedReceipt(**{**base, **over})  # type: ignore[arg-type]


def _key(r: DeletionReceipt) -> str:
    return receipt_key(ReceiptRef(T, D, V, r.receipt_id))


# --- identity -------------------------------------------------------------------


def test_the_sink_binds_receipts_to_one_dedicated_bucket() -> None:
    assert sink_for(fake.BUCKET) == SINK
    for bad in (
        "nlw-local-datasets-111122223333-us-east-1",  # the dataset bucket
        "nlw-local-dataset-audit-111122223333-us-east-1",  # the audit bucket
        "other-bucket",
    ):
        with pytest.raises(DeletionLogUnavailable):
            sink_for(bad)


# --- write once, retained -------------------------------------------------------


def test_append_writes_one_retained_object_once() -> None:
    bucket = fake.ReceiptBucket()
    log = _log(bucket)
    r = _receipt()
    log.preflight()
    assert log.append(r) == r.receipt_id
    [stored] = bucket.objects[_key(r)]
    assert json.loads(stored.data) == json.loads(r.to_json())
    assert stored.mode == "GOVERNANCE" and stored.sse == "AES256"
    assert log.verify(_expected(r)) is ReceiptCheck.VERIFIED
    # The same id is never written twice (If-None-Match), and nothing is deleted.
    with pytest.raises(DeletionLogUnavailable, match="already exists"):
        log.append(r)
    assert len(bucket.objects[_key(r)]) == 1
    assert "delete_object" not in log._s3.calls  # type: ignore[attr-defined]


def test_the_storage_location_and_names_never_leave_the_log() -> None:
    bucket = fake.ReceiptBucket()
    log = _log(bucket)
    r = _receipt()
    log.append(r)
    body = bucket.objects[_key(r)][0].data.decode()
    assert "source.csv" not in body and "versions/" not in body and "#v=" not in body
    bucket.set_lock(None)
    with pytest.raises(DeletionLogUnavailable) as exc:
        log.preflight()
    assert fake.BUCKET not in str(exc.value) and "receipts/" not in str(exc.value)


@pytest.mark.parametrize("mode", [None, "NONE"])
def test_preflight_refuses_a_bucket_without_default_retention(mode: str | None) -> None:
    bucket = fake.ReceiptBucket()
    bucket.set_lock(None) if mode is None else bucket.set_lock("GOVERNANCE", days=0)
    with pytest.raises(DeletionLogUnavailable):
        _log(bucket).preflight()


def test_append_refuses_a_receipt_stored_without_retention() -> None:
    bucket = fake.ReceiptBucket()
    log = _log(bucket)
    bucket.set_lock(None)  # retention removed after the preflight
    with pytest.raises(DeletionLogUnavailable, match="without Object Lock retention"):
        log.append(_receipt())


def test_append_refuses_a_receipt_for_another_sink() -> None:
    with pytest.raises(DeletionLogUnavailable, match="another sink"):
        _log().append(_receipt(sink="local-fake"))


# --- verify ---------------------------------------------------------------------


def _stored_log() -> tuple[object, S3DeletionLog, DeletionReceipt]:
    bucket = fake.ReceiptBucket()
    log = _log(bucket)
    r = _receipt()
    log.append(r)
    return bucket, log, r


def test_verify_looks_up_by_the_expected_ids_not_the_receipt_id_alone() -> None:
    _, log, r = _stored_log()
    assert log.verify(_expected(r, version_id=uuid.uuid4())) is ReceiptCheck.MISSING
    assert log.verify(_expected(r, tenant_id=uuid.uuid4())) is ReceiptCheck.MISSING
    assert log.verify(_expected(r, receipt_id="not-there")) is ReceiptCheck.MISSING
    assert log.verify(_expected(r, sink="local-fake")) is ReceiptCheck.SINK_MISMATCH


def test_verify_detects_tampered_bytes_and_lost_retention() -> None:
    bucket, log, r = _stored_log()
    good = bucket.objects[_key(r)][0].data  # type: ignore[attr-defined]
    bucket.corrupt(_key(r), good.replace(b'"op"', b'"xx"'))  # type: ignore[attr-defined]
    assert log.verify(_expected(r)) is ReceiptCheck.MALFORMED  # checksum
    bucket.corrupt(_key(r), good)  # type: ignore[attr-defined]
    assert log.verify(_expected(r)) is ReceiptCheck.VERIFIED
    bucket.expire_retention(_key(r))  # type: ignore[attr-defined]
    assert log.verify(_expected(r)) is ReceiptCheck.NOT_RETAINED


def test_verify_applies_the_provider_neutral_checks() -> None:
    _, log, r = _stored_log()
    assert log.verify(_expected(r, deletion_set_sha256="d" * 64)) is ReceiptCheck.DIGEST_MISMATCH
    assert log.verify(_expected(r, content_sha256="e" * 64)) is ReceiptCheck.DIGEST_MISMATCH
    later = datetime.now(UTC) + timedelta(minutes=5)
    assert log.verify(_expected(r, not_before=later)) is ReceiptCheck.STALE


def test_an_oversized_receipt_is_malformed() -> None:
    bucket, log, r = _stored_log()
    bucket.objects[_key(r)][0].data = b"x" * (MAX_RECEIPT_BYTES + 1)  # type: ignore[attr-defined]
    bucket.objects[_key(r)][0].checksum = fake.b64sha(b"x" * (MAX_RECEIPT_BYTES + 1))  # type: ignore[attr-defined]
    assert log.verify(_expected(r)) is ReceiptCheck.MALFORMED


def test_an_access_failure_is_unverifiable_never_verified() -> None:
    bucket, _, r = _stored_log()
    api = _log(bucket, role="api")
    assert api.verify(_expected(r)) is ReceiptCheck.UNVERIFIABLE


# --- list and read --------------------------------------------------------------


def test_refs_lists_every_receipt_across_pages_and_skips_strangers() -> None:
    bucket = fake.ReceiptBucket(page_size=2)
    log = _log(bucket)
    written = []
    for _ in range(5):
        r = _receipt(receipt_id=str(uuid.uuid4()))
        log.append(r)
        written.append(ReceiptRef(T, D, V, r.receipt_id))
    bucket.plant("receipts/not-a-receipt.txt", b"x")
    assert sorted(log.refs()) == sorted(written)
    assert log.unexpected_objects == 1
    assert log.read(written[0])["receipt_id"] == written[0].receipt_id  # type: ignore[index]
    assert log.read(ReceiptRef(T, D, V, "absent")) is None


def test_read_refuses_an_untrustworthy_receipt() -> None:
    bucket, log, r = _stored_log()
    bucket.expire_retention(_key(r))  # type: ignore[attr-defined]
    with pytest.raises(ReceiptUnreadable) as exc:
        log.read(ReceiptRef(T, D, V, r.receipt_id))
    assert exc.value.check is ReceiptCheck.NOT_RETAINED


# --- the grants ------------------------------------------------------------------


def test_runtime_roles_cannot_touch_receipts_and_the_operator_cannot_delete() -> None:
    bucket, _, r = _stored_log()
    for role in fake.RUNTIME_ROLES:
        log = _log(bucket, role=role)
        with pytest.raises(DeletionLogUnavailable):
            log.preflight()
        with pytest.raises(DeletionLogUnavailable):
            list(log.refs())
    operator = bucket.client("operator")  # type: ignore[attr-defined]
    with pytest.raises(Exception, match="AccessDenied"):
        operator.delete_object(Bucket=fake.BUCKET, Key=_key(r))
    admin = bucket.client("audit-admin")  # type: ignore[attr-defined]
    with pytest.raises(Exception, match="AccessDenied"):  # Object Lock, even for the admin
        admin.delete_object(Bucket=fake.BUCKET, Key=_key(r))
    assert bucket.objects[_key(r)]  # type: ignore[attr-defined]


# --- review findings (PR #66): M-1 writers, M-2 nesting, L-1 listing, L-2 strays ------------


@pytest.mark.parametrize("role", ["account-admin", "audit-admin", "api", "ingest"])
def test_only_the_operator_role_can_create_a_receipt(role: str) -> None:
    """M-1: whatever a principal's identity policy allows, the bucket policy
    lets only nlw-<ENV>-dataset-operator create a receipt."""
    bucket = fake.ReceiptBucket()
    with pytest.raises(DeletionLogUnavailable):
        _log(bucket, role=role).append(_receipt())
    assert bucket.objects == {}
    _log(bucket, role="operator").append(_receipt())
    assert len(bucket.objects) == 1


def _bomb(depth: int = 30_000) -> bytes:
    return b"[" * depth + b"]" * depth


def test_a_deeply_nested_receipt_is_malformed_never_a_crash() -> None:
    """M-2: within the 64 KiB bound, but nested far past the parser's limit."""
    bucket = fake.ReceiptBucket()
    log = _log(bucket)
    assert len(_bomb()) <= MAX_RECEIPT_BYTES
    bucket.plant(receipt_key(ReceiptRef(T, D, V, "bomb")), _bomb())
    assert log.verify(_expected(_receipt(), receipt_id="bomb")) is ReceiptCheck.MALFORMED
    with pytest.raises(ReceiptUnreadable) as exc:
        log.read(ReceiptRef(T, D, V, "bomb"))
    assert exc.value.check is ReceiptCheck.MALFORMED


def test_nesting_is_bounded_before_parsing_and_strings_do_not_count() -> None:
    assert json_depth_within(b'{"a": [1, 2]}')
    assert json_depth_within(b'{"operator": "[[[[[[{{{{{{"}')  # brackets inside a string
    assert json_depth_within(b'{"x": "\\"[[[[[["}')  # escaped quotes stay inside it
    nested = b"[" * (MAX_JSON_DEPTH + 1) + b"]" * (MAX_JSON_DEPTH + 1)
    assert not json_depth_within(nested)
    assert parse_receipt(nested) is None
    # An OBJECT nested one level too deep is refused for its depth alone.
    deep_object = b'{"a": ' + b"[" * MAX_JSON_DEPTH + b"]" * MAX_JSON_DEPTH + b"}"
    assert not json_depth_within(deep_object)
    assert parse_receipt(deep_object) is None
    at_limit = b'{"a": ' + b"[" * (MAX_JSON_DEPTH - 1) + b"]" * (MAX_JSON_DEPTH - 1) + b"}"
    assert parse_receipt(at_limit) == {"a": [[[]]]}
    # A real receipt (an object holding one list) is well within the bound.
    assert parse_receipt(_receipt().to_json().encode()) is not None


def test_a_recursion_error_is_still_contained_if_the_depth_bound_were_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deletion_log_s3, "MAX_JSON_DEPTH", 10**9)
    monkeypatch.setattr(deletion_log_s3, "json_depth_within", lambda body, limit=0: True)
    assert parse_receipt(_bomb()) is None


def test_a_receipt_whose_strings_hold_brackets_still_verifies() -> None:
    bucket = fake.ReceiptBucket()
    log = _log(bucket)
    r = _receipt(operator="[[[[[[[[{{{{")
    log.append(r)
    assert log.verify(_expected(r)) is ReceiptCheck.VERIFIED


class _Lister:
    """A scripted ListObjectsV2: each call returns the next page (the last repeats)."""

    def __init__(self, pages: list[dict[str, object]]) -> None:
        self.pages, self.calls = pages, 0

    def list_objects_v2(self, **kw: object) -> dict[str, object]:
        page = self.pages[min(self.calls, len(self.pages) - 1)]
        self.calls += 1
        return page


GOOD = {"Prefix": "receipts/", "Contents": [{"Key": f"receipts/{T}/{D}/{V}/r1.json"}]}


@pytest.mark.parametrize(
    "bad, reason",
    [
        ({"Prefix": "receipts/other/", "Contents": []}, "not what was asked for"),
        ({"Contents": []}, "not what was asked for"),  # no prefix echo at all
        ({"Prefix": "receipts/", "EncodingType": "url", "Contents": []}, "not what was asked for"),
        ({"Prefix": "receipts/", "Contents": [{"Key": "versions/x"}]}, "not what was asked for"),
        ({"Prefix": "receipts/", "IsTruncated": True, "Contents": []}, "truncated"),
    ],
)
def test_a_malformed_listing_page_refuses_the_whole_listing(
    bad: dict[str, object], reason: str
) -> None:
    """L-1: even after a good first page, nothing is returned from a bad listing."""
    first = {**GOOD, "IsTruncated": True, "NextContinuationToken": "t1"}
    log = S3DeletionLog(_Lister([first, bad]), fake.BUCKET)  # type: ignore[arg-type]
    with pytest.raises(DeletionLogUnavailable, match=reason):
        list(log.refs())


def test_a_repeating_continuation_token_is_refused_at_once() -> None:
    page = {**GOOD, "IsTruncated": True, "NextContinuationToken": "same"}
    lister = _Lister([page])
    with pytest.raises(DeletionLogUnavailable, match="does not advance"):
        list(S3DeletionLog(lister, fake.BUCKET).refs())  # type: ignore[arg-type]
    assert lister.calls == 2


def test_the_listing_is_bounded_to_1000_pages() -> None:
    class Endless:
        calls = 0

        def list_objects_v2(self, **kw: object) -> dict[str, object]:
            self.calls += 1
            return {"Prefix": "receipts/", "Contents": [], "IsTruncated": True,
                    "NextContinuationToken": f"t{self.calls}"}  # fmt: skip

    endless = Endless()
    with pytest.raises(DeletionLogUnavailable, match="exceeds its bound"):
        list(S3DeletionLog(endless, fake.BUCKET).refs())  # type: ignore[arg-type]
    assert endless.calls == 1000


def test_objects_that_are_not_receipts_are_counted_never_read() -> None:
    """L-2: strays under receipts/ are counted (and reported by the commands)."""
    bucket = fake.ReceiptBucket()
    log = _log(bucket)
    log.append(_receipt())
    bucket.plant(f"receipts/{T}/{D}/{V}/not-json", b"x")
    bucket.plant(f"receipts/{str(T).upper()}/{D}/{V}/r.json", b"x")
    client: Any = log._s3
    before = list(client.calls)
    assert len(list(log.refs())) == 1
    assert log.unexpected_objects == 2
    assert "get_object" not in client.calls[len(before) :]
