"""The deletion-receipt log templates (ADR-034): parsed, pinned and checked
against the invariants the code relies on. NOT RUN against AWS."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = ROOT / "docs/runbooks/deletion-receipt-log-provisioning.md"
PROVISIONING = ROOT / "docs/runbooks/dataset-s3-provisioning.md"
TEMPLATE = re.compile(r"<!-- template: ([a-z0-9-]+) -->\n```json\n(.*?)```", re.S)

_spec = importlib.util.spec_from_file_location(
    "receipt_s3_fake", Path(__file__).with_name("receipt_s3_fake.py")
)
assert _spec is not None and _spec.loader is not None
fake = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("receipt_s3_fake", fake)
_spec.loader.exec_module(fake)

BUCKET = "arn:aws:s3:::<RECEIPT_BUCKET>"
OBJECTS = "arn:aws:s3:::<RECEIPT_BUCKET>/*"
RECEIPTS = "arn:aws:s3:::<RECEIPT_BUCKET>/receipts/*"
NEVER = {
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
    "s3:BypassGovernanceRetention",
    "s3:PutObjectRetention",
    "s3:PutObjectLegalHold",
}


def _strict(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    assert len(keys) == len(set(keys)), f"duplicate JSON keys {keys}"
    return dict(pairs)


def templates(path: Path = RUNBOOK) -> dict[str, Any]:
    found = TEMPLATE.findall(path.read_text())
    names = [n for n, _ in found]
    assert len(names) == len(set(names)), names
    return {n: json.loads(raw, object_pairs_hook=_strict) for n, raw in found}


def sids(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["Sid"]: s for s in doc["Statement"]}


def acts(s: dict[str, Any]) -> set[str]:
    a = s["Action"]
    return {a} if isinstance(a, str) else set(a)


def test_the_runbook_holds_exactly_the_reviewed_templates() -> None:
    assert sorted(templates()) == [
        "receipt-bucket-lifecycle",
        "receipt-bucket-policy",
        "role-audit-admin-receipts",
        "role-audit-reader-receipts",
        "role-operator-receipts",
    ]
    # Nothing in the reviewed dataset/D6 templates is redefined here.
    assert not set(templates()) & set(templates(PROVISIONING))


def test_the_operator_grants_are_pinned_and_match_the_tested_fake() -> None:
    doc = templates()["role-operator-receipts"]
    s = sids(doc)
    assert list(s) == [
        "WriteReceiptsOnce",
        "ReadReceipts",
        "ListReceipts",
        "ConfirmRetention",
        "NeverAlterReceipts",
    ]
    allowed: dict[str, str] = {}
    for st in doc["Statement"]:
        if st["Effect"] != "Allow":
            continue
        for a in acts(st):
            res = st["Resource"]
            if res == RECEIPTS:
                allowed[a] = "receipts/"
            elif res == BUCKET and a == "s3:ListBucket":
                assert st["Condition"] == {"StringLike": {"s3:prefix": ["receipts/*"]}}
                allowed[a] = "receipts/"
            else:
                assert res == BUCKET, (a, res)
                allowed[a] = ""
    assert allowed == fake.OPERATOR_GRANTS
    assert not NEVER & set(allowed)
    deny = s["NeverAlterReceipts"]
    assert deny["Effect"] == "Deny" and acts(deny) >= NEVER
    assert set(deny["Resource"]) == {BUCKET, OBJECTS}


def test_the_bucket_policy_protects_every_receipt() -> None:
    s = sids(templates()["receipt-bucket-policy"])
    assert all(st["Effect"] == "Deny" and st["Principal"] == "*" for st in s.values())
    assert s["DenyNonTLS"]["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
    runtime = s["DenyDatasetRuntimeRoles"]["Condition"]["ArnLike"]["aws:PrincipalArn"]
    assert {r.rsplit("-", 1)[-1] for r in runtime} == set(fake.RUNTIME_ROLES)
    assert all("dataset-operator" not in r for r in runtime)  # the operator writes receipts
    assert s["DenyUnconditionalCreate"]["Condition"] == {"Null": {"s3:if-none-match": "true"}}
    assert s["DenyWrongSseAlgorithm"]["Condition"] == {
        "StringNotEquals": {"s3:x-amz-server-side-encryption": "AES256"}
    }
    assert s["DenyWritesOutsideReceipts"]["NotResource"] == RECEIPTS
    change = s["DenyRecordChangeExceptAuditAdmin"]
    assert acts(change) == NEVER and change["Resource"] == OBJECTS
    admin = "arn:aws:iam::<ACCOUNT>:role/<AUDIT_ADMIN_ROLE>"
    assert change["Condition"] == {"ArnNotEquals": {"aws:PrincipalArn": admin}}
    config = s["DenyBucketConfigExceptAuditAdmin"]
    assert {"s3:PutBucketObjectLockConfiguration", "s3:PutLifecycleConfiguration"} <= acts(config)
    assert config["Condition"] == {"ArnNotEquals": {"aws:PrincipalArn": admin}}


def test_no_audit_role_can_shorten_retention() -> None:
    t = templates()
    for name in ("role-audit-admin-receipts", "role-audit-reader-receipts"):
        granted = set().union(*(acts(st) for st in t[name]["Statement"]))
        assert not NEVER & granted, name
        assert all(st["Effect"] == "Allow" for st in t[name]["Statement"])


def test_receipts_expire_only_after_their_retention() -> None:
    rule = templates()["receipt-bucket-lifecycle"]["Rules"][0]
    assert rule["Filter"] == {"Prefix": "receipts/"}
    assert rule["Expiration"] == {"Days": "<RECEIPT_EXPIRY_DAYS>"}
    text = RUNBOOK.read_text()
    assert "`<RECEIPT_EXPIRY_DAYS>` | `<RECEIPT_RETENTION_DAYS>` + 1" in text


@pytest.mark.parametrize(
    "value", [r"\b\d{12}\b", r"arn:aws:iam::\d", r"nlw-(staging|production)-deletion-receipts-\d"]
)
def test_no_real_identifier_is_written_down(value: str) -> None:
    assert re.search(value, RUNBOOK.read_text()) is None
