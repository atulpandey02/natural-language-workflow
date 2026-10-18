"""The unattended retention identity (ADR-038): its templates parsed, pinned
and checked against the reviewed D6 and O-3 documents. NOT RUN against AWS."""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = ROOT / "docs/runbooks/dataset-retention-identity-provisioning.md"
D6 = ROOT / "docs/runbooks/dataset-s3-provisioning.md"
RECEIPTS = ROOT / "docs/runbooks/deletion-receipt-log-provisioning.md"
TEMPLATE = re.compile(r"<!-- template: ([a-z0-9-]+) -->\n```json\n(.*?)```", re.S)

OPERATOR = "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator"
RETENTION = "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-retention"
BOOTSTRAP = "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap"
API = "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api"
INGEST = "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest"
BUCKET = "arn:aws:s3:::<BUCKET>"


def templates(path: Path = RUNBOOK) -> dict[str, Any]:
    found = TEMPLATE.findall(path.read_text())
    assert len({n for n, _ in found}) == len(found)
    return {n: json.loads(raw) for n, raw in found}


def sids(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["Sid"]: s for s in doc["Statement"]}


def acts(s: dict[str, Any]) -> set[str]:
    a = s["Action"]
    return {a} if isinstance(a, str) else set(a)


def res(s: dict[str, Any]) -> set[str]:
    r = s.get("Resource", [])
    return {r} if isinstance(r, str) else set(r)


def test_the_runbook_holds_exactly_the_reviewed_templates() -> None:
    assert sorted(templates()) == [
        "dataset-bucket-policy-with-retention",
        "role-bootstrap-with-retention",
        "role-dataset-retention",
        "trust-retention",
    ]
    assert not set(templates()) & set(templates(D6))
    assert not set(templates()) & set(templates(RECEIPTS))


def test_the_bucket_policy_differs_from_d6_only_by_the_retention_exception() -> None:
    d6 = copy.deepcopy(templates(D6)["dataset-bucket-policy"])
    ours = templates()["dataset-bucket-policy-with-retention"]
    exc = sids(ours)["DenyDeleteExceptOperator"]
    assert exc["Condition"] == {"ArnNotEquals": {"aws:PrincipalArn": [OPERATOR, RETENTION]}}
    sids(d6)["DenyDeleteExceptOperator"]["Condition"]["ArnNotEquals"]["aws:PrincipalArn"].append(
        RETENTION
    )
    assert ours == d6


def test_the_bootstrap_role_differs_from_d6_only_by_the_retention_role() -> None:
    d6 = copy.deepcopy(templates(D6)["role-bootstrap"])
    ours = templates()["role-bootstrap-with-retention"]
    s = sids(ours)
    assert s["AssumeRuntimeRolesOnly"]["Resource"] == [API, INGEST, RETENTION]
    assert s["NeverAssumeAnyOtherRole"]["NotResource"] == [API, INGEST, RETENTION]
    for sid in ("AssumeRuntimeRolesOnly",):
        sids(d6)[sid]["Resource"].append(RETENTION)
    sids(d6)["NeverAssumeAnyOtherRole"]["NotResource"].append(RETENTION)
    assert ours == d6
    # Still never the operator, the restore role or any other.
    assert OPERATOR not in json.dumps(ours)


def test_only_the_host_assumes_the_retention_role_with_its_fixed_session_name() -> None:
    (stmt,) = templates()["trust-retention"]["Statement"]
    assert stmt == {
        "Sid": "BootstrapWithRetentionSessionName",
        "Effect": "Allow",
        "Principal": {"AWS": BOOTSTRAP},
        "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"sts:RoleSessionName": "nlw-<ENV>-retention"}},
    }


def test_the_retention_role_may_only_list_purge_and_handle_receipts() -> None:
    doc = templates()["role-dataset-retention"]
    allowed = {
        (sid, frozenset(acts(s)), frozenset(res(s)))
        for sid, s in sids(doc).items()
        if s["Effect"] == "Allow"
    }
    assert {a for _, actions, _ in allowed for a in actions} == {
        "s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads",
        "s3:DeleteObjectVersion", "s3:AbortMultipartUpload", "s3:PutObject",
        "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention",
        "s3:GetBucketObjectLockConfiguration", "iam:GetRole",
    }  # fmt: skip
    for sid, actions, resources in allowed:
        if actions & {"s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"}:
            assert resources == {"arn:aws:s3:::<RECEIPT_BUCKET>/receipts/*"}, sid
        if actions & {"s3:DeleteObjectVersion", "s3:AbortMultipartUpload"}:
            assert resources == {f"{BUCKET}/versions/*"}, sid
        assert not any(a.startswith(("kms:", "backup:", "sts:")) for a in actions), sid
    s = sids(doc)
    assert s["ConfirmOwnRolePath"]["Resource"] == RETENTION
    assert acts(s["NeverReadOrWriteDatasetContent"]) >= {"s3:GetObject", "s3:PutObject"}
    assert res(s["NeverReadOrWriteDatasetContent"]) == {f"{BUCKET}/*"}
    assert s["NeverUseAKey"] == {
        "Sid": "NeverUseAKey", "Effect": "Deny", "Action": "kms:*", "Resource": "*",
    }  # fmt: skip
    assert res(s["NeverRestoreBucket"]) == {
        "arn:aws:s3:::<RESTORE_BUCKET>", "arn:aws:s3:::<RESTORE_BUCKET>/*",
    }  # fmt: skip
    assert {"s3:BypassGovernanceRetention", "s3:PutObjectRetention", "s3:PutBucket*"} <= acts(
        s["NeverAlterReceiptsOrConfiguration"]
    )
    # Negated conditions on keys a request may not carry are not used here: an
    # absent key would make such a deny match every request.
    for st in doc["Statement"]:
        if st["Effect"] == "Deny":
            assert "Condition" not in st, st["Sid"]


def test_its_receipt_grants_are_the_operators_except_its_own_role_path() -> None:
    operator = sids(templates(RECEIPTS)["role-operator-receipts"])
    ours = sids(templates()["role-dataset-retention"])
    for sid in ("WriteReceiptsOnce", "ReadReceipts", "ListReceipts", "ConfirmRetention"):
        assert ours[sid] == operator[sid], sid
    assert operator["ConfirmOwnRolePath"]["Resource"] == OPERATOR
    assert {**ours["ConfirmOwnRolePath"], "Resource": OPERATOR} == operator["ConfirmOwnRolePath"]


def test_the_refresher_session_names_are_the_ones_the_trust_policies_accept() -> None:
    """Every role the refresher assumes trusts the bootstrap role only under one
    fixed session name; a different name is refused by AWS."""
    spec = importlib.util.spec_from_file_location(
        "nlw_aws_credential_refresh_t", ROOT / "scripts/ops/nlw_aws_credential_refresh.py"
    )
    assert spec is not None and spec.loader is not None
    refresher = importlib.util.module_from_spec(spec)
    sys.modules["nlw_aws_credential_refresh_t"] = refresher
    spec.loader.exec_module(refresher)
    trusts = {**templates(D6), **templates()}
    assert set(refresher.SERVICES) == {"api", "ingest", "retention"}
    for service in refresher.SERVICES:
        (stmt,) = trusts[f"trust-{service}"]["Statement"]
        assert stmt["Principal"] == {"AWS": BOOTSTRAP}
        expected = stmt["Condition"]["StringEquals"]["sts:RoleSessionName"]
        assert refresher.session_name("<ENV>", service) == expected, service


@pytest.mark.parametrize("value", [r"\b\d{12}\b", r"arn:aws:iam::\d"])
def test_no_real_identifier_is_written_down(value: str) -> None:
    assert re.search(value, RUNBOOK.read_text()) is None
