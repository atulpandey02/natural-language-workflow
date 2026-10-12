"""Contract tests for the NOT RUN dataset S3 provisioning templates (ADR-033).

Every JSON template in docs/runbooks/dataset-s3-provisioning.md is parsed and
checked for the security properties the ADR relies on: SSE-KMS required on
every creation request (missing and wrong values denied separately, no
``…IfExists``), write-once, operator-only deletion, read-only ingest, a
bootstrap role that cannot reach the operator role, a data-event trail scoped
to the dataset bucket, confused-deputy protection on audit delivery, and no
dataset role able to touch the audit records. Templates must contain
placeholders only, never real identifiers or secrets."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = ROOT / "docs" / "runbooks" / "dataset-s3-provisioning.md"
TEMPLATE = re.compile(r"<!-- template: ([a-z0-9-]+) -->\n```json\n(.*?)```", re.S)
EXPECTED = {
    "dataset-kms-key-statement",
    "dataset-bucket-lifecycle",
    "dataset-bucket-policy",
    "role-bootstrap",
    "role-api",
    "role-ingest",
    "role-operator",
    "trail-advanced-event-selectors",
    "audit-kms-key-statements",
    "audit-bucket-policy",
}
ROLES = ("role-bootstrap", "role-api", "role-ingest", "role-operator")


def _text() -> str:
    return RUNBOOK.read_text()


def _templates() -> dict[str, Any]:
    return {name: json.loads(body) for name, body in TEMPLATE.findall(_text())}


def _statements(doc: Any) -> list[dict[str, Any]]:
    if isinstance(doc, list):
        return doc
    return list(doc["Statement"]) if "Statement" in doc else [doc]


def _by_sid(doc: Any) -> dict[str, dict[str, Any]]:
    return {s["Sid"]: s for s in _statements(doc) if "Sid" in s}


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else [v]


def _actions(s: dict[str, Any]) -> set[str]:
    return set(_as_list(s.get("Action", [])))


def _walk(o: Any) -> list[str]:
    if isinstance(o, dict):
        return [x for k, v in o.items() for x in (k, *_walk(v))]
    if isinstance(o, list):
        return [x for v in o for x in _walk(v)]
    return [str(o)]


def test_every_json_block_is_a_named_template_and_parses() -> None:
    assert len(re.findall(r"```json\n", _text())) == len(TEMPLATE.findall(_text()))
    assert set(_templates()) == EXPECTED


def test_templates_hold_placeholders_only_never_real_identifiers_or_secrets() -> None:
    text = _text()
    for pattern in (
        r"\b\d{12}\b",  # account id
        r"AKIA[0-9A-Z]{16}",  # access key id
        r"aws_secret_access_key|AWS_SECRET_ACCESS_KEY\s*=",
        r"arn:aws:iam::\d",
        r"arn:aws:kms:[a-z0-9-]+:\d",
        r"key/[0-9a-f]{8}-[0-9a-f]{4}-",
    ):
        assert not re.search(pattern, text), pattern
    for name, doc in _templates().items():
        for s in _walk(doc):
            if s.startswith("arn:aws:s3:::"):
                assert "<" in s, (name, s)  # every bucket ARN is a placeholder


# --- encryption ----------------------------------------------------------------------------


def test_every_creation_request_must_name_sse_kms_and_the_environment_key() -> None:
    sids = _by_sid(_templates()["dataset-bucket-policy"])
    expected = {
        "DenyMissingSseAlgorithmHeader": ("Null", "s3:x-amz-server-side-encryption", "true"),
        "DenyMissingSseKmsKeyHeader": (
            "Null", "s3:x-amz-server-side-encryption-aws-kms-key-id", "true",
        ),
        "DenyWrongSseAlgorithm": (
            "StringNotEquals", "s3:x-amz-server-side-encryption", "aws:kms",
        ),
        "DenyWrongSseKmsKey": (
            "StringNotEquals", "s3:x-amz-server-side-encryption-aws-kms-key-id", "<KEY_ARN>",
        ),
    }  # fmt: skip
    for sid, (op, key, value) in expected.items():
        s = sids[sid]
        assert s["Effect"] == "Deny" and s["Principal"] == "*", sid
        assert _actions(s) == {"s3:PutObject"}, sid
        assert s["Resource"] == "arn:aws:s3:::<BUCKET>/*", sid  # every object, no exception
        assert s["Condition"] == {op: {key: value}}, sid  # one condition each: auditable


def test_no_negated_ifexists_operator_and_no_default_encryption_fallback_claim() -> None:
    for name, doc in _templates().items():
        for s in _statements(doc):
            for op in s.get("Condition", {}):
                assert not op.endswith("IfExists"), (name, s.get("Sid"), op)
    prose = _text().lower()
    assert "still applies when the header is absent" not in prose
    assert "never a fallback" in prose or "no request ever relies on the default" in prose


def test_the_dataset_bucket_policy_is_deny_only_and_keeps_write_once_and_tls() -> None:
    doc = _templates()["dataset-bucket-policy"]
    assert {s["Effect"] for s in _statements(doc)} == {"Deny"}
    sids = _by_sid(doc)
    cond = sids["DenyUnconditionalCreate"]["Condition"]
    assert cond == {
        "Null": {"s3:if-none-match": "true"},
        "Bool": {"s3:ObjectCreationOperation": "true"},
    }
    assert sids["DenyNonTLS"]["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
    deletes = sids["DenyDeleteExceptOperator"]
    assert _actions(deletes) == {"s3:DeleteObject", "s3:DeleteObjectVersion"}
    assert deletes["Condition"]["ArnNotEquals"]["aws:PrincipalArn"] == [
        "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator"
    ]


# --- roles ---------------------------------------------------------------------------------


def _allowed(doc: Any) -> set[str]:
    return {a for s in _statements(doc) if s["Effect"] == "Allow" for a in _actions(s)}


def test_role_capabilities_match_the_identity_model() -> None:
    t = _templates()
    assert _allowed(t["role-bootstrap"]) == {"sts:AssumeRole"}
    assume = next(s for s in _statements(t["role-bootstrap"]) if s["Effect"] == "Allow")
    assert sorted(assume["Resource"]) == [
        "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api",
        "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest",
    ]  # never the operator role
    assert _allowed(t["role-ingest"]) == {"s3:GetObject", "kms:Decrypt"}
    api = _allowed(t["role-api"])
    assert api == {
        "s3:PutObject", "s3:AbortMultipartUpload", "s3:GetObject", "s3:GetObjectAttributes",
        "kms:GenerateDataKey", "kms:Decrypt",
    }  # fmt: skip
    for role in ROLES:
        allowed = _allowed(t[role])
        deletes = {a for a in allowed if a.startswith("s3:Delete")}
        assert deletes == ({"s3:DeleteObjectVersion"} if role == "role-operator" else set()), role
        assert not any(a.startswith("s3:List") for a in allowed) or role == "role-operator"
        assert "s3:*" not in allowed and "kms:*" not in allowed, role


@pytest.mark.parametrize("role", ROLES)
def test_every_dataset_role_is_denied_the_audit_trail_bucket_and_key(role: str) -> None:
    sids = _by_sid(_templates()[role])
    touch = sids["NeverTouchAudit"]
    assert touch["Effect"] == "Deny"
    assert _actions(touch) == {"cloudtrail:*", "s3:*", "kms:*"}
    assert set(touch["Resource"]) == {
        "<TRAIL_ARN>",
        "arn:aws:s3:::<AUDIT_BUCKET>",
        "arn:aws:s3:::<AUDIT_BUCKET>/*",
        "<AUDIT_KEY_ARN>",
    }
    alter = sids["NeverAlterAnyTrail"]
    assert alter["Effect"] == "Deny" and alter["Resource"] == "*"
    assert {
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail",
        "cloudtrail:PutEventSelectors",
    } <= _actions(alter)


# --- audit ---------------------------------------------------------------------------------


def test_the_trail_records_object_reads_and_writes_for_the_dataset_bucket_only() -> None:
    (selector,) = _templates()["trail-advanced-event-selectors"]
    fields = {f["Field"]: f for f in selector["FieldSelectors"]}
    assert set(fields) == {"eventCategory", "resources.type", "resources.ARN"}  # no readOnly
    assert fields["eventCategory"]["Equals"] == ["Data"]
    assert fields["resources.type"]["Equals"] == ["AWS::S3::Object"]
    assert fields["resources.ARN"] == {
        "Field": "resources.ARN",
        "StartsWith": ["arn:aws:s3:::<BUCKET>/"],
    }


def test_audit_delivery_has_confused_deputy_protection() -> None:
    t = _templates()
    service = [
        s
        for name in ("audit-bucket-policy", "audit-kms-key-statements")
        for s in _statements(t[name])
        if s.get("Principal") == {"Service": "cloudtrail.amazonaws.com"}
    ]
    assert len(service) == 4
    for s in service:
        eq = s["Condition"]["StringEquals"]
        assert eq["aws:SourceArn"] == "<TRAIL_ARN>" and eq["aws:SourceAccount"] == "<ACCOUNT>"
    write = _by_sid(t["audit-bucket-policy"])["CloudTrailWriteThisTrailOnly"]
    assert _actions(write) == {"s3:PutObject"}
    assert write["Resource"].startswith("arn:aws:s3:::<AUDIT_BUCKET>/dataset-data-events/")


def test_the_audit_bucket_denies_dataset_roles_and_record_deletion() -> None:
    sids = _by_sid(_templates()["audit-bucket-policy"])
    roles = sids["DenyDatasetRoles"]
    assert roles["Effect"] == "Deny" and _actions(roles) == {"s3:*"}
    named = roles["Condition"]["ArnLike"]["aws:PrincipalArn"]
    for r in ("api", "ingest", "bootstrap", "operator"):
        assert f"arn:aws:iam::<ACCOUNT>:role/nlw-*-dataset-{r}" in named
    deletion = sids["DenyRecordDeletionExceptAuditAdmin"]
    assert {"s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention"} <= (
        _actions(deletion)
    )
    assert sids["DenyNonTLS"]["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
    text = _text()
    assert "Object Lock:** enabled at creation" in text and "Bucket Key off" in text


def test_the_proof_checklist_covers_encryption_and_audit_cases() -> None:
    text = _text()
    for case in (
        "E-ALG-MISSING", "E-KEY-MISSING", "E-ALG-WRONG", "E-KEY-WRONG", "E-OK", "E-MPU",
        "A-API-META", "A-INGEST-READ", "A-DENIED", "A-WRITE", "A-TAMPER", "A-VALIDATE",
        "A-SCOPE",
    ):  # fmt: skip
        assert f"**{case}:**" in text, case


# --- multipart cleanup permissions (review finding F5) -------------------------------------

# From the AWS Service Authorization Reference, Amazon S3 actions table
# (https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3.html,
# read 2026-10-12): the resource type each action takes and whether ``s3:prefix``
# is among its condition keys. Only actions the dataset templates use.
S3_ACTIONS = {
    "s3:ListBucket": ("bucket", True),
    "s3:ListBucketVersions": ("bucket", True),
    "s3:ListBucketMultipartUploads": ("bucket", False),
    "s3:ListMultipartUploadParts": ("object", False),
    "s3:AbortMultipartUpload": ("object", False),
    "s3:DeleteObjectVersion": ("object", False),
    "s3:DeleteObject": ("object", False),
    "s3:GetObject": ("object", False),
    "s3:GetObjectVersion": ("object", False),
    "s3:GetObjectAttributes": ("object", False),
    "s3:PutObject": ("object", False),
}
BUCKET_ARN = "arn:aws:s3:::<BUCKET>"


def _allows(doc: Any, action: str) -> list[dict[str, Any]]:
    return [s for s in _statements(doc) if s["Effect"] == "Allow" and action in _actions(s)]


def test_the_operator_may_list_in_progress_uploads_on_exactly_its_bucket() -> None:
    """1. What AWS needs: ``ListBucketMultipartUploads`` on the bucket ARN,
    with no condition it cannot satisfy."""
    (grant,) = _allows(_templates()["role-operator"], "s3:ListBucketMultipartUploads")
    assert grant["Sid"] == "ListInProgressUploads"
    assert _actions(grant) == {"s3:ListBucketMultipartUploads"}
    assert grant["Resource"] == BUCKET_ARN  # the exact environment bucket, not "*" or "/*"
    assert "Condition" not in grant and "NotAction" not in grant and "NotResource" not in grant


def test_no_statement_conditions_an_action_on_a_key_it_does_not_support() -> None:
    """2. ``s3:prefix`` appears only with actions AWS evaluates it for: an
    unsupported key in an Allow never matches (the action is silently denied),
    and in a Deny it would silently never apply."""
    for name, doc in _templates().items():
        for s in _statements(doc):
            keys = {k for cond in s.get("Condition", {}).values() for k in cond}
            if "s3:prefix" not in keys:
                continue
            for action in _actions(s):
                assert action in S3_ACTIONS and S3_ACTIONS[action][1], (name, s.get("Sid"), action)


def test_bucket_and_object_actions_name_the_matching_resource_type() -> None:
    for name, doc in _templates().items():
        for s in _statements(doc):
            if s.get("Effect") != "Allow":
                continue
            kinds = {S3_ACTIONS[a][0] for a in _actions(s) if a in S3_ACTIONS}
            if not kinds:
                continue  # no action from the table (for example the audit bucket's ACL check)
            for r in _as_list(s.get("Resource", [])):
                if not r.startswith("arn:aws:s3:::"):
                    continue
                assert kinds == {"object" if "/" in r[len("arn:aws:s3:::"):] else "bucket"}, (
                    name, s.get("Sid"), r)  # fmt: skip


def test_the_prose_never_claims_the_multipart_listing_is_prefix_bounded() -> None:
    for path in (RUNBOOK, ROOT / "docs" / "adr" / "ADR-033-s3-dataset-object-storage.md"):
        text = path.read_text()
        assert "Bounded listing (prefix-conditioned)" not in text, path
        assert "ListBucketMultipartUploads" in text and "s3:prefix" in text, path
    text = _text()
    assert "lists **no**\n  `s3:prefix` condition key for `s3:ListBucketMultipartUploads`" in text
    assert "**O-MPU-LIST:**" in text and "**O-MPU-ABORT:**" in text


def test_the_operator_gains_no_object_data_permission() -> None:
    """7. The fix adds a bucket-level listing only: every object action stays
    exactly as before, under ``versions/*``, and nothing lists parts."""
    op = _templates()["role-operator"]
    assert _allowed(op) == {
        "s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads",
        "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes",
        "s3:DeleteObjectVersion", "s3:AbortMultipartUpload", "kms:Decrypt",
    }  # fmt: skip
    sids = _by_sid(op)
    assert sids["PurgeAndVerify"]["Resource"] == "arn:aws:s3:::<BUCKET>/versions/*"
    assert _actions(sids["PurgeAndVerify"]) == {
        "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes",
        "s3:DeleteObjectVersion", "s3:AbortMultipartUpload",
    }  # fmt: skip
    assert sids["ListVersionsBounded"]["Condition"] == {"StringLike": {"s3:prefix": ["versions/*"]}}
    assert _actions(sids["ListVersionsBounded"]) == {"s3:ListBucket", "s3:ListBucketVersions"}
    for s in _statements(op):
        objects = {a for a in _actions(s) if a in S3_ACTIONS and S3_ACTIONS[a][0] == "object"}
        if s["Effect"] == "Allow" and objects:
            assert s["Resource"] == "arn:aws:s3:::<BUCKET>/versions/*", s["Sid"]
    assert "s3:ListMultipartUploadParts" not in _allowed(op)


# The reviewed JSON of these templates on origin/main at eb42250, before this
# fix: any change to them is a deliberate, reviewed edit of the fixture.
UNCHANGED = json.loads(
    (ROOT / "tests" / "fixtures" / "dataset_s3_unchanged_templates.json").read_text()
)["templates"]


def test_the_unchanged_fixture_covers_every_other_template() -> None:
    assert set(UNCHANGED) == set(_templates()) - {"role-operator"}


@pytest.mark.parametrize("name", sorted(UNCHANGED))
def test_every_template_but_the_operators_is_unchanged(name: str) -> None:
    """8. Only the operator template changed. The worker, scheduler and
    dispatcher have no AWS role at all, and still get no AWS mount."""
    assert _templates()[name] == UNCHANGED[name], name


def test_worker_scheduler_and_dispatcher_still_get_no_aws_role_or_mount() -> None:
    assert not {n for n in _templates() if re.search(r"worker|scheduler|dispatch", n)}
    assert "The dispatcher, worker, scheduler and web containers get **no** AWS mount." in _text()
    assert set(ROLES) == {n for n in _templates() if n.startswith("role-")}
