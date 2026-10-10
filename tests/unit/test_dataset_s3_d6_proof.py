"""Contract tests for the NOT RUN O-2/D6 AWS proof package (ADR-033 D6).

Two documents are parsed: the provisioning templates
(docs/runbooks/dataset-s3-provisioning.md) and the ordered proof procedure
(docs/runbooks/dataset-s3-d6-proof.md). Every check is a function returning
the list of violations, so each one runs twice: against the committed
documents, where it must find nothing, and against a deliberately weakened
copy (the negative controls at the end), where it must find the weakness.

These are structural checks of JSON and shell text. They do not show that AWS
accepts or evaluates the policies as read; only the proof can.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from nlw.storage import s3_credentials as creds

ROOT = Path(__file__).resolve().parents[2]
RUNBOOKS = ROOT / "docs" / "runbooks"
PROVISIONING = RUNBOOKS / "dataset-s3-provisioning.md"
PROOF = RUNBOOKS / "dataset-s3-d6-proof.md"
DECISIONS = RUNBOOKS / "dataset-s3-d6-owner-decisions.md"
REVIEW = ROOT / "docs" / "security" / "o2-aws-policy-review.md"
TEMPLATE = re.compile(r"<!-- template: ([a-z0-9-]+) -->\n```json\n(.*?)```", re.S)
FILE_BLOCK = re.compile(r"<!-- file: ([a-z0-9.-]+) -->\n```[a-z]+\n(.*?)```", re.S)
BASH_BLOCK = re.compile(r"```bash\n(.*?)```", re.S)
LABEL = re.compile(
    r"\*\*(?P<id>P\d\d-\d\d|X\d\d) · (?P<cls>READ-ONLY|MUTATING|HOST|LOCAL)"
    r" · (?P<where>workstation|proof instance)(?P<deny> · EXPECT-DENIED)?\*\*"
)
AWS_OP = re.compile(r"(?<![\w/-])aws\s+([a-z][a-z0-9-]*)\s+([a-z][a-z0-9-]*)")
READ_OPS = re.compile(
    r"^(get-.*|list-.*|describe-.*|head-.*|lookup-.*|simulate-.*|validate-logs|wait|get"
    r"|export-credentials|assume-role)$"
)
SSE_KEY_ID = "s3:x-amz-server-side-encryption-aws-kms-key-id"
ROLES = ("role-bootstrap", "role-api", "role-ingest", "role-operator")
DATA_ROLES = ("role-api", "role-ingest", "role-operator")
ACCOUNT_ROLE = "arn:aws:iam::<ACCOUNT>:role/"
KMS_USE = {"kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:ReEncryptFrom", "kms:ReEncryptTo",
           "kms:GenerateDataKey", "kms:GenerateDataKey*", "kms:GenerateDataKeyWithoutPlaintext",
           "kms:*"}  # fmt: skip

Templates = dict[str, Any]


# --- parsing --------------------------------------------------------------------------------


def load_templates(text: str | None = None) -> Templates:
    body = PROVISIONING.read_text() if text is None else text
    return {name: json.loads(raw) for name, raw in TEMPLATE.findall(body)}


def proof_text() -> str:
    return PROOF.read_text()


def statements(doc: Any) -> list[dict[str, Any]]:
    if isinstance(doc, list):
        return doc
    return list(doc["Statement"]) if "Statement" in doc else [doc]


def by_sid(doc: Any) -> dict[str, dict[str, Any]]:
    return {s["Sid"]: s for s in statements(doc) if "Sid" in s}


def as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else [v]


def actions(s: dict[str, Any]) -> set[str]:
    return set(as_list(s.get("Action", [])))


def allows(doc: Any) -> list[dict[str, Any]]:
    return [s for s in statements(doc) if s["Effect"] == "Allow"]


def allowed_actions(doc: Any) -> set[str]:
    return {a for s in allows(doc) for a in actions(s)}


def principals(s: dict[str, Any]) -> set[str]:
    p = s.get("Principal", {})
    if p == "*":
        return {"*"}
    return {x for v in p.values() for x in as_list(v)}


def role(name: str) -> str:
    return f"{ACCOUNT_ROLE}nlw-<ENV>-dataset-{name}"


def labelled_blocks(text: str) -> list[dict[str, Any]]:
    """Every ```bash block with the label that precedes it (None if missing)."""
    out, previous_end = [], 0
    for block in BASH_BLOCK.finditer(text):
        labels = list(LABEL.finditer(text, previous_end, block.start()))
        label = labels[-1].groupdict() if labels else None
        body = block.group(1).replace("\\\n", " ")
        out.append({"label": label, "body": body, "start": block.start()})
        previous_end = block.end()
    return out


def aws_ops(body: str) -> list[tuple[str, str, str]]:
    """(service, operation, joined line) for each AWS CLI call in a block."""
    found = []
    for line in body.splitlines():
        if line.lstrip().startswith("#"):
            continue
        found += [(m.group(1), m.group(2), line) for m in AWS_OP.finditer(line)]
    return found


def is_read(op: str) -> bool:
    return bool(READ_OPS.match(op))


# --- B. policy validation --------------------------------------------------------------------


def least_privilege_violations(t: Templates) -> list[str]:
    v = []
    for name in (*ROLES, "role-audit-admin", "role-audit-reader"):
        for s in allows(t[name]):
            sid = f"{name}/{s.get('Sid')}"
            if "NotAction" in s or "NotResource" in s:
                v.append(f"{sid}: NotAction/NotResource in an Allow")
            for a in actions(s):
                if a == "*" or a.endswith(":*"):
                    v.append(f"{sid}: wildcard action {a}")
            for r in as_list(s.get("Resource", [])):
                scoped = (
                    r.startswith(
                        ("arn:aws:s3:::<BUCKET>", "arn:aws:s3:::<AUDIT_BUCKET>", ACCOUNT_ROLE)
                    )
                    or r in ("<KEY_ARN>", "<AUDIT_KEY_ARN>", "<TRAIL_ARN>")
                    or r.startswith("arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-")
                )
                unscoped_ok = r == "*" and (
                    actions(s) <= {"cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
                                   "cloudtrail:ListPublicKeys"}
                    or ("Condition" in s and actions(s) <= {"kms:CreateKey", "kms:TagResource"})
                )  # fmt: skip
                if not (scoped or unscoped_ok):
                    v.append(f"{sid}: unscoped resource {r}")
    api = allowed_actions(t["role-api"])
    if api != {"s3:PutObject", "s3:AbortMultipartUpload", "s3:GetObject",
               "s3:GetObjectAttributes", "kms:GenerateDataKey", "kms:Decrypt"}:  # fmt: skip
        v.append(f"role-api grants {sorted(api)}")
    if allowed_actions(t["role-ingest"]) != {"s3:GetObject", "kms:Decrypt"}:
        v.append("role-ingest grants more than GetObject and Decrypt")
    if allowed_actions(t["role-bootstrap"]) != {"sts:AssumeRole"}:
        v.append("role-bootstrap grants more than sts:AssumeRole")
    return v


def cross_environment_violations(t: Templates) -> list[str]:
    v = []
    deny = by_sid(t["dataset-bucket-policy"]).get("DenyOtherEnvironmentRoles")
    if not (
        deny
        and deny["Effect"] == "Deny"
        and deny["Principal"] == "*"
        and actions(deny) == {"s3:*"}
        and set(as_list(deny["Resource"])) == {"arn:aws:s3:::<BUCKET>", "arn:aws:s3:::<BUCKET>/*"}
        and deny.get("Condition")
        == {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/nlw-<OTHER_ENV>-*"}}
    ):
        v.append("dataset bucket policy lacks DenyOtherEnvironmentRoles")
    for name in ROLES:
        sids = by_sid(t[name])
        if name == "role-bootstrap":
            nd = sids.get("NeverDataPlane", {})
            if not (nd.get("Effect") == "Deny" and actions(nd) == {"s3:*", "kms:*"}
                    and nd.get("Resource") == "*" and "Condition" not in nd):  # fmt: skip
                v.append("role-bootstrap lacks an unconditional S3 and KMS deny")
            continue
        other = sids.get("NeverOtherEnvironment", {})
        if not (
            other.get("Effect") == "Deny"
            and {"s3:*"} <= actions(other)
            and set(as_list(other.get("Resource", [])))
            >= {"arn:aws:s3:::nlw-<OTHER_ENV>-*", "arn:aws:s3:::nlw-<OTHER_ENV>-*/*"}
            and "Condition" not in other
        ):
            v.append(f"{name} lacks an unconditional deny on the other environment's buckets")
        keys = sids.get("NeverOtherEnvironmentKeys", {})
        if not (
            keys.get("Effect") == "Deny"
            and actions(keys) == {"kms:*"}
            and keys.get("Resource") == "arn:aws:kms:us-east-1:<ACCOUNT>:key/*"
            and keys.get("Condition") == {"StringNotEquals": {"aws:ResourceTag/nlw-env": "<ENV>"}}
        ):
            v.append(f"{name} lacks a deny on keys not tagged for its environment")
    return v


def sse_kms_violations(t: Templates) -> list[str]:
    v = []
    sids = by_sid(t["dataset-bucket-policy"])
    expected = {
        "DenyMissingSseAlgorithmHeader": {"Null": {"s3:x-amz-server-side-encryption": "true"}},
        "DenyMissingSseKmsKeyHeader": {
            "Null": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "true"}
        },
        "DenyWrongSseAlgorithm": {
            "StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}
        },
        "DenyWrongSseKmsKey": {
            "StringNotEquals": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "<KEY_ARN>"}
        },
    }
    for sid, cond in expected.items():
        s = sids.get(sid)
        if not (
            s
            and s["Effect"] == "Deny"
            and s["Principal"] == "*"
            and actions(s) == {"s3:PutObject"}
            and s["Resource"] == "arn:aws:s3:::<BUCKET>/*"
            and s.get("Condition") == cond
        ):
            v.append(f"{sid} missing or weakened")
    return v


def conditional_write_violations(t: Templates) -> list[str]:
    v = []
    sids = by_sid(t["dataset-bucket-policy"])
    create = sids.get("DenyUnconditionalCreate", {})
    if not (
        create.get("Effect") == "Deny"
        and create.get("Principal") == "*"
        and actions(create) == {"s3:PutObject"}
        and create.get("Resource") == "arn:aws:s3:::<BUCKET>/versions/*"
        and create.get("Condition")
        == {"Null": {"s3:if-none-match": "true"}, "Bool": {"s3:ObjectCreationOperation": "true"}}
    ):
        v.append("DenyUnconditionalCreate missing or weakened")
    copy_deny = sids.get("DenyServerSideCopy", {})
    if not (
        copy_deny.get("Effect") == "Deny"
        and actions(copy_deny) == {"s3:PutObject"}
        and copy_deny.get("Resource") == "arn:aws:s3:::<BUCKET>/*"
        and copy_deny.get("Condition") == {"Null": {"s3:x-amz-copy-source": "false"}}
    ):
        v.append("DenyServerSideCopy missing or weakened")
    return v


def runtime_delete_violations(t: Templates) -> list[str]:
    v = []
    for name in ROLES:
        deletes = {a for a in allowed_actions(t[name]) if a.startswith("s3:Delete")}
        want = {"s3:DeleteObjectVersion"} if name == "role-operator" else set()
        if deletes != want:
            v.append(f"{name} may delete: {sorted(deletes)}")
    deny = by_sid(t["dataset-bucket-policy"]).get("DenyDeleteExceptOperator", {})
    if not (
        deny.get("Effect") == "Deny"
        and actions(deny) == {"s3:DeleteObject", "s3:DeleteObjectVersion"}
        and deny.get("Condition", {}).get("ArnNotEquals", {}).get("aws:PrincipalArn")
        == [role("operator")]
    ):
        v.append("the bucket does not reserve deletion to the operator")
    return v


def instance_role_violations(t: Templates) -> list[str]:
    v = []
    boot = t["role-bootstrap"]
    runtime = sorted([role("api"), role("ingest")])
    for s in allows(boot):
        if sorted(as_list(s.get("Resource", []))) != runtime:
            v.append(f"bootstrap may assume {as_list(s.get('Resource'))}")
    never = by_sid(boot).get("NeverAssumeAnyOtherRole", {})
    if not (never.get("Effect") == "Deny" and actions(never) == {"sts:AssumeRole"}
            and sorted(as_list(never.get("NotResource", []))) == runtime):  # fmt: skip
        v.append("bootstrap lacks an explicit deny on every other role")
    trust = t["trust-human-mfa"]
    for s in allows(trust):
        if principals(s) != {"<HUMAN_PRINCIPAL_ARNS>"}:
            v.append(f"human trust allows {sorted(principals(s))}")
    machines = by_sid(trust).get("DenyMachineRoles", {})
    named = set(machines.get("Condition", {}).get("ArnLike", {}).get("aws:PrincipalArn", []))
    for r in ("bootstrap", "api", "ingest"):
        if f"{ACCOUNT_ROLE}nlw-*-dataset-{r}" not in named or machines.get("Effect") != "Deny":
            v.append(f"human trust does not deny the {r} role")
    for name, session in (("trust-api", "api"), ("trust-ingest", "ingest")):
        (s,) = allows(t[name])
        if principals(s) != {role("bootstrap")} or s.get("Condition") != {
            "StringEquals": {"sts:RoleSessionName": f"nlw-<ENV>-{session}"}
        }:
            v.append(f"{name} is not bootstrap-only with session nlw-<ENV>-{session}")
    if principals(allows(t["trust-bootstrap"])[0]) != {"ec2.amazonaws.com"}:
        v.append("bootstrap is not trusted by EC2 only")
    return v


def mfa_violations(t: Templates) -> list[str]:
    v = []
    trust = t["trust-human-mfa"]
    (allow,) = allows(trust)
    if allow.get("Condition", {}).get("Bool") != {"aws:MultiFactorAuthPresent": "true"}:
        v.append("human trust does not require MFA")
    sids = by_sid(trust)
    if sids.get("DenyWithoutMfaContext", {}).get("Condition") != {
        "Null": {"aws:MultiFactorAuthPresent": "true"}
    }:
        v.append("human trust does not deny a session without MFA context")
    if sids.get("DenyWithoutMfa", {}).get("Condition") != {
        "Bool": {"aws:MultiFactorAuthPresent": "false"}
    }:
        v.append("human trust does not deny a session without MFA")
    return v


def audit_tamper_violations(t: Templates) -> list[str]:
    v = []
    audit = {"<TRAIL_ARN>", "arn:aws:s3:::<AUDIT_BUCKET>", "arn:aws:s3:::<AUDIT_BUCKET>/*",
             "<AUDIT_KEY_ARN>"}  # fmt: skip
    for name in ROLES:
        sids = by_sid(t[name])
        touch = sids.get("NeverTouchAudit", {})
        if not (touch.get("Effect") == "Deny"
                and actions(touch) == {"cloudtrail:*", "s3:*", "kms:*"}
                and set(as_list(touch.get("Resource", []))) == audit):  # fmt: skip
            v.append(f"{name} lacks NeverTouchAudit")
        alter = sids.get("NeverAlterAnyTrail", {})
        if not (alter.get("Effect") == "Deny" and alter.get("Resource") == "*"
                and {"cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
                     "cloudtrail:PutEventSelectors"} <= actions(alter)):  # fmt: skip
            v.append(f"{name} lacks NeverAlterAnyTrail")
    sids = by_sid(t["audit-bucket-policy"])
    if "DenyDatasetRoles" not in sids or sids["DenyDatasetRoles"]["Effect"] != "Deny":
        v.append("audit bucket does not deny dataset roles")
    deletion = sids.get("DenyRecordDeletionExceptAuditAdmin", {})
    if not {"s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention",
            "s3:PutObjectRetention"} <= actions(deletion):  # fmt: skip
        v.append("audit bucket does not protect log objects")
    if "DenyBucketConfigExceptAuditAdmin" not in sids:
        v.append("audit bucket configuration is not reserved to the audit administrator")
    for s in statements(t["audit-kms-key-statements"]):
        if "kms:ScheduleKeyDeletion" in actions(s) or "kms:*" in actions(s):
            v.append("the audit key can be scheduled for deletion")
    admin = t["role-audit-admin"]
    granted = allowed_actions(admin)
    for forbidden in ("s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObject",
                      "s3:BypassGovernanceRetention", "s3:PutObjectRetention"):  # fmt: skip
        if forbidden in granted:
            v.append(f"the audit administrator may {forbidden}")
    for name in ("role-audit-admin", "role-audit-reader"):
        never = by_sid(t[name]).get("NeverTouchDatasets", {})
        if never.get("Effect") != "Deny" or "<KEY_ARN>" not in as_list(never.get("Resource")):
            v.append(f"{name} may touch dataset objects or the dataset key")
    text = PROVISIONING.read_text()
    if "Object Lock:** enabled at creation" not in text or "Log file validation:** on" not in text:
        v.append("Object Lock or log-file validation is no longer required")
    return v


def key_policy_violations(t: Templates) -> list[str]:
    v = []
    for name in ("dataset-kms-key-statements", "audit-kms-key-statements"):
        for s in allows(t[name]):
            p = principals(s)
            admins = {"arn:aws:iam::<ACCOUNT>:root", f"{ACCOUNT_ROLE}<ADMIN_ROLE>",
                      f"{ACCOUNT_ROLE}<AUDIT_ADMIN_ROLE>"}  # fmt: skip
            if p & admins and actions(s) & KMS_USE:
                v.append(f"{name}/{s.get('Sid')}: an administrator may use the key")
    for s in allows(t["dataset-kms-key-statements"]):
        if not principals(s) & {role("api"), role("ingest"), role("operator")}:
            continue
        cond = s.get("Condition", {}).get("StringEquals", {})
        if cond != {"kms:ViaService": "s3.us-east-1.amazonaws.com",
                    "kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::<BUCKET>"}:  # fmt: skip
            v.append(f"{s.get('Sid')}: key use is not bound to S3 and this bucket")
    return v


def credential_separation_violations(t: Templates) -> list[str]:
    v = []
    generators = {
        p
        for s in allows(t["dataset-kms-key-statements"])
        if actions(s) & {"kms:GenerateDataKey", "kms:GenerateDataKey*", "kms:*"}
        for p in principals(s)
    }
    if generators - {role("api")}:
        v.append(f"the key policy lets {sorted(generators - {role('api')})} generate data keys")
    if {a for a in allowed_actions(t["role-ingest"]) if a.startswith("kms:Generate")}:
        v.append("the ingest role may generate data keys")
    if "s3:PutObject" in allowed_actions(t["role-ingest"]):
        v.append("the ingest role may write")
    api_session = allows(t["trust-api"])[0].get("Condition")
    ingest_session = allows(t["trust-ingest"])[0].get("Condition")
    if api_session == ingest_session:
        v.append("API and ingest trust the same session name")
    text = PROVISIONING.read_text()
    for must in ("/run/nlw/aws/api/credentials", "/run/nlw/aws/ingest/credentials",
                 "The API container mounts only `/run/nlw/aws/api`",
                 "The ingest container mounts only `/run/nlw/aws/ingest`"):  # fmt: skip
        if must not in text:
            v.append(f"credential separation prose missing: {must}")
    return v


def credential_chain_violations(session_factory: Callable[..., Any], tmp: Path) -> list[str]:
    """The session's credentials come from the file alone, with no fallback."""
    path = tmp / "credentials"
    expiry = (datetime.now(UTC) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    path.write_text(
        "[default]\naws_access_key_id = FILEKEY\naws_secret_access_key = file-secret\n"
        f"aws_session_token = file-token\nx_nlw_expiration = {expiry}\n"
    )
    path.chmod(0o600)
    session = session_factory(creds._refreshable(str(path)), "us-east-1")
    resolver = session.get_component("credential_provider")
    methods = [p.METHOD for p in resolver.providers]
    if methods != ["nlw-credential-file"]:
        # Stop here: resolving an unpinned chain could try IMDS or a profile.
        return [f"credential providers: {methods}"]
    got = session.get_credentials()
    if got is None or got.get_frozen_credentials().access_key != "FILEKEY":
        return ["credentials did not come from the file"]
    return []


# --- C/D/F. proof procedure --------------------------------------------------------------


def label_violations(text: str) -> list[str]:
    v = []
    for b in labelled_blocks(text):
        label = b["label"]
        if label is None:
            v.append(f"unlabelled command block at offset {b['start']}")
            continue
        ops = aws_ops(b["body"])
        writes = [o for o in ops if not is_read(o[1])]
        sid, cls = label["id"], label["cls"]
        if cls == "READ-ONLY" and writes:
            v.append(f"{sid} is READ-ONLY but calls {[f'{s} {o}' for s, o, _ in writes]}")
        if cls == "MUTATING" and not writes:
            v.append(f"{sid} is MUTATING but makes no mutating call")
        if cls in ("HOST", "LOCAL") and ops:
            v.append(f"{sid} is {cls} but calls AWS")
        if label["deny"]:
            for _, op, line in ops:
                if not re.match(r"\s*(expect_denied|expect_error|absent)\b", line):
                    v.append(f"{sid} is EXPECT-DENIED but '{op}' is not wrapped in expect_*")
        if (
            not ops
            and cls in ("READ-ONLY", "MUTATING")
            and "probe " not in b["body"]
            and ("write_credentials" not in b["body"])
        ):
            v.append(f"{sid} is {cls} but contains no AWS call")
    ids = [b["label"]["id"] for b in labelled_blocks(text) if b["label"]]
    if len(ids) != len(set(ids)):
        v.append("duplicate step ids")
    return v


def staging_only_violations(text: str) -> list[str]:
    v = []
    for b in labelled_blocks(text):
        if b["label"] and b["label"]["cls"] == "MUTATING" and re.search(r"production", b["body"]):
            v.append(f"{b['label']['id']} is MUTATING and names production")
    (inventory,) = re.findall(r"<!-- inventory -->\n```json\n(.*?)```", text, re.S)
    for item in json.loads(inventory):
        name = item["name"]
        if "production" in name or (item["type"] != "AWS::S3::Object" and "staging" not in name):
            v.append(f"inventory item {item['id']} is not a staging resource: {name}")
    lib = dict(FILE_BLOCK.findall(text))["lib.sh"]
    for var in ("BUCKET", "AUDIT_BUCKET", "TRAIL", "KEY_ALIAS", "AUDIT_KEY_ALIAS"):
        m = re.search(rf"^{var}=(.*)$", lib, re.M)
        if m is None or "staging" not in m.group(1) or "production" in m.group(1):
            v.append(f"lib.sh {var} is not a staging name")
    return v


def secret_print_violations(text: str) -> list[str]:
    v = []
    code = "\n".join(
        [b["body"] for b in labelled_blocks(text)] + [body for _, body in FILE_BLOCK.findall(text)]
    ).replace("\\\n", " ")
    for line in code.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "--debug" in line or re.search(r"\bset -[a-z]*x", line):
            v.append(f"debug tracing would print secrets: {stripped}")
        if "sts assume-role" in line and (
            "--query" not in line or "Credentials" in line.split("--query", 1)[1]
        ):
            v.append(f"assume-role output is not restricted: {stripped}")
        if "export-credentials" in line and "|" not in line:
            v.append(f"export-credentials output is not piped into the writer: {stripped}")
        if re.search(r"\bcat\b[^|]*credentials", line):
            v.append(f"a credential file is printed: {stripped}")
    return v


def cleanup_violations(text: str) -> list[str]:
    v = []
    for b in labelled_blocks(text):
        label = b["label"]
        if not label or not label["id"].startswith("X"):
            continue
        for _, op, line in aws_ops(b["body"]):
            if is_read(op):
                continue
            if not re.search(r"\$\{(REC_|!v)", line):
                v.append(f"{label['id']} {op} does not use a recorded id")
            unexpanded = re.sub(r"\$\{[^}]*\}", "", line)  # ${v##*/} trims, it is no glob
            if "*" in unexpanded or "--recursive" in line or "--force" in line:
                v.append(f"{label['id']} {op} uses a wildcard, --recursive or --force")
        if re.search(r"aws s3 (rm|rb)\b", b["body"]):
            v.append(f"{label['id']} uses the high-level s3 rm/rb")
    return v


def stop_violations(text: str) -> list[str]:
    v = []
    code = "\n".join(
        [b["body"] for b in labelled_blocks(text)] + [body for _, body in FILE_BLOCK.findall(text)]
    )
    for n in range(1, 10):
        if f"| **S{n}** |" not in text:
            v.append(f"stop condition S{n} is not defined")
        if not re.search(rf"\bS{n}\b", code):
            v.append(f"stop condition S{n} is never checked by a command")
    return v


def inventory_violations(text: str) -> list[str]:
    v = []
    (inventory,) = re.findall(r"<!-- inventory -->\n```json\n(.*?)```", text, re.S)
    blocks = labelled_blocks(text)
    proc = "\n".join(b["body"] for b in blocks if b["label"] and b["label"]["id"].startswith("P"))
    cleanup = "\n".join(
        b["body"] for b in blocks if b["label"] and b["label"]["id"].startswith("X")
    )
    for item in json.loads(inventory):
        ledger = item["ledger"]
        if not re.search(rf"(record|mkrole [a-z-]+ [a-z-]+) {re.escape(ledger)}", proc):
            v.append(f"{item['id']} is never recorded in the ledger ({ledger})")
        if item["after_proof"] in ("always deleted", "always purged", "decision E3") and (
            ledger not in cleanup
        ):
            v.append(f"{item['id']} has no cleanup step")
    return v


def imds_violations(text: str) -> list[str]:
    v = []
    if (
        "--metadata-options HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled"
        not in text
    ):
        v.append("the proof instance does not require IMDSv2 with hop limit 1")
    if "iptables -I DOCKER-USER -d 169.254.169.254/32 -j DROP" not in text:
        v.append("the host firewall does not drop IMDS for containers")
    lib = dict(FILE_BLOCK.findall(text))["lib.sh"]
    if "export AWS_SHARED_CREDENTIALS_FILE=/dev/null" not in lib:
        v.append("the proof session may read a static credentials file")
    if "unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN" not in lib:
        v.append("the proof session may use static environment credentials")
    if "probe api /run/nlw/aws/empty --network host" not in text:
        v.append("the no-fallback probe with IMDS reachable is missing")
    return v


# --- the committed documents pass every check -------------------------------------------------


def test_allows_are_least_privilege() -> None:
    assert least_privilege_violations(load_templates()) == []


def test_cross_environment_access_is_explicitly_denied() -> None:
    assert cross_environment_violations(load_templates()) == []


def test_sse_kms_is_required_with_the_exact_key() -> None:
    assert sse_kms_violations(load_templates()) == []


def test_conditional_writes_and_copy_are_enforced() -> None:
    assert conditional_write_violations(load_templates()) == []


def test_runtime_roles_can_never_delete() -> None:
    assert runtime_delete_violations(load_templates()) == []


def test_the_instance_role_can_never_become_the_operator() -> None:
    assert instance_role_violations(load_templates()) == []


def test_human_roles_require_mfa() -> None:
    assert mfa_violations(load_templates()) == []


def test_audit_tamper_protection_is_complete() -> None:
    assert audit_tamper_violations(load_templates()) == []


def test_key_policies_split_encrypt_from_decrypt_and_never_let_admins_use_keys() -> None:
    assert key_policy_violations(load_templates()) == []


def test_api_and_ingest_credentials_are_separate() -> None:
    assert credential_separation_violations(load_templates()) == []


def test_the_credential_chain_has_no_fallback(tmp_path: Path) -> None:
    assert credential_chain_violations(creds._session, tmp_path) == []


def test_the_proof_instance_requires_imdsv2_with_hop_limit_one() -> None:
    assert imds_violations(proof_text()) == []


def test_every_command_block_is_labelled_and_the_label_matches_its_calls() -> None:
    assert label_violations(proof_text()) == []


def test_mutating_commands_touch_staging_only() -> None:
    assert staging_only_violations(proof_text()) == []


def test_no_command_can_print_a_credential() -> None:
    assert secret_print_violations(proof_text()) == []


def test_cleanup_uses_recorded_ids_only() -> None:
    assert cleanup_violations(proof_text()) == []


def test_every_stop_condition_is_defined_and_checked() -> None:
    assert stop_violations(proof_text()) == []


def test_every_inventory_resource_is_recorded_and_cleaned_up() -> None:
    assert inventory_violations(proof_text()) == []


def test_the_procedure_covers_every_required_step_in_order() -> None:
    text = proof_text()
    heads = re.findall(r"^### (P\d\d)\. ", text, re.M)
    assert heads == [f"P{n:02d}" for n in range(0, 19)]


def test_every_owner_decision_is_open_with_options_and_a_recommendation() -> None:
    text = DECISIONS.read_text()
    rows = re.findall(r"^\| \*\*(E\d+)\*\* \| (.+?) \| (.+?) \| (.+?) \|$", text, re.M)
    assert [r[0] for r in rows] == [f"E{n}" for n in range(1, 11)]
    for _, _, options, recommendation in rows:
        assert options.strip() and recommendation.strip()
    assert "every decision below is open" in text


def test_package_documents_hold_placeholders_only() -> None:
    for path in (PROOF, DECISIONS, REVIEW, PROVISIONING):
        # The one literal key id is the all-zero ARN used as a deliberately wrong key.
        text = path.read_text().replace("key/00000000-0000-0000-0000-000000000000", "key/<ZERO>")
        for pattern in (
            r"\b\d{12}\b",
            r"AKIA[0-9A-Z]{16}",
            r"ASIA[0-9A-Z]{16}",
            r"\bi-[0-9a-f]{8,17}\b",
            r"\bsg-[0-9a-f]{8,17}\b",
            r"\bvpc-[0-9a-f]{8,17}\b",
            r"arn:aws:iam::\d",
            r"key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        ):
            assert not re.search(pattern, text), (path.name, pattern)


def test_the_package_claims_no_aws_validation() -> None:
    assert "NOT RUN" in proof_text() and "has not been validated by AWS" not in proof_text()
    assert "nothing here has been validated by aws" in proof_text().lower()
    assert "NOT validated by AWS" in REVIEW.read_text()


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is required")
def test_every_shell_block_is_valid_bash(tmp_path: Path) -> None:
    text = proof_text()
    scripts = [b["body"] for b in labelled_blocks(text)]
    scripts += [body for name, body in FILE_BLOCK.findall(text) if name.endswith(".sh")]
    for i, script in enumerate(scripts):
        f = tmp_path / f"block{i}.sh"
        f.write_text(script)
        result = subprocess.run(["bash", "-n", str(f)], capture_output=True, text=True)
        assert result.returncode == 0, (i, result.stderr)


# AWS's documented size limits, counted without whitespace.
SIZE_LIMITS = {"trust": 2048, "role": 10240, "bucket": 20480, "key": 32768}


def _limit_for(name: str) -> int | None:
    if name.startswith("trust-"):
        return SIZE_LIMITS["trust"]
    if name.startswith("role-"):
        return SIZE_LIMITS["role"]
    if name.endswith("bucket-policy"):
        return SIZE_LIMITS["bucket"]
    if name.endswith("kms-key-statements"):
        return SIZE_LIMITS["key"]
    return None


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is required")
def test_every_template_renders_completely_and_within_size_limits(tmp_path: Path) -> None:
    """Run the proof's own ``render`` helper (lib.sh) offline with dummy
    session values: every template must fill every placeholder, parse, and fit
    the AWS policy size limit for its kind."""
    lib = tmp_path / "lib.sh"
    lib.write_text(dict(FILE_BLOCK.findall(proof_text()))["lib.sh"])
    dummy = "111122223333"
    kms = f"arn:aws:kms:us-east-1:{dummy}:key"
    env = {
        "PATH": os.environ["PATH"], "HOME": str(tmp_path),
        "PROOF_DIR": str(tmp_path), "PROOF_ID": "d6-test", "APPROVED_ACCOUNT": dummy,
        "RUNBOOK_DIR": str(RUNBOOKS), "ADMIN_ROLE": "nlw-test-admin",
        "REC_KEY_ARN": f"{kms}/{'1' * 8}-1111-1111-1111-{'1' * 12}",
        "REC_AUDIT_KEY_ARN": f"{kms}/{'2' * 8}-2222-2222-2222-{'2' * 12}",
        "HUMANS": json.dumps([f"arn:aws:iam::{dummy}:role/human-{x}" for x in "ab"]),
        "AUDIT_RETENTION_DAYS": "90",
    }  # fmt: skip
    for name in load_templates():
        result = subprocess.run(
            ["bash", "-c", f'source "{lib}" && render {name}'],
            capture_output=True, text=True, env=env, timeout=30,
        )  # fmt: skip
        assert result.returncode == 0, (name, result.stderr)
        doc = json.loads(result.stdout)
        rendered = json.dumps(doc, separators=(",", ":"))
        assert "<" not in rendered, name
        limit = _limit_for(name)
        if limit is not None:
            assert len(rendered) <= limit, (name, len(rendered), limit)
    lifecycle = subprocess.run(
        ["bash", "-c", f'source "{lib}" && render audit-bucket-lifecycle'],
        capture_output=True, text=True, env=env, timeout=30,
    )  # fmt: skip
    assert json.loads(lifecycle.stdout)["Rules"][0]["Expiration"]["Days"] == 91


def test_rendering_refuses_a_template_with_an_unfilled_placeholder(tmp_path: Path) -> None:
    """Negative control: without the key ARN, a role policy must not render."""
    lib = tmp_path / "lib.sh"
    lib.write_text(dict(FILE_BLOCK.findall(proof_text()))["lib.sh"])
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "PROOF_DIR": str(tmp_path),
           "PROOF_ID": "d6-test", "APPROVED_ACCOUNT": "111122223333",
           "RUNBOOK_DIR": str(RUNBOOKS), "ADMIN_ROLE": "nlw-test-admin"}  # fmt: skip
    result = subprocess.run(
        ["bash", "-c", f'source "{lib}" && render role-api'],
        capture_output=True, text=True, env=env, timeout=30,
    )  # fmt: skip
    assert result.returncode != 0 and "unfilled placeholder" in result.stderr
    assert result.stdout == ""


# --- the probe's offline refusals (no network: each refuses before any AWS call) -------------


def _run_probe(tmp_path: Path, credentials: Path | None, extra_env: dict[str, str]) -> str:
    probe = tmp_path / "probe.py"
    probe.write_text(dict(FILE_BLOCK.findall(proof_text()))["probe.py"])
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("AWS_") and k not in ("HTTP_PROXY", "HTTPS_PROXY")
    }
    env.update(
        AWS_EC2_METADATA_DISABLED="true",
        HTTPS_PROXY="http://127.0.0.1:9",  # any accidental network call fails at once
        HTTP_PROXY="http://127.0.0.1:9",
        AWS_CONFIG_FILE=str(tmp_path / "no-config"),
        AWS_SHARED_CREDENTIALS_FILE=str(credentials or tmp_path / "absent"),
        **extra_env,
    )
    result = subprocess.run(
        [sys.executable, str(probe), "api", "nlw-staging-datasets-111122223333-us-east-1"],
        capture_output=True, text=True, env=env, timeout=60,
    )  # fmt: skip
    assert result.returncode == 3, (result.stdout, result.stderr)
    lines = [ln for ln in result.stdout.splitlines() if ln.startswith(("REFUSED", "ACCEPTED"))]
    assert len(lines) == 1
    assert "proof-dummy" not in result.stdout + result.stderr
    return lines[0]


def _dummy_file(tmp_path: Path, expiry: str, mode: int) -> Path:
    path = tmp_path / "credentials"
    path.write_text(
        "[default]\naws_access_key_id = proof-dummy-id\naws_secret_access_key = proof-dummy\n"
        f"aws_session_token = proof-dummy\nx_nlw_expiration = {expiry}\n"
    )
    path.chmod(mode)
    return path


def test_the_probe_refuses_a_missing_file(tmp_path: Path) -> None:
    assert _run_probe(tmp_path, None, {}) == (
        "REFUSED: the AWS credential file is missing or unreadable"
    )


def test_the_probe_refuses_an_expired_file(tmp_path: Path) -> None:
    path = _dummy_file(tmp_path, "2000-01-01T00:00:00Z", stat.S_IRUSR)
    assert "expired or about to expire" in _run_probe(tmp_path, path, {})


def test_the_probe_refuses_an_exposed_file(tmp_path: Path) -> None:
    path = _dummy_file(tmp_path, "2999-01-01T00:00:00Z", 0o444)
    assert "private regular file" in _run_probe(tmp_path, path, {})


def test_the_probe_refuses_static_environment_credentials(tmp_path: Path) -> None:
    out = _run_probe(tmp_path, None, {"AWS_ACCESS_KEY_ID": "proof-dummy-id"})
    assert "static AWS credentials" in out


# --- G. negative controls: each check fails when its property is weakened ---------------------


def _drop_sid(t: Templates, name: str, sid: str) -> None:
    doc = t[name]
    kept = [s for s in statements(doc) if s.get("Sid") != sid]
    assert len(kept) < len(statements(doc)), (name, sid)
    if isinstance(doc, list):
        t[name] = kept
    else:
        doc["Statement"] = kept


def _sid(t: Templates, name: str, sid: str) -> dict[str, Any]:
    return by_sid(t[name])[sid]


TemplateMutation = tuple[str, Callable[[Templates], None], Callable[[Templates], list[str]]]

TEMPLATE_MUTATIONS: list[TemplateMutation] = [
    # cross-environment denial removed
    ("bucket cross-env deny removed",
     lambda t: _drop_sid(t, "dataset-bucket-policy", "DenyOtherEnvironmentRoles"),
     cross_environment_violations),
    ("operator cross-env deny removed",
     lambda t: _drop_sid(t, "role-operator", "NeverOtherEnvironment"),
     cross_environment_violations),
    ("api cross-env deny made conditional",
     lambda t: _sid(t, "role-api", "NeverOtherEnvironment").update(
         Condition={"StringNotEquals": {"aws:ResourceTag/nlw-env": "<ENV>"}}),
     cross_environment_violations),
    ("ingest key-tag deny removed",
     lambda t: _drop_sid(t, "role-ingest", "NeverOtherEnvironmentKeys"),
     cross_environment_violations),
    # SSE-KMS weakened
    ("missing-key-header deny removed",
     lambda t: _drop_sid(t, "dataset-bucket-policy", "DenyMissingSseKmsKeyHeader"),
     sse_kms_violations),
    ("wrong-key deny switched to IfExists",
     lambda t: _sid(t, "dataset-bucket-policy", "DenyWrongSseKmsKey").update(Condition={
         "StringNotEqualsIfExists": {SSE_KEY_ID: "<KEY_ARN>"}}),
     sse_kms_violations),
    ("wrong-key deny accepts any key",
     lambda t: _sid(t, "dataset-bucket-policy", "DenyWrongSseKmsKey").update(Condition={
         "StringNotLike": {SSE_KEY_ID: "arn:aws:kms:*"}}),
     sse_kms_violations),
    ("algorithm deny allows AES256",
     lambda t: _sid(t, "dataset-bucket-policy", "DenyWrongSseAlgorithm").update(Condition={
         "StringNotEquals": {"s3:x-amz-server-side-encryption": ["aws:kms", "AES256"]}}),
     sse_kms_violations),
    ("encryption deny limited to versions/",
     lambda t: _sid(t, "dataset-bucket-policy", "DenyMissingSseAlgorithmHeader").update(
         Resource="arn:aws:s3:::<BUCKET>/versions/*"),
     sse_kms_violations),
    # conditional writes removed
    ("unconditional-create deny removed",
     lambda t: _drop_sid(t, "dataset-bucket-policy", "DenyUnconditionalCreate"),
     conditional_write_violations),
    ("unconditional-create deny loses If-None-Match",
     lambda t: _sid(t, "dataset-bucket-policy", "DenyUnconditionalCreate").update(
         Condition={"Bool": {"s3:ObjectCreationOperation": "true"}}),
     conditional_write_violations),
    ("server-side copy allowed",
     lambda t: _drop_sid(t, "dataset-bucket-policy", "DenyServerSideCopy"),
     conditional_write_violations),
    # runtime delete access added
    ("api may delete objects",
     lambda t: _sid(t, "role-api", "CreateOnce").update(
         Action=["s3:PutObject", "s3:AbortMultipartUpload", "s3:DeleteObject"]),
     runtime_delete_violations),
    ("ingest may delete versions",
     lambda t: _sid(t, "role-ingest", "ReadVersions").update(
         Action=["s3:GetObject", "s3:DeleteObjectVersion"]),
     runtime_delete_violations),
    ("operator may add delete markers",
     lambda t: _sid(t, "role-operator", "PurgeAndVerify")["Action"].append("s3:DeleteObject"),
     runtime_delete_violations),
    ("bucket lets the api delete",
     lambda t: _sid(t, "dataset-bucket-policy", "DenyDeleteExceptOperator")["Condition"][
         "ArnNotEquals"]["aws:PrincipalArn"].append(role("api")),
     runtime_delete_violations),
    # the instance role can assume the operator role
    ("bootstrap may assume the operator",
     lambda t: _sid(t, "role-bootstrap", "AssumeRuntimeRolesOnly")["Resource"].append(
         role("operator")),
     instance_role_violations),
    ("bootstrap's explicit role deny removed",
     lambda t: _drop_sid(t, "role-bootstrap", "NeverAssumeAnyOtherRole"),
     instance_role_violations),
    ("human trust admits the bootstrap role",
     lambda t: _sid(t, "trust-human-mfa", "NamedHumansWithMfa").update(
         Principal={"AWS": ["<HUMAN_PRINCIPAL_ARNS>", role("bootstrap")]}),
     instance_role_violations),
    ("human trust stops denying machine roles",
     lambda t: _drop_sid(t, "trust-human-mfa", "DenyMachineRoles"),
     instance_role_violations),
    ("api trust drops the session-name condition",
     lambda t: _sid(t, "trust-api", "BootstrapWithApiSessionName").pop("Condition"),
     instance_role_violations),
    ("operator trust without MFA",
     lambda t: _sid(t, "trust-human-mfa", "NamedHumansWithMfa").pop("Condition"),
     mfa_violations),
    ("operator trust without the missing-MFA deny",
     lambda t: _drop_sid(t, "trust-human-mfa", "DenyWithoutMfaContext"),
     mfa_violations),
    # audit tamper protection removed
    ("ingest may touch audit resources",
     lambda t: _drop_sid(t, "role-ingest", "NeverTouchAudit"),
     audit_tamper_violations),
    ("api may stop the trail",
     lambda t: _drop_sid(t, "role-api", "NeverAlterAnyTrail"),
     audit_tamper_violations),
    ("audit bucket admits dataset roles",
     lambda t: _drop_sid(t, "audit-bucket-policy", "DenyDatasetRoles"),
     audit_tamper_violations),
    ("audit logs deletable",
     lambda t: _drop_sid(t, "audit-bucket-policy", "DenyRecordDeletionExceptAuditAdmin"),
     audit_tamper_violations),
    ("audit key deletable",
     lambda t: _sid(t, "audit-kms-key-statements", "AdministerNeverUse")["Action"].append(
         "kms:ScheduleKeyDeletion"),
     audit_tamper_violations),
    ("audit admin may delete log objects",
     lambda t: _sid(t, "role-audit-admin", "AdministerAuditBucket")["Action"].append(
         "s3:DeleteObjectVersion"),
     audit_tamper_violations),
    # credential separation
    ("key policy lets ingest generate data keys (F1)",
     lambda t: _sid(t, "dataset-kms-key-statements", "ReadersDecryptViaS3ForThisBucketOnly").update(
         Action=["kms:GenerateDataKey", "kms:Decrypt"]),
     credential_separation_violations),
    ("api and ingest share a session name",
     lambda t: _sid(t, "trust-ingest", "BootstrapWithIngestSessionName").update(
         Condition={"StringEquals": {"sts:RoleSessionName": "nlw-<ENV>-api"}}),
     credential_separation_violations),
    ("ingest may write",
     lambda t: _sid(t, "role-ingest", "ReadVersions")["Action"].append("s3:PutObject"),
     credential_separation_violations),
    # key policies and least privilege
    ("admin may decrypt with the dataset key",
     lambda t: _sid(t, "dataset-kms-key-statements", "AdministerNeverUse")["Action"].append(
         "kms:Decrypt"),
     key_policy_violations),
    ("key use not bound to S3",
     lambda t: _sid(t, "dataset-kms-key-statements", "ApiEncryptViaS3ForThisBucketOnly").pop(
         "Condition"),
     key_policy_violations),
    ("api role gains s3:*",
     lambda t: _sid(t, "role-api", "CreateOnce").update(Action="s3:*"),
     least_privilege_violations),
    ("ingest reads every bucket",
     lambda t: _sid(t, "role-ingest", "ReadVersions").update(Resource="*"),
     least_privilege_violations),
]  # fmt: skip


@pytest.mark.parametrize(
    ("mutation", "check"),
    [(m[1], m[2]) for m in TEMPLATE_MUTATIONS],
    ids=[m[0] for m in TEMPLATE_MUTATIONS],
)
def test_negative_control_template_weakening_is_detected(
    mutation: Callable[[Templates], None], check: Callable[[Templates], list[str]]
) -> None:
    weakened = copy.deepcopy(load_templates())
    mutation(weakened)
    assert check(weakened), "the weakened template passed its check"


def _block_containing(text: str, step: str) -> tuple[int, int]:
    label = text.index(f"**{step} ·")
    start = text.index("```bash\n", label) + len("```bash\n")
    return start, text.index("```", start)


def _insert_into(text: str, step: str, line: str) -> str:
    start, _ = _block_containing(text, step)
    return text[:start] + line + "\n" + text[start:]


ProofMutation = tuple[str, Callable[[str], str], Callable[[str], list[str]]]

PROOF_MUTATIONS: list[ProofMutation] = [
    ("production bucket written by the staging proof",
     lambda t: _insert_into(t, "P04-01", "aws s3api put-object --profile proof-api "
                            '--bucket "nlw-production-datasets-${ACCOUNT}-us-east-1" '
                            "--key k --body f"),
     staging_only_violations),
    ("production role created by the staging proof",
     lambda t: _insert_into(t, "P03-01", "aws iam create-role "
                            "--role-name nlw-production-dataset-api "
                            "--assume-role-policy-document file://x"),
     staging_only_violations),
    ("inventory names a production bucket",
     lambda t: t.replace('"name": "nlw-staging-datasets-<ACCOUNT>-us-east-1<SUFFIX>"',
                         '"name": "nlw-production-datasets-<ACCOUNT>-us-east-1<SUFFIX>"'),
     staging_only_violations),
    ("lib.sh bucket points at production",
     lambda t: t.replace('BUCKET="nlw-staging-datasets-', 'BUCKET="nlw-production-datasets-', 1),
     staging_only_violations),
    ("IMDS hop limit raised to 2",
     lambda t: t.replace("HttpPutResponseHopLimit=1", "HttpPutResponseHopLimit=2"),
     imds_violations),
    ("IMDS firewall rule removed",
     lambda t: t.replace("sudo iptables -I DOCKER-USER -d 169.254.169.254/32 -j DROP\n", ""),
     imds_violations),
    ("static credentials file allowed",
     lambda t: t.replace("export AWS_SHARED_CREDENTIALS_FILE=/dev/null\n", ""),
     imds_violations),
    ("mutating call in a READ-ONLY block",
     lambda t: _insert_into(t, "P06-02", "aws s3api delete-object --bucket b --key k"),
     label_violations),
    ("unwrapped call in an EXPECT-DENIED block",
     lambda t: _insert_into(t, "P11-01",
                            "aws s3api delete-object --profile proof-api --bucket b --key k"),
     label_violations),
    ("unlabelled command block",
     lambda t: t.replace("**P08-01 · READ-ONLY · proof instance**", "P08-01"),
     label_violations),
    ("assume-role prints the session",
     lambda t: _insert_into(t, "P12-02", "aws sts assume-role --role-arn x --role-session-name y"),
     secret_print_violations),
    ("debug tracing enabled",
     lambda t: _insert_into(t, "P04-01", "set -x"),
     secret_print_violations),
    ("credentials exported to the terminal",
     lambda t: _insert_into(t, "P14-02", "aws configure export-credentials --profile proof-api"),
     secret_print_violations),
    ("cleanup deletes by wildcard",
     lambda t: _insert_into(t, "X06",
                            'aws s3api delete-object --bucket "${REC_BUCKET}" --key "versions/*"'),
     cleanup_violations),
    ("cleanup uses an unrecorded id",
     lambda t: _insert_into(t, "X03", "aws ec2 terminate-instances --instance-ids i-proofexample"),
     cleanup_violations),
    ("cleanup empties a bucket recursively",
     lambda t: _insert_into(t, "X06", 'aws s3 rm "s3://${REC_BUCKET}" --recursive'),
     cleanup_violations),
    ("a stop condition is never checked",
     lambda t: re.sub(r"\bS5\b(?! \|)", "S9", t),
     stop_violations),
    ("a created resource is never recorded",
     lambda t: t.replace("record REC_SG_ID", "SG_ID=$(true) #", 1),
     inventory_violations),
]  # fmt: skip


@pytest.mark.parametrize(
    ("mutation", "check"),
    [(m[1], m[2]) for m in PROOF_MUTATIONS],
    ids=[m[0] for m in PROOF_MUTATIONS],
)
def test_negative_control_procedure_weakening_is_detected(
    mutation: Callable[[str], str], check: Callable[[str], list[str]]
) -> None:
    text = proof_text()
    weakened = mutation(text)
    assert weakened != text, "the mutation did not apply"
    assert check(weakened), "the weakened procedure passed its check"


def test_negative_control_a_fallback_credential_chain_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A session built WITHOUT replacing the SDK's provider chain (the bug the
    pin prevents) must fail the check: env, profile and IMDS providers appear."""
    import botocore.session

    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")

    def unpinned(credentials: Any, region: str) -> Any:
        session = botocore.session.Session()
        session.set_config_variable("region", region)
        return session

    assert credential_chain_violations(unpinned, tmp_path)
