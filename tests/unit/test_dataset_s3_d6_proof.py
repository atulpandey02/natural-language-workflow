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
import shlex
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
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
READ_OPS = re.compile(
    r"^(get-.*|list-.*|describe-.*|head-.*|lookup-.*|simulate-.*|validate-logs|wait|get"
    r"|export-credentials|assume-role)$"
)
SSE_KEY_ID = "s3:x-amz-server-side-encryption-aws-kms-key-id"
ROLES = ("role-bootstrap", "role-api", "role-ingest", "role-operator")
DATA_ROLES = ("role-api", "role-ingest", "role-operator")
ACCOUNT_ROLE = "arn:aws:iam::<ACCOUNT>:role/"
KMS_USE = {
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:ReEncrypt*",
    "kms:ReEncryptFrom",
    "kms:ReEncryptTo",
    "kms:GenerateDataKey",
    "kms:GenerateDataKey*",
    "kms:GenerateDataKeyWithoutPlaintext",
    "kms:*",
}

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


# A small shell reader: enough of bash's grammar to find every simple command
# (including those inside "$(...)"), what wraps it, and the AWS CLI service and
# operation it runs even when global options come first. Anything it cannot
# tokenise is an error, never silently skipped.

HEREDOC = re.compile(r"(?<!<)<<-?(?!<)\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")
PREFIX_WORDS = {
    "if",
    "then",
    "else",
    "elif",
    "do",
    "while",
    "until",
    "!",
    "time",
    "sudo",
    "command",
    "exec",
    "fi",
    "done",
    "{",
    "}",
    "esac",
    "$",
}
WRAPPERS = {"expect_denied": 0, "expect_error": 1, "absent": 1}
AWS_VALUE_OPTS = {
    "--profile",
    "--region",
    "--output",
    "--query",
    "--endpoint-url",
    "--cli-read-timeout",
    "--cli-connect-timeout",
    "--color",
    "--ca-bundle",
}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


@dataclass
class Cmd:
    words: list[str]
    line: str
    wrapper: str | None = None
    wrapper_arg: str | None = None
    nested: bool = False
    assignments: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return self.words[0] if self.words else ""

    @property
    def text(self) -> str:
        return " ".join(self.words)


def _tokens(line: str) -> list[str]:
    lex = shlex.shlex(line, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    return list(lex)


def logical_lines(body: str) -> list[str]:
    """Lines joined across backslashes and open quotes; heredoc bodies and
    comment lines dropped."""
    lines: list[str] = []
    skip_until: str | None = None
    buf = ""
    for raw in body.replace("\\\n", " ").splitlines():
        if skip_until is not None:
            if raw.strip() == skip_until:
                skip_until = None
            continue
        if not buf and (raw.strip().startswith("#") or not raw.strip()):
            continue
        buf = f"{buf}\n{raw}" if buf else raw
        try:
            _tokens(buf)
        except ValueError:
            continue  # an open quote: the string continues on the next line
        m = HEREDOC.search(buf)
        if m:
            skip_until = m.group(1)
        lines.append(buf)
        buf = ""
    if buf:
        raise ValueError(f"unterminated quote: {buf[:60]}")
    return lines


def _substitutions(token: str) -> list[str]:
    out, i = [], 0
    while (j := token.find("$(", i)) != -1:
        depth, k = 0, j + 1
        while k < len(token):
            if token[k] == "(":
                depth += 1
            elif token[k] == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        out.append(token[j + 2 : k])
        i = k + 1
    return out


def _split(line: str, nested: bool) -> list[tuple[list[str], bool]]:
    cmds: list[tuple[list[str], bool]] = []
    cur: list[str] = []
    skip = False
    for tok in _tokens(line):
        if skip:
            skip = False
            continue
        if tok and set(tok) <= set("();<>|&"):
            if "<" in tok or ">" in tok:
                skip = True  # the redirection target is not a command word
                continue
            if cur:
                cmds.append((cur, nested))
                cur = []
            continue
        for inner in _substitutions(tok):
            cmds += _split(inner, True)
        cur.append(tok)
    if cur:
        cmds.append((cur, nested))
    return cmds


def commands(body: str) -> list[Cmd]:
    out: list[Cmd] = []
    for line in logical_lines(body):
        for words, nested in _split(line, False):
            assigned = []
            while words and (words[0] in PREFIX_WORDS or ASSIGNMENT.match(words[0])):
                if ASSIGNMENT.match(words[0]):
                    assigned.append(words[0])
                words = words[1:]
            if not words:
                continue
            cmd = Cmd(words, line, nested=nested, assignments=tuple(assigned))
            if cmd.name == "trap" and len(words) > 1:
                out += [Cmd(w, line, nested=True) for w, _ in _split(words[1], True)]
            if cmd.name in WRAPPERS and len(words) > 1 + WRAPPERS[cmd.name]:
                skip = WRAPPERS[cmd.name]
                cmd = Cmd(
                    words[1 + skip :],
                    line,
                    cmd.name,
                    words[1] if skip else None,
                    nested,
                    cmd.assignments,
                )
            out.append(cmd)
    return out


def aws_call(cmd: Cmd) -> tuple[str, str] | None:
    """(service, operation) when ``cmd`` runs the AWS CLI, whatever global
    options precede the service."""
    if cmd.name != "aws":
        return None
    w, i = cmd.words, 1
    while i < len(w) and w[i].startswith("--"):
        i += 2 if w[i] in AWS_VALUE_OPTS else 1
    return (w[i], w[i + 1]) if i + 1 < len(w) else None


def aws_ops(body: str) -> list[tuple[str, str, Cmd]]:
    """(service, operation, command) for each AWS CLI call in a block."""
    return [(*call, c) for c in commands(body) if (call := aws_call(c))]


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
                if ":role/" in r and "*" in r:
                    v.append(f"{sid}: wildcard role resource {r}")
                scoped = (
                    r.startswith(("arn:aws:s3:::<BUCKET>", "arn:aws:s3:::<AUDIT_BUCKET>"))
                    or r in (role("api"), role("ingest"))
                    or r in ("<KEY_ARN>", "<AUDIT_KEY_ARN>", "<TRAIL_ARN>")
                    or r.startswith("arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-")
                )
                unscoped_ok = r == "*" and (
                    actions(s)
                    <= {
                        "cloudtrail:DescribeTrails",
                        "cloudtrail:GetTrailStatus",
                        "cloudtrail:ListPublicKeys",
                    }
                    or ("Condition" in s and actions(s) in ({"kms:CreateKey"}, {"kms:TagResource"}))
                )
                if not (scoped or unscoped_ok):
                    v.append(f"{sid}: unscoped resource {r}")
    api = allowed_actions(t["role-api"])
    if api != {
        "s3:PutObject",
        "s3:AbortMultipartUpload",
        "s3:GetObject",
        "s3:GetObjectAttributes",
        "kms:GenerateDataKey",
        "kms:Decrypt",
    }:
        v.append(f"role-api grants {sorted(api)}")
    if allowed_actions(t["role-ingest"]) != {"s3:GetObject", "kms:Decrypt"}:
        v.append("role-ingest grants more than GetObject and Decrypt")
    if allowed_actions(t["role-bootstrap"]) != {"sts:AssumeRole"}:
        v.append("role-bootstrap grants more than sts:AssumeRole")
    return v


# Every Allow statement of every role, pinned exactly (Sid, actions, resources,
# condition). Any added action, resource, statement or relaxed condition
# fails; a deliberate change must update this table in review.
_DS = "arn:aws:s3:::<BUCKET>"
_AU = "arn:aws:s3:::<AUDIT_BUCKET>"
EXPECTED_ROLE_ALLOWS: dict[str, dict[str, tuple[set[str], set[str], dict[str, Any] | None]]] = {
    "role-bootstrap": {
        "AssumeRuntimeRolesOnly": ({"sts:AssumeRole"}, {role("api"), role("ingest")}, None),
    },
    "role-api": {
        "CreateOnce": ({"s3:PutObject", "s3:AbortMultipartUpload"}, {f"{_DS}/versions/*"}, None),
        "RetryAndOrphanMetadata": (
            {"s3:GetObject", "s3:GetObjectAttributes"},
            {f"{_DS}/versions/*"},
            None,
        ),
        "Encrypt": ({"kms:GenerateDataKey", "kms:Decrypt"}, {"<KEY_ARN>"}, None),
    },
    "role-ingest": {
        "ReadVersions": ({"s3:GetObject"}, {f"{_DS}/versions/*"}, None),
        "Decrypt": ({"kms:Decrypt"}, {"<KEY_ARN>"}, None),
    },
    "role-operator": {
        "ListVersionsBounded": (
            {"s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"},
            {_DS},
            {"StringLike": {"s3:prefix": ["versions/*"]}},
        ),
        "PurgeAndVerify": (
            {
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:GetObjectAttributes",
                "s3:DeleteObjectVersion",
                "s3:AbortMultipartUpload",
            },
            {f"{_DS}/versions/*"},
            None,
        ),
        "Decrypt": ({"kms:Decrypt"}, {"<KEY_ARN>"}, None),
    },
    "role-audit-admin": {
        "AdministerThisTrail": (
            {
                "cloudtrail:CreateTrail",
                "cloudtrail:GetTrail",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetEventSelectors",
                "cloudtrail:PutEventSelectors",
                "cloudtrail:StartLogging",
                "cloudtrail:StopLogging",
                "cloudtrail:UpdateTrail",
                "cloudtrail:DeleteTrail",
                "cloudtrail:AddTags",
                "cloudtrail:ListTags",
            },
            {"<TRAIL_ARN>"},
            None,
        ),
        "AdministerAuditBucket": (
            {
                "s3:CreateBucket",
                "s3:ListBucket",
                "s3:ListBucketVersions",
                "s3:GetBucketPolicy",
                "s3:PutBucketPolicy",
                "s3:GetBucketAcl",
                "s3:GetBucketVersioning",
                "s3:PutBucketVersioning",
                "s3:GetEncryptionConfiguration",
                "s3:PutEncryptionConfiguration",
                "s3:GetLifecycleConfiguration",
                "s3:PutLifecycleConfiguration",
                "s3:GetBucketObjectLockConfiguration",
                "s3:PutBucketObjectLockConfiguration",
                "s3:GetBucketPublicAccessBlock",
                "s3:PutBucketPublicAccessBlock",
                "s3:GetBucketOwnershipControls",
                "s3:PutBucketOwnershipControls",
                "s3:GetBucketTagging",
                "s3:PutBucketTagging",
                "s3:DeleteBucket",
            },
            {_AU},
            None,
        ),
        "CreateAuditKey": (
            {"kms:CreateKey"},
            {"*"},
            {"StringEquals": {"aws:RequestTag/nlw-env": "<ENV>"}},
        ),
        "TagOnlyUntaggedKeys": (
            {"kms:TagResource"},
            {"*"},
            {
                "StringEquals": {"aws:RequestTag/nlw-env": "<ENV>"},
                "Null": {"aws:ResourceTag/nlw-env": "true"},
            },
        ),
        "AdministerAuditKey": (
            {
                "kms:CreateAlias",
                "kms:DescribeKey",
                "kms:GetKeyPolicy",
                "kms:PutKeyPolicy",
                "kms:EnableKeyRotation",
                "kms:GetKeyRotationStatus",
                "kms:ListResourceTags",
            },
            {"<AUDIT_KEY_ARN>", "arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-dataset-audit"},
            None,
        ),
    },
    "role-audit-reader": {
        "ReadAuditLogs": ({"s3:GetObject"}, {f"{_AU}/dataset-data-events/*"}, None),
        "ListAuditLogs": (
            {"s3:ListBucket"},
            {_AU},
            {"StringLike": {"s3:prefix": ["dataset-data-events/*"]}},
        ),
        "DecryptAuditLogs": ({"kms:Decrypt"}, {"<AUDIT_KEY_ARN>"}, None),
        "ValidateTrail": (
            {"cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:ListPublicKeys"},
            {"*"},
            None,
        ),
    },
}
ALL_ROLES = tuple(EXPECTED_ROLE_ALLOWS)


def role_statement_violations(t: Templates) -> list[str]:
    v = []
    for name, expected in EXPECTED_ROLE_ALLOWS.items():
        got = allows(t[name])
        sids = [s.get("Sid") for s in got]
        if sorted(map(str, sids)) != sorted(expected) or len(sids) != len(set(sids)):
            v.append(f"{name}: Allow statements {sids}, expected {sorted(expected)}")
            continue
        for s in got:
            acts, res, cond = expected[s["Sid"]]
            if "NotAction" in s or "NotResource" in s or "Principal" in s:
                v.append(f"{name}/{s['Sid']}: unexpected NotAction, NotResource or Principal")
            if actions(s) != acts:
                v.append(f"{name}/{s['Sid']}: actions {sorted(actions(s) ^ acts)} differ")
            if set(as_list(s.get("Resource", []))) != res:
                v.append(f"{name}/{s['Sid']}: resources differ")
            if s.get("Condition") != cond:
                v.append(f"{name}/{s['Sid']}: condition differs")
    return v


ROOT_ARN = "arn:aws:iam::<ACCOUNT>:root"
DATASET_KEY_ADMIN = {
    "kms:DescribeKey",
    "kms:GetKeyPolicy",
    "kms:PutKeyPolicy",
    "kms:GetKeyRotationStatus",
    "kms:EnableKeyRotation",
    "kms:ListResourceTags",
    "kms:TagResource",
    "kms:UntagResource",
    "kms:CreateAlias",
    "kms:UpdateAlias",
    "kms:DeleteAlias",
    "kms:EnableKey",
    "kms:DisableKey",
    "kms:ScheduleKeyDeletion",
    "kms:CancelKeyDeletion",
}
AUDIT_KEY_ADMIN = DATASET_KEY_ADMIN - {
    "kms:DeleteAlias",
    "kms:ScheduleKeyDeletion",
    "kms:CancelKeyDeletion",
}
VIA_S3 = {
    "StringEquals": {
        "kms:ViaService": "s3.us-east-1.amazonaws.com",
        "kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::<BUCKET>",
    }
}
CT_SOURCE = {"aws:SourceArn": "<TRAIL_ARN>", "aws:SourceAccount": "<ACCOUNT>"}
# Resource, key and trust policies: the ONLY principals an Allow may name, the
# actions each may receive, and the condition every such grant must carry.
PRINCIPAL_ALLOWLIST: dict[str, dict[str, tuple[set[str], Callable[[Any], bool]]]] = {
    "dataset-kms-key-statements": {
        ROOT_ARN: (DATASET_KEY_ADMIN, lambda c: c is None),
        f"{ACCOUNT_ROLE}<ADMIN_ROLE>": (DATASET_KEY_ADMIN, lambda c: c is None),
        role("api"): ({"kms:GenerateDataKey", "kms:Decrypt"}, lambda c: c == VIA_S3),
        role("ingest"): ({"kms:Decrypt"}, lambda c: c == VIA_S3),
        role("operator"): ({"kms:Decrypt"}, lambda c: c == VIA_S3),
    },
    "audit-kms-key-statements": {
        ROOT_ARN: (AUDIT_KEY_ADMIN, lambda c: c is None),
        f"{ACCOUNT_ROLE}<AUDIT_ADMIN_ROLE>": (AUDIT_KEY_ADMIN, lambda c: c is None),
        "cloudtrail.amazonaws.com": (
            {"kms:GenerateDataKey*", "kms:DescribeKey"},
            lambda c: (
                c is not None
                and c.get("StringEquals") == CT_SOURCE
                and set(c) <= {"StringEquals", "StringLike"}
            ),
        ),
        f"{ACCOUNT_ROLE}<AUDIT_READER_ROLE>": (
            {"kms:Decrypt"},
            lambda c: (
                c == {"StringEquals": {"kms:EncryptionContext:aws:cloudtrail:arn": "<TRAIL_ARN>"}}
            ),
        ),
    },
    "dataset-bucket-policy": {},
    "audit-bucket-policy": {
        "cloudtrail.amazonaws.com": (
            {"s3:GetBucketAcl", "s3:PutObject"},
            lambda c: (
                c is not None
                and {k: v for k, v in c["StringEquals"].items() if k != "s3:x-amz-acl"} == CT_SOURCE
            ),
        ),
    },
    "trust-bootstrap": {"ec2.amazonaws.com": ({"sts:AssumeRole"}, lambda c: c is None)},
    "trust-api": {
        role("bootstrap"): (
            {"sts:AssumeRole"},
            lambda c: c == {"StringEquals": {"sts:RoleSessionName": "nlw-<ENV>-api"}},
        )
    },
    "trust-ingest": {
        role("bootstrap"): (
            {"sts:AssumeRole"},
            lambda c: c == {"StringEquals": {"sts:RoleSessionName": "nlw-<ENV>-ingest"}},
        )
    },
    "trust-human-mfa": {
        "<HUMAN_PRINCIPAL_ARNS>": (
            {"sts:AssumeRole"},
            lambda c: (
                c
                == {
                    "Bool": {"aws:MultiFactorAuthPresent": "true"},
                    "NumericLessThan": {"aws:MultiFactorAuthAge": "3600"},
                }
            ),
        )
    },
}
# The exact resources the CloudTrail service may write to or check.
AUDIT_BUCKET_SERVICE_RESOURCES = {
    "s3:GetBucketAcl": "arn:aws:s3:::<AUDIT_BUCKET>",
    "s3:PutObject": "arn:aws:s3:::<AUDIT_BUCKET>/dataset-data-events/AWSLogs/<ACCOUNT>/*",
}


def principal_violations(t: Templates) -> list[str]:
    """Every Allow in every resource, key and trust policy names only
    allow-listed principals, each receiving only its own actions under its
    own condition. Wildcard principals are refused outright."""
    v = []
    for name, allowed in PRINCIPAL_ALLOWLIST.items():
        for s in statements(t[name]):
            sid = f"{name}/{s.get('Sid')}"
            if s["Effect"] != "Allow":
                continue
            if "NotPrincipal" in s or "NotAction" in s or "NotResource" in s:
                v.append(f"{sid}: NotPrincipal, NotAction or NotResource in an Allow")
            ps = principals(s)
            if not ps or "*" in ps or any("*" in p for p in ps):
                v.append(f"{sid}: wildcard or missing principal {sorted(ps)}")
                continue
            for p in ps:
                if p not in allowed:
                    v.append(f"{sid}: principal {p} is not allow-listed")
                    continue
                acts, condition_ok = allowed[p]
                if not actions(s) <= acts:
                    v.append(f"{sid}: {p} receives {sorted(actions(s) - acts)}")
                if not condition_ok(s.get("Condition")):
                    v.append(f"{sid}: {p} is granted without its required condition")
            if name == "audit-bucket-policy":
                for a in actions(s):
                    if s.get("Resource") != AUDIT_BUCKET_SERVICE_RESOURCES.get(a):
                        v.append(f"{sid}: {a} on an unexpected resource")
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
            if not (
                nd.get("Effect") == "Deny"
                and actions(nd) == {"s3:*", "kms:*"}
                and nd.get("Resource") == "*"
                and "Condition" not in nd
            ):
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
    if not (
        never.get("Effect") == "Deny"
        and actions(never) == {"sts:AssumeRole"}
        and sorted(as_list(never.get("NotResource", []))) == runtime
    ):
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
    boot_trust = allows(t["trust-bootstrap"])
    if len(boot_trust) != 1 or any(principals(s) != {"ec2.amazonaws.com"} for s in boot_trust):
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
    audit = {
        "<TRAIL_ARN>",
        "arn:aws:s3:::<AUDIT_BUCKET>",
        "arn:aws:s3:::<AUDIT_BUCKET>/*",
        "<AUDIT_KEY_ARN>",
    }
    for name in ROLES:
        sids = by_sid(t[name])
        touch = sids.get("NeverTouchAudit", {})
        if not (
            touch.get("Effect") == "Deny"
            and actions(touch) == {"cloudtrail:*", "s3:*", "kms:*"}
            and set(as_list(touch.get("Resource", []))) == audit
        ):
            v.append(f"{name} lacks NeverTouchAudit")
        alter = sids.get("NeverAlterAnyTrail", {})
        if not (
            alter.get("Effect") == "Deny"
            and alter.get("Resource") == "*"
            and {
                "cloudtrail:StopLogging",
                "cloudtrail:DeleteTrail",
                "cloudtrail:UpdateTrail",
                "cloudtrail:PutEventSelectors",
            }
            <= actions(alter)
        ):
            v.append(f"{name} lacks NeverAlterAnyTrail")
    sids = by_sid(t["audit-bucket-policy"])
    if "DenyDatasetRoles" not in sids or sids["DenyDatasetRoles"]["Effect"] != "Deny":
        v.append("audit bucket does not deny dataset roles")
    deletion = sids.get("DenyRecordDeletionExceptAuditAdmin", {})
    if not {
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:BypassGovernanceRetention",
        "s3:PutObjectRetention",
    } <= actions(deletion):
        v.append("audit bucket does not protect log objects")
    if "DenyBucketConfigExceptAuditAdmin" not in sids:
        v.append("audit bucket configuration is not reserved to the audit administrator")
    for s in statements(t["audit-kms-key-statements"]):
        if "kms:ScheduleKeyDeletion" in actions(s) or "kms:*" in actions(s):
            v.append("the audit key can be scheduled for deletion")
    admin = t["role-audit-admin"]
    granted = allowed_actions(admin)
    for forbidden in (
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:PutObject",
        "s3:BypassGovernanceRetention",
        "s3:PutObjectRetention",
    ):
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
            admins = {
                "arn:aws:iam::<ACCOUNT>:root",
                f"{ACCOUNT_ROLE}<ADMIN_ROLE>",
                f"{ACCOUNT_ROLE}<AUDIT_ADMIN_ROLE>",
            }
            if p & admins and actions(s) & KMS_USE:
                v.append(f"{name}/{s.get('Sid')}: an administrator may use the key")
    for s in allows(t["dataset-kms-key-statements"]):
        if not principals(s) & {role("api"), role("ingest"), role("operator")}:
            continue
        cond = s.get("Condition", {}).get("StringEquals", {})
        if cond != {
            "kms:ViaService": "s3.us-east-1.amazonaws.com",
            "kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::<BUCKET>",
        }:
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
    for must in (
        "/run/nlw/aws/api/credentials",
        "/run/nlw/aws/ingest/credentials",
        "The API container mounts only `/run/nlw/aws/api`",
        "The ingest container mounts only `/run/nlw/aws/ingest`",
    ):
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


def all_code(text: str) -> list[tuple[str, str]]:
    """(where, body) for every command block and every shell file block."""
    out = [(b["label"]["id"] if b["label"] else "?", b["body"]) for b in labelled_blocks(text)]
    out += [(name, body) for name, body in FILE_BLOCK.findall(text) if name.endswith(".sh")]
    return out


def block(text: str, step: str) -> str:
    (body,) = [b["body"] for b in labelled_blocks(text) if b["label"] and b["label"]["id"] == step]
    return str(body)


def label_violations(text: str) -> list[str]:
    v = []
    for b in labelled_blocks(text):
        label = b["label"]
        if label is None:
            v.append(f"unlabelled command block at offset {b['start']}")
            continue
        sid, cls = label["id"], label["cls"]
        try:
            cmds = commands(b["body"])
        except ValueError as exc:
            v.append(f"{sid} cannot be parsed: {exc}")
            continue
        ops = [(c, call) for c in cmds if (call := aws_call(c))]
        writes = [call for _, call in ops if not is_read(call[1])]
        if cls == "READ-ONLY" and writes:
            v.append(f"{sid} is READ-ONLY but calls {writes}")
        if cls == "MUTATING" and not writes:
            v.append(f"{sid} is MUTATING but makes no mutating call")
        if cls in ("HOST", "LOCAL") and ops:
            v.append(f"{sid} is {cls} but calls AWS")
        if label["deny"]:
            for c, call in ops:
                if c.wrapper is None:
                    v.append(f"{sid} is EXPECT-DENIED but {call} is not wrapped in expect_*")
            for line in {c.line for c in cmds if c.wrapper}:
                top = [c for c in cmds if c.line == line and not c.nested]
                if len(top) != 1:
                    v.append(f"{sid}: an expectation shares its line with another command")
        if (
            not ops
            and cls in ("READ-ONLY", "MUTATING")
            and not any(c.name in ("probe", "write_credentials") for c in cmds)
        ):
            v.append(f"{sid} is {cls} but contains no AWS call")
    ids = [b["label"]["id"] for b in labelled_blocks(text) if b["label"]]
    if len(ids) != len(set(ids)):
        v.append("duplicate step ids")
    return v


VAR_REF = re.compile(r"\$\{!?([A-Za-z_][A-Za-z0-9_]*)[^}]*\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def assignments(body: str) -> list[tuple[str, str]]:
    """NAME=value pairs in order, from plain assignments and export/local."""
    out = []
    for line in logical_lines(body):
        for words, _ in _split(line, False):
            if words and words[0] in ("export", "local", "readonly"):
                words = words[1:]
            for w in words:
                if not ASSIGNMENT.match(w):
                    break
                name, value = w.split("=", 1)
                out.append((name, value))
    return out


def expand(value: str, env: dict[str, str]) -> str:
    for _ in range(6):
        new = VAR_REF.sub(lambda m: env.get(m.group(1) or m.group(2), ""), value)
        if new == value:
            break
        value = new
    return value


def production_env(text: str) -> tuple[dict[str, str], set[str]]:
    """Variables from lib.sh and every block, and those that resolve to production."""
    env: dict[str, str] = {}
    for _, body in all_code(text):
        for name, value in assignments(body):
            env.setdefault(name, value)
    resolved = {k: expand(v, env) for k, v in env.items()}
    forbidden = {k for k, v in resolved.items() if "production" in v} | {"OTHER_BUCKET", "PROD_KEY"}
    return resolved, forbidden


def staging_only_violations(text: str) -> list[str]:
    v = []
    env, forbidden = production_env(text)
    for b in labelled_blocks(text):
        if not b["label"] or b["label"]["cls"] != "MUTATING":
            continue
        sid, local = b["label"]["id"], dict(env)
        for name, value in assignments(b["body"]):
            local[name] = expand(value, local)
        for c in commands(b["body"]):
            names = {m.group(1) or m.group(2) for m in VAR_REF.finditer(c.text)}
            if names & forbidden:
                v.append(f"{sid}: {c.name} references {sorted(names & forbidden)}")
            if "production" in expand(c.text, local) or "production" in c.text:
                v.append(f"{sid}: {c.name} resolves to a production name")
    (inventory,) = re.findall(r"<!-- inventory -->\n```json\n(.*?)```", text, re.S)
    for item in json.loads(inventory):
        name = item["name"]
        if "production" in name or (item["type"] != "AWS::S3::Object" and "staging" not in name):
            v.append(f"inventory item {item['id']} is not a staging resource: {name}")
    for var in ("BUCKET", "AUDIT_BUCKET", "TRAIL", "KEY_ALIAS", "AUDIT_KEY_ALIAS"):
        value = env.get(var, "")
        if "staging" not in value or "production" in value:
            v.append(f"lib.sh {var} is not a staging name")
    return v


SECRET_NAMES = re.compile(
    r"AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AWS_ACCESS_KEY_ID|SecretAccessKey|SessionToken"
)
CREDENTIAL_ISSUING = {
    ("sts", "assume-role"),
    ("sts", "get-session-token"),
    ("sts", "get-federation-token"),
    ("sts", "assume-role-with-saml"),
    ("sts", "assume-role-with-web-identity"),
}


def secret_print_violations(text: str) -> list[str]:
    v = []
    for where, body in all_code(text):
        for c in commands(body):
            w = c.words
            if "--debug" in w or (c.name == "set" and any(re.match(r"-\w*x", a) for a in w[1:])):
                v.append(f"{where}: debug tracing would print secrets")
            if c.name in ("env", "printenv") or (c.name == "set" and len(w) == 1):
                v.append(f"{where}: {c.name} prints the environment")
            if c.name in ("export", "declare", "typeset") and "-p" in w:
                v.append(f"{where}: {c.name} -p prints the environment")
            if c.name in ("echo", "printf") and any(SECRET_NAMES.search(a) for a in w[1:]):
                v.append(f"{where}: {c.name} prints a credential")
            if c.name in ("cat", "less", "more", "head", "tail", "strings", "xxd", "od") and any(
                "credentials" in a for a in w[1:]
            ):
                v.append(f"{where}: {c.name} prints a credential file")
            call = aws_call(c)
            if call == ("configure", "get") and any(
                re.search(r"secret|session|access_key", a) for a in w
            ):
                v.append(f"{where}: aws configure get prints a credential")
            if call == ("configure", "list"):
                v.append(f"{where}: aws configure list prints credential fragments")
            if call in CREDENTIAL_ISSUING:
                query = w[w.index("--query") + 1] if "--query" in w[:-1] else None
                if query is None or "Credentials" in query:
                    v.append(f"{where}: {call[1]} output is not restricted")
            if call == ("configure", "export-credentials"):
                toks = _tokens(c.line)
                if "|" not in toks[toks.index("export-credentials") :]:
                    v.append(f"{where}: export-credentials is not piped into the writer")
    return v


def cleanup_violations(text: str) -> list[str]:
    v = []
    for b in labelled_blocks(text):
        label = b["label"]
        if not label or not label["id"].startswith("X"):
            continue
        for _, op, c in aws_ops(b["body"]):
            if is_read(op):
                continue
            if not re.search(r"\$\{(REC_|!v)", c.text):
                v.append(f"{label['id']} {op} does not use a recorded id")
            unexpanded = re.sub(r"\$\{[^}]*\}", "", c.text)  # ${v##*/} trims, it is no glob
            if "*" in unexpanded or "--recursive" in c.words or "--force" in c.words:
                v.append(f"{label['id']} {op} uses a wildcard, --recursive or --force")
            if c.words[1:2] == ["s3"]:
                v.append(f"{label['id']} uses the high-level s3 commands")
    return v


STOP_IDS = [f"S{n}" for n in range(1, 11)]


def stop_violations(text: str) -> list[str]:
    """Each stop condition is defined, and is the target of an executable
    ``stop`` call (or the S2 override that ``absent`` uses): a mention in a
    comment, a string or an ``echo`` does not count."""
    v = []
    enforced: set[str] = set()
    for _, body in all_code(text):
        for c in commands(body):
            if c.name == "stop" and len(c.words) > 1:
                enforced |= set(re.findall(r"S\d+", c.words[1]))
            for a in c.assignments:
                if a.startswith("ON_ALLOWED="):
                    enforced |= set(re.findall(r"S\d+", a))
    for sid in STOP_IDS:
        if f"| **{sid}** |" not in text:
            v.append(f"stop condition {sid} is not defined")
        if sid not in enforced:
            v.append(f"stop condition {sid} is never enforced by an executable stop")
    return v


def _call_index(cmds: list[Cmd], service: str, op: str, after: int = -1) -> int:
    for i, c in enumerate(cmds):
        if i > after and aws_call(c) == (service, op):
            return i
    return -1


def bucket_creation_violations(text: str) -> list[str]:
    """H1: absence checked in the same block right before create-bucket; the
    new bucket proven pristine before any configuration; ledger written only
    after that."""
    v = []
    for step, ledger in (("P03-06", "REC_BUCKET"), ("P03-07", "REC_AUDIT_BUCKET")):
        cmds = commands(block(text, step))
        create = _call_index(cmds, "s3api", "create-bucket")
        head = _call_index(cmds, "s3api", "head-bucket")
        if (
            create < 0
            or not (0 <= head < create)
            or cmds[head].wrapper != "absent"
            or (cmds[head].wrapper_arg != "404")
        ):
            v.append(f"{step}: create-bucket is not preceded by an absence check in its block")
            continue
        configure = next(
            (
                i
                for i, c in enumerate(cmds)
                if i > create and (call := aws_call(c)) and call[1].startswith("put-")
            ),
            len(cmds),
        )
        records = [i for i, c in enumerate(cmds) if c.name == "record" and c.words[1:2] == [ledger]]
        pristine = [
            i
            for i, c in enumerate(cmds)
            if i > create
            and (c.wrapper == "absent" or aws_call(c) == ("s3api", "list-object-versions"))
        ]
        checks = {
            ("get-bucket-tagging", "NoSuchTagSet"),
            ("get-bucket-policy", "NoSuchBucketPolicy"),
        }
        for c in cmds[create + 1 : configure]:
            call = aws_call(c)
            if call and c.wrapper == "absent":
                checks.discard((call[1], c.wrapper_arg or ""))
        if checks:
            v.append(f"{step}: pristine checks missing before configuration: {sorted(checks)}")
        if not any(
            aws_call(c) == ("s3api", "list-object-versions") for c in cmds[create + 1 : configure]
        ):
            v.append(f"{step}: the new bucket is not checked for existing objects")
        if not any(c.name == "stop" and c.words[1:2] == ["S2"] for c in cmds[create:configure]):
            v.append(f"{step}: a non-pristine bucket does not stop with S2")
        if not records or not pristine or not all(max(pristine) < i < configure for i in records):
            v.append(f"{step}: the ledger entry is not written after the pristine checks")
    lib = dict(FILE_BLOCK.findall(text))["lib.sh"]
    if '"$SUFFIX" =~ ^-d6[0-9a-f]{12}$' not in lib or '"${BUCKET_SUFFIX:?}"' not in lib:
        v.append("lib.sh does not require a high-entropy proof suffix")
    if 'export BUCKET_SUFFIX="-d6$(openssl rand -hex 6)"' not in block(text, "P00-01"):
        v.append("P00 does not generate a random proof suffix")
    return v


PROOF_KEY_ENV = {"REC_PROOF_WS": "<WS1>", "REC_PROOF_WS2": "<WS2>"}
WRITE_OPS = {
    "put-object",
    "copy-object",
    "create-multipart-upload",
    "complete-multipart-upload",
    "delete-object",
    "delete-objects",
    "upload-part",
}


def denied_write_violations(text: str) -> list[str]:
    """Every write the proof expects to be refused targets a key inside the
    proof's own random prefixes (or the one recorded outside key), so R-OBJ
    can find whatever an unexpected success leaves behind."""
    v = []
    for b in labelled_blocks(text):
        if not b["label"] or not b["label"]["id"].startswith("P"):
            continue
        env = dict(PROOF_KEY_ENV)
        env.update({f"REC_OBJ_K{n}": f"versions/<WS1>/k{n}" for n in range(1, 10)})
        env.update({f"REC_MPU_K{n}": f"versions/<WS1>/k{n}" for n in range(1, 10)})
        for name, value in assignments(b["body"]):
            env[name] = expand(value, env)
        for c in commands(b["body"]):
            call = aws_call(c)
            if not (c.wrapper and call and call[1] in WRITE_OPS) or "--key" not in c.words:
                continue
            key = expand(c.words[c.words.index("--key") + 1], env)
            if not (
                key.startswith(("versions/<WS1>/", "versions/<WS2>/")) or key == "outside/<WS1>/x"
            ):
                v.append(f"{b['label']['id']}: expected-denied {call[1]} on {key}")
    return v


def recovery_violations(text: str) -> list[str]:
    """M2: R-OBJ inspects only the proof's exact prefixes, records exact ids,
    and feeds them into the ordinary, recorded-id cleanup."""
    v = []
    x10 = commands(block(text, "X10"))
    prefixes = [
        c.words[c.words.index("--prefix") + 1]
        for c in x10
        if aws_call(c) == ("s3api", "list-object-versions")
    ]
    if prefixes != ["versions/$ws/"] or not any(
        c.name == "for" and c.words[1:] == ["ws", "in", "$REC_PROOF_WS", "$REC_PROOF_WS2"]
        for c in x10
    ):
        v.append("X10 does not list exactly the two recorded proof prefixes")
    if not any(c.name == "nlw-proof-operator" or "nlw-proof-operator" in c.words for c in x10):
        v.append("X10 does not list as the MFA operator")
    body = block(text, "X10")
    if '[[ "$modified" > "$started" ]] || stop S8' not in body:
        v.append("X10 does not refuse versions older than the proof run")
    if '[[ "$key" == "versions/$ws/"* ]] || stop S8' not in body:
        v.append("X10 does not refuse keys outside the prefix")
    if not any(c.name == "record" and c.words[1].startswith("REC_RECOVERED_") for c in x10):
        v.append("X10 does not record what it finds")
    x11 = commands(block(text, "X11"))
    heads = [c for c in x11 if aws_call(c) == ("s3api", "head-object")]
    if (
        len(heads) != 1
        or heads[0].words[heads[0].words.index("--key") + 1] != "$OUTSIDE"
        or ('OUTSIDE="outside/$REC_PROOF_WS/x"' not in block(text, "X11"))
        or "nlw-proof-admin" not in heads[0].words
    ):
        v.append("X11 does not check exactly the one outside key as the administrator")
    if "REC_RECOVERED_" not in block(text, "X04"):
        v.append("X04 does not purge recovered versions")
    x05 = commands(block(text, "X05"))
    listing = [c for c in x05 if aws_call(c) == ("s3api", "list-object-versions")]
    if (
        len(listing) != 1
        or listing[0].words[listing[0].words.index("--prefix") + 1] != "versions/"
        or (
            not any(
                c.name == "stop" and c.words[1:2] == ["S8"] and c.line == listing[0].line
                for c in x05
            )
        )
    ):
        v.append("X05 no longer refuses unrecorded versions")
    return v


def commit_binding_violations(text: str) -> list[str]:
    v = []
    p00 = [c for c in commands(block(text, "P00-01"))]
    first_effect = next(i for i, c in enumerate(p00) if c.name in ("mkdir", "python3"))
    guards = [
        i
        for i, c in enumerate(p00)
        if c.name == "[[" and ("$REVIEWED_COMMIT" in c.words or "--porcelain" in c.text)
    ]
    if len(guards) < 2 or max(guards) > first_effect:
        v.append("P00 does not bind HEAD and a clean tree before acting")
    lib = dict(FILE_BLOCK.findall(text))["lib.sh"]
    if not re.search(r"render\(\) \{\n  verify_reviewed_commit\n", lib):
        v.append("render does not verify the reviewed commit first")
    return v


PASS_DENY = {
    "iam:PassRole",
    "ec2:AssociateIamInstanceProfile",
    "ec2:ReplaceIamInstanceProfileAssociation",
}


def pass_role_violations(t: Templates, text: str) -> list[str]:
    v = []
    for name in ALL_ROLES:
        s = by_sid(t[name]).get("NeverPassOrAttachDatasetRoles", {})
        if not (
            s.get("Effect") == "Deny"
            and actions(s) == PASS_DENY
            and s.get("Resource") == "*"
            and "Condition" not in s
        ):
            v.append(f"{name} may pass or attach roles")
    p0311 = block(text, "P03-11")
    if (
        "for r in bootstrap api ingest operator audit-admin audit-reader; do" not in p0311
        or not any(
            aws_call(c) == ("iam", "simulate-principal-policy") and "iam:PassRole" in c.words
            for c in commands(p0311)
        )
    ):
        v.append("P03-11 does not simulate PassRole for all six roles")
    return v


def budget_violations(text: str) -> list[str]:
    v = []
    ids = [b["label"]["id"] for b in labelled_blocks(text) if b["label"]]
    mutating = [
        b["label"]["id"]
        for b in labelled_blocks(text)
        if b["label"] and b["label"]["cls"] == "MUTATING"
    ]
    if "P03-00" not in ids or mutating[0] != "P03-00":
        v.append("the budget alert is not the first resource the proof creates")
        return v
    calls = [aws_call(c) for c in commands(block(text, "P03-00"))]
    for needed in (
        ("budgets", "create-budget"),
        ("budgets", "describe-budget"),
        ("budgets", "describe-notifications-for-budget"),
    ):
        if needed not in calls:
            v.append(f"P03-00 lacks {needed[1]}")
    if block(text, "P03-00").count("|| stop S9") < 2:
        v.append("P03-00 does not stop when the budget or its alert differs")
    for doc in (text, DECISIONS.read_text()):
        if "enforced with an AWS Budgets alert" in doc:
            v.append("a budget alert is described as enforcement")
    return v


def cleanup_identity_violations(text: str) -> list[str]:
    v = []
    x01 = block(text, "X01")
    for case in (
        'REC_TRAIL_ARN) [[ "$value" == "$TRAIL_ARN" ]] ;;',
        'REC_PROFILE_BOOTSTRAP) [[ "$value" == '
        '"arn:aws:iam::${ACCOUNT}:instance-profile/nlw-staging-dataset-bootstrap" ]] ;;',
        'REC_PROOF_ID) [[ "$value" == "$PROOF_ID" ]] ;;',
    ):
        if case not in x01:
            v.append(f"X01 does not check {case.split(')')[0]}")
    calls = {aws_call(c) for c in commands(block(text, "X02"))}
    for needed in (
        ("iam", "list-instance-profile-tags"),
        ("cloudtrail", "list-tags"),
        ("iam", "get-instance-profile"),
        ("cloudtrail", "get-trail"),
    ):
        if needed not in calls:
            v.append(f"X02 lacks {needed[1]}")
    lib = dict(FILE_BLOCK.findall(text))["lib.sh"]
    if '[[ "${REC_PROOF_ID:-}" == "$PROOF_ID" ]] || stop S8' not in lib:
        v.append("the ledger is not bound to the proof run")
    return v


CONFIG_ACTIONS = {
    "s3:PutReplicationConfiguration",
    "s3:PutInventoryConfiguration",
    "s3:PutAnalyticsConfiguration",
    "s3:PutMetricsConfiguration",
    "s3:PutIntelligentTieringConfiguration",
    "s3:PutAccelerateConfiguration",
}


def config_deny_violations(t: Templates) -> list[str]:
    v = []
    for name, sid in (
        ("dataset-bucket-policy", "DenyBucketConfigExceptAdmin"),
        ("audit-bucket-policy", "DenyBucketConfigExceptAuditAdmin"),
    ):
        missing = CONFIG_ACTIONS - actions(by_sid(t[name]).get(sid, {}))
        if missing:
            v.append(f"{name}/{sid} does not deny {sorted(missing)}")
    return v


def untagged_key_violations(t: Templates) -> list[str]:
    s = by_sid(t["role-audit-admin"]).get("TagOnlyUntaggedKeys", {})
    ok = actions(s) == {"kms:TagResource"} and s.get("Condition", {}).get("Null") == {
        "aws:ResourceTag/nlw-env": "true"
    }
    grants_tag = [
        x.get("Sid")
        for x in allows(t["role-audit-admin"])
        if "kms:TagResource" in actions(x) and x.get("Sid") != "TagOnlyUntaggedKeys"
    ]
    return ([] if ok else ["audit admin may tag keys that already carry nlw-env"]) + [
        f"{sid} also grants kms:TagResource" for sid in grants_tag
    ]


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


def test_every_role_grants_exactly_its_pinned_statements() -> None:
    assert role_statement_violations(load_templates()) == []


def test_every_policy_principal_is_allow_listed_with_its_actions_and_condition() -> None:
    assert principal_violations(load_templates()) == []


def test_bucket_creation_is_guarded_in_the_same_block() -> None:
    assert bucket_creation_violations(proof_text()) == []


def test_every_expected_denied_write_stays_inside_the_proof_prefixes() -> None:
    assert denied_write_violations(proof_text()) == []


def test_unledgered_objects_are_recovered_by_exact_ids_only() -> None:
    assert recovery_violations(proof_text()) == []


def test_execution_is_bound_to_the_reviewed_clean_commit() -> None:
    assert commit_binding_violations(proof_text()) == []


def test_no_dataset_or_audit_role_may_pass_or_attach_roles() -> None:
    assert pass_role_violations(load_templates(), proof_text()) == []


def test_the_budget_alert_is_created_verified_and_not_called_enforcement() -> None:
    assert budget_violations(proof_text()) == []


def test_cleanup_verifies_trail_and_instance_profile_identity() -> None:
    assert cleanup_identity_violations(proof_text()) == []


def test_bucket_configuration_denies_cover_replication_and_inventory() -> None:
    assert config_deny_violations(load_templates()) == []


def test_the_audit_admin_can_tag_only_untagged_keys() -> None:
    assert untagged_key_violations(load_templates()) == []


def test_every_owner_decision_is_open_with_options_and_a_recommendation() -> None:
    text = DECISIONS.read_text()
    rows = re.findall(r"^\| \*\*(E\d+)\*\* \| (.+?) \| (.+?) \| (.+?) \|$", text, re.M)
    assert [r[0] for r in rows] == [f"E{n}" for n in range(1, 14)]
    for _, _, options, recommendation in rows:
        assert options.strip() and recommendation.strip()
    assert "every decision below is open" in text
    assert "E11, E12 and E13 are **required before D6**" in text
    e11 = next(r for r in rows if r[0] == "E11")
    assert "aws:MultiFactorAuthPresent" in e11[3] and "role chaining" in e11[3]
    assert "**fails closed**" in e11[3] and "separately reviewed trust-policy design" in e11[3]
    assert "not chosen here" in e11[3]
    assert '[[ "$E11_IDENTITY" == iam-user-mfa ]]' in block(proof_text(), "P00-01")


def test_overclaims_are_corrected() -> None:
    review, prov, proof = REVIEW.read_text(), PROVISIONING.read_text(), proof_text()
    assert "audit key cannot be scheduled for deletion" not in review
    assert "Nobody may schedule this key's deletion" not in prov
    assert "cannot be scheduled\n  for deletion **without first changing its key policy**" in prov
    assert "no IMDS fallback even when IMDS is reachable" not in proof
    assert "it does **not** show what happens when a running" in proof
    assert "mid-run expiry with IMDS reachable is untested until P14-05 runs" in review


def test_the_multipart_fallback_is_stated_as_an_application_change() -> None:
    prov = PROVISIONING.read_text()
    assert "is **an application change**" in prov
    assert "which is viable because uploads are capped at 25 MB" not in prov


def test_stand_in_limits_shared_uid_and_open_aws_questions_are_documented() -> None:
    proof, review = proof_text(), REVIEW.read_text()
    for item in (
        "systemd scheduling",
        "retry and backoff",
        "tmpfs",
        "host reboot",
        "refresh-failure alert",
        "both run as uid\n10001",
    ):
        assert item in proof, item
    for rid in ("**R7**", "**R8**", "**R9**", "**R10**", "**I1**", "**I2**", "**I3**", "**I4**"):
        assert rid in review, rid


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


DUMMY_ACCOUNT = "111122223333"
GOOD_SUFFIX = "-d6" + "a1b2c3d4e5f6"


def _reviewed_repo(tmp_path: Path) -> tuple[Path, str]:
    """A throwaway git repository holding the provisioning runbook, standing in
    for the reviewed checkout."""
    repo = tmp_path / "repo"
    (repo / "docs" / "runbooks").mkdir(parents=True)
    shutil.copy(PROVISIONING, repo / "docs" / "runbooks" / PROVISIONING.name)
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "--no-gpg-sign", "-m", "r"]):
        subprocess.run(["git", "-C", str(repo), *args], check=True, env=env)
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    ).stdout.strip()
    return repo, head


def _lib_run(tmp_path: Path, script: str, **overrides: str) -> subprocess.CompletedProcess[str]:
    repo, head = _reviewed_repo(tmp_path)
    proof_dir = tmp_path / "proof"
    proof_dir.mkdir(exist_ok=True)
    lib = proof_dir / "lib.sh"
    lib.write_text(dict(FILE_BLOCK.findall(proof_text()))["lib.sh"])
    kms = f"arn:aws:kms:us-east-1:{DUMMY_ACCOUNT}:key"
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "PROOF_DIR": str(proof_dir),
        "PROOF_ID": "d6-test",
        "APPROVED_ACCOUNT": DUMMY_ACCOUNT,
        "BUCKET_SUFFIX": GOOD_SUFFIX,
        "RUNBOOK_DIR": str(repo / "docs" / "runbooks"),
        "REVIEWED_COMMIT": head,
        "ADMIN_ROLE": "nlw-test-admin",
        "REC_KEY_ARN": f"{kms}/{'1' * 8}-1111-1111-1111-{'1' * 12}",
        "REC_AUDIT_KEY_ARN": f"{kms}/{'2' * 8}-2222-2222-2222-{'2' * 12}",
        "HUMANS": json.dumps([f"arn:aws:iam::{DUMMY_ACCOUNT}:role/human-{x}" for x in "ab"]),
        "AUDIT_RETENTION_DAYS": "90",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    env.update(overrides)
    if overrides.get("DIRTY"):
        (repo / "docs" / "runbooks" / PROVISIONING.name).write_text("tampered")
    return subprocess.run(
        ["bash", "-c", f'source "{lib}" && {script}'],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


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


needs_bash_and_git = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("git") is None, reason="bash and git are required"
)


@needs_bash_and_git
def test_every_template_renders_completely_and_within_size_limits(tmp_path: Path) -> None:
    """Run the proof's own ``render`` (lib.sh) offline, from a reviewed clean
    checkout, with dummy session values: every template fills every
    placeholder, parses, and fits the AWS size limit for its kind."""
    names = list(load_templates())
    script = "; ".join(f'render {n} > "$PROOF_DIR/{n}.json"' for n in names)
    result = _lib_run(tmp_path, script)
    assert result.returncode == 0, result.stderr
    for name in names:
        rendered = json.dumps(
            json.loads((tmp_path / "proof" / f"{name}.json").read_text()), separators=(",", ":")
        )
        assert "<" not in rendered, name
        limit = _limit_for(name)
        if limit is not None:
            assert len(rendered) <= limit, (name, len(rendered), limit)
    lifecycle = json.loads((tmp_path / "proof" / "audit-bucket-lifecycle.json").read_text())
    assert lifecycle["Rules"][0]["Expiration"]["Days"] == 91


@needs_bash_and_git
def test_rendering_refuses_a_template_with_an_unfilled_placeholder(tmp_path: Path) -> None:
    result = _lib_run(tmp_path, "render role-api", REC_KEY_ARN="")
    assert result.returncode != 0 and "unfilled placeholder" in result.stderr
    assert result.stdout == ""


@needs_bash_and_git
@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"REVIEWED_COMMIT": "0" * 40}, "STOP S9: the checkout is not the reviewed commit"),
        ({"DIRTY": "1"}, "STOP S9: the checkout has local changes"),
        ({"REVIEWED_COMMIT": "main"}, "STOP S9: REVIEWED_COMMIT is not a full commit id"),
    ],
    ids=["wrong commit", "dirty tree", "symbolic ref"],
)
def test_negative_control_rendering_refuses_an_unreviewed_checkout(
    tmp_path: Path, overrides: dict[str, str], expected: str
) -> None:
    result = _lib_run(tmp_path, "render role-api", **overrides)
    assert result.returncode != 0 and expected in result.stderr
    assert result.stdout == ""


@needs_bash_and_git
@pytest.mark.parametrize(
    ("script", "overrides", "expected"),
    [
        ("true", {"BUCKET_SUFFIX": "-a1"}, "STOP S1: BUCKET_SUFFIX is not this proof's suffix"),
        ("true", {"BUCKET_SUFFIX": ""}, "BUCKET_SUFFIX"),
        ("record REC_X ''", {}, "STOP S10: a create returned no identifier"),
        ("false", {}, "STOP S10: command failed"),
        ("expect_denied true", {}, "STOP S4: allowed, expected AccessDenied"),
        ("absent 404 true", {}, "STOP S2: allowed, expected 404"),
        ("record REC_X 'a*b'", {}, "STOP S8: wildcard ledger value"),
    ],
    ids=[
        "weak suffix",
        "no suffix",
        "create without id",
        "failed command",
        "unexpected success",
        "resource already exists",
        "wildcard ledger value",
    ],
)
def test_negative_control_lib_stops_with_the_right_condition(
    tmp_path: Path, script: str, overrides: dict[str, str], expected: str
) -> None:
    result = _lib_run(tmp_path, script, **overrides)
    assert result.returncode != 0 and expected in result.stderr, result.stderr


@needs_bash_and_git
def test_negative_control_a_ledger_from_another_run_is_refused(tmp_path: Path) -> None:
    (tmp_path / "proof").mkdir()
    (tmp_path / "proof" / "created.env").write_text("REC_PROOF_ID=d6-other\n")
    result = _lib_run(tmp_path, "true")
    assert result.returncode != 0
    assert "STOP S8: the ledger belongs to another proof run" in result.stderr


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
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
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
    (
        "bucket cross-env deny removed",
        lambda t: _drop_sid(t, "dataset-bucket-policy", "DenyOtherEnvironmentRoles"),
        cross_environment_violations,
    ),
    (
        "operator cross-env deny removed",
        lambda t: _drop_sid(t, "role-operator", "NeverOtherEnvironment"),
        cross_environment_violations,
    ),
    (
        "api cross-env deny made conditional",
        lambda t: _sid(t, "role-api", "NeverOtherEnvironment").update(
            Condition={"StringNotEquals": {"aws:ResourceTag/nlw-env": "<ENV>"}}
        ),
        cross_environment_violations,
    ),
    (
        "ingest key-tag deny removed",
        lambda t: _drop_sid(t, "role-ingest", "NeverOtherEnvironmentKeys"),
        cross_environment_violations,
    ),
    # SSE-KMS weakened
    (
        "missing-key-header deny removed",
        lambda t: _drop_sid(t, "dataset-bucket-policy", "DenyMissingSseKmsKeyHeader"),
        sse_kms_violations,
    ),
    (
        "wrong-key deny switched to IfExists",
        lambda t: _sid(t, "dataset-bucket-policy", "DenyWrongSseKmsKey").update(
            Condition={"StringNotEqualsIfExists": {SSE_KEY_ID: "<KEY_ARN>"}}
        ),
        sse_kms_violations,
    ),
    (
        "wrong-key deny accepts any key",
        lambda t: _sid(t, "dataset-bucket-policy", "DenyWrongSseKmsKey").update(
            Condition={"StringNotLike": {SSE_KEY_ID: "arn:aws:kms:*"}}
        ),
        sse_kms_violations,
    ),
    (
        "algorithm deny allows AES256",
        lambda t: _sid(t, "dataset-bucket-policy", "DenyWrongSseAlgorithm").update(
            Condition={
                "StringNotEquals": {"s3:x-amz-server-side-encryption": ["aws:kms", "AES256"]}
            }
        ),
        sse_kms_violations,
    ),
    (
        "encryption deny limited to versions/",
        lambda t: _sid(t, "dataset-bucket-policy", "DenyMissingSseAlgorithmHeader").update(
            Resource="arn:aws:s3:::<BUCKET>/versions/*"
        ),
        sse_kms_violations,
    ),
    # conditional writes removed
    (
        "unconditional-create deny removed",
        lambda t: _drop_sid(t, "dataset-bucket-policy", "DenyUnconditionalCreate"),
        conditional_write_violations,
    ),
    (
        "unconditional-create deny loses If-None-Match",
        lambda t: _sid(t, "dataset-bucket-policy", "DenyUnconditionalCreate").update(
            Condition={"Bool": {"s3:ObjectCreationOperation": "true"}}
        ),
        conditional_write_violations,
    ),
    (
        "server-side copy allowed",
        lambda t: _drop_sid(t, "dataset-bucket-policy", "DenyServerSideCopy"),
        conditional_write_violations,
    ),
    # runtime delete access added
    (
        "api may delete objects",
        lambda t: _sid(t, "role-api", "CreateOnce").update(
            Action=["s3:PutObject", "s3:AbortMultipartUpload", "s3:DeleteObject"]
        ),
        runtime_delete_violations,
    ),
    (
        "ingest may delete versions",
        lambda t: _sid(t, "role-ingest", "ReadVersions").update(
            Action=["s3:GetObject", "s3:DeleteObjectVersion"]
        ),
        runtime_delete_violations,
    ),
    (
        "operator may add delete markers",
        lambda t: _sid(t, "role-operator", "PurgeAndVerify")["Action"].append("s3:DeleteObject"),
        runtime_delete_violations,
    ),
    (
        "bucket lets the api delete",
        lambda t: _sid(t, "dataset-bucket-policy", "DenyDeleteExceptOperator")["Condition"][
            "ArnNotEquals"
        ]["aws:PrincipalArn"].append(role("api")),
        runtime_delete_violations,
    ),
    # the instance role can assume the operator role
    (
        "bootstrap may assume the operator",
        lambda t: _sid(t, "role-bootstrap", "AssumeRuntimeRolesOnly")["Resource"].append(
            role("operator")
        ),
        instance_role_violations,
    ),
    (
        "bootstrap's explicit role deny removed",
        lambda t: _drop_sid(t, "role-bootstrap", "NeverAssumeAnyOtherRole"),
        instance_role_violations,
    ),
    (
        "human trust admits the bootstrap role",
        lambda t: _sid(t, "trust-human-mfa", "NamedHumansWithMfa").update(
            Principal={"AWS": ["<HUMAN_PRINCIPAL_ARNS>", role("bootstrap")]}
        ),
        instance_role_violations,
    ),
    (
        "human trust stops denying machine roles",
        lambda t: _drop_sid(t, "trust-human-mfa", "DenyMachineRoles"),
        instance_role_violations,
    ),
    (
        "api trust drops the session-name condition",
        lambda t: _sid(t, "trust-api", "BootstrapWithApiSessionName").pop("Condition"),
        instance_role_violations,
    ),
    (
        "operator trust without MFA",
        lambda t: _sid(t, "trust-human-mfa", "NamedHumansWithMfa").pop("Condition"),
        mfa_violations,
    ),
    (
        "operator trust without the missing-MFA deny",
        lambda t: _drop_sid(t, "trust-human-mfa", "DenyWithoutMfaContext"),
        mfa_violations,
    ),
    # audit tamper protection removed
    (
        "ingest may touch audit resources",
        lambda t: _drop_sid(t, "role-ingest", "NeverTouchAudit"),
        audit_tamper_violations,
    ),
    (
        "api may stop the trail",
        lambda t: _drop_sid(t, "role-api", "NeverAlterAnyTrail"),
        audit_tamper_violations,
    ),
    (
        "audit bucket admits dataset roles",
        lambda t: _drop_sid(t, "audit-bucket-policy", "DenyDatasetRoles"),
        audit_tamper_violations,
    ),
    (
        "audit logs deletable",
        lambda t: _drop_sid(t, "audit-bucket-policy", "DenyRecordDeletionExceptAuditAdmin"),
        audit_tamper_violations,
    ),
    (
        "audit key deletable",
        lambda t: _sid(t, "audit-kms-key-statements", "AdministerNeverUse")["Action"].append(
            "kms:ScheduleKeyDeletion"
        ),
        audit_tamper_violations,
    ),
    (
        "audit admin may delete log objects",
        lambda t: _sid(t, "role-audit-admin", "AdministerAuditBucket")["Action"].append(
            "s3:DeleteObjectVersion"
        ),
        audit_tamper_violations,
    ),
    # credential separation
    (
        "key policy lets ingest generate data keys (F1)",
        lambda t: _sid(
            t, "dataset-kms-key-statements", "ReadersDecryptViaS3ForThisBucketOnly"
        ).update(Action=["kms:GenerateDataKey", "kms:Decrypt"]),
        credential_separation_violations,
    ),
    (
        "api and ingest share a session name",
        lambda t: _sid(t, "trust-ingest", "BootstrapWithIngestSessionName").update(
            Condition={"StringEquals": {"sts:RoleSessionName": "nlw-<ENV>-api"}}
        ),
        credential_separation_violations,
    ),
    (
        "ingest may write",
        lambda t: _sid(t, "role-ingest", "ReadVersions")["Action"].append("s3:PutObject"),
        credential_separation_violations,
    ),
    # key policies and least privilege
    (
        "admin may decrypt with the dataset key",
        lambda t: _sid(t, "dataset-kms-key-statements", "AdministerNeverUse")["Action"].append(
            "kms:Decrypt"
        ),
        key_policy_violations,
    ),
    (
        "key use not bound to S3",
        lambda t: _sid(t, "dataset-kms-key-statements", "ApiEncryptViaS3ForThisBucketOnly").pop(
            "Condition"
        ),
        key_policy_violations,
    ),
    (
        "api role gains s3:*",
        lambda t: _sid(t, "role-api", "CreateOnce").update(Action="s3:*"),
        least_privilege_violations,
    ),
    (
        "ingest reads every bucket",
        lambda t: _sid(t, "role-ingest", "ReadVersions").update(Resource="*"),
        least_privilege_violations,
    ),
    # H2: the escalations the security review found the tests accepted
    (
        "key policy grants kms:Decrypt to Principal *",
        lambda t: t["dataset-kms-key-statements"].append(
            {
                "Sid": "X",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "kms:Decrypt",
                "Resource": "*",
            }
        ),
        principal_violations,
    ),
    (
        "audit bucket grants GetObject to Principal *",
        lambda t: t["audit-bucket-policy"]["Statement"].append(
            {
                "Sid": "X",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::<AUDIT_BUCKET>/*",
            }
        ),
        principal_violations,
    ),
    (
        "trust-bootstrap gains a second wildcard Allow (principals)",
        lambda t: t["trust-bootstrap"]["Statement"].append(
            {"Sid": "X", "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}
        ),
        principal_violations,
    ),
    (
        "trust-bootstrap gains a second wildcard Allow (instance role)",
        lambda t: t["trust-bootstrap"]["Statement"].append(
            {"Sid": "X", "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}
        ),
        instance_role_violations,
    ),
    (
        "operator gains s3:PutObject",
        lambda t: _sid(t, "role-operator", "PurgeAndVerify")["Action"].append("s3:PutObject"),
        role_statement_violations,
    ),
    (
        "operator gains sts:AssumeRole on role/* (pinned)",
        lambda t: t["role-operator"]["Statement"].append(
            {
                "Sid": "X",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::<ACCOUNT>:role/*",
            }
        ),
        role_statement_violations,
    ),
    (
        "operator gains sts:AssumeRole on role/* (least privilege)",
        lambda t: t["role-operator"]["Statement"].append(
            {
                "Sid": "X",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::<ACCOUNT>:role/*",
            }
        ),
        least_privilege_violations,
    ),
    (
        "audit reader gains DeleteObjectVersion",
        lambda t: _sid(t, "role-audit-reader", "ReadAuditLogs")["Action"].append(
            "s3:DeleteObjectVersion"
        ),
        role_statement_violations,
    ),
    (
        "audit admin gains iam:PutRolePolicy",
        lambda t: t["role-audit-admin"]["Statement"].append(
            {
                "Sid": "X",
                "Effect": "Allow",
                "Action": "iam:PutRolePolicy",
                "Resource": "arn:aws:iam::<ACCOUNT>:role/nlw-staging-dataset-api",
            }
        ),
        role_statement_violations,
    ),
    (
        "ingest condition relaxed on an existing statement",
        lambda t: _sid(t, "role-operator", "ListVersionsBounded").pop("Condition"),
        role_statement_violations,
    ),
    (
        "key policy grants ingest GenerateDataKey in a new statement",
        lambda t: t["dataset-kms-key-statements"].append(
            {
                "Sid": "X",
                "Effect": "Allow",
                "Principal": {"AWS": role("ingest")},
                "Action": "kms:GenerateDataKey",
                "Resource": "*",
                "Condition": VIA_S3,
            }
        ),
        principal_violations,
    ),
    (
        "key policy names an unknown principal",
        lambda t: _sid(t, "dataset-kms-key-statements", "ReadersDecryptViaS3ForThisBucketOnly")[
            "Principal"
        ]["AWS"].append("arn:aws:iam::<ACCOUNT>:role/someone"),
        principal_violations,
    ),
    (
        "runtime key grant loses its S3 condition",
        lambda t: _sid(t, "dataset-kms-key-statements", "ReadersDecryptViaS3ForThisBucketOnly").pop(
            "Condition"
        ),
        principal_violations,
    ),
    (
        "CloudTrail audit write loses SourceArn",
        lambda t: _sid(t, "audit-bucket-policy", "CloudTrailWriteThisTrailOnly")["Condition"][
            "StringEquals"
        ].pop("aws:SourceArn"),
        principal_violations,
    ),
    (
        "CloudTrail may write anywhere in the audit bucket",
        lambda t: _sid(t, "audit-bucket-policy", "CloudTrailWriteThisTrailOnly").update(
            Resource="arn:aws:s3:::<AUDIT_BUCKET>/*"
        ),
        principal_violations,
    ),
    (
        "api trust admits another principal",
        lambda t: _sid(t, "trust-api", "BootstrapWithApiSessionName").update(
            Principal={"AWS": [role("bootstrap"), role("operator")]}
        ),
        principal_violations,
    ),
    # M5, L1, L7
    (
        "audit admin may re-tag environment-tagged keys",
        lambda t: _sid(t, "role-audit-admin", "TagOnlyUntaggedKeys")["Condition"].pop("Null"),
        untagged_key_violations,
    ),
    (
        "replication configuration not denied",
        lambda t: _sid(t, "dataset-bucket-policy", "DenyBucketConfigExceptAdmin")["Action"].remove(
            "s3:PutReplicationConfiguration"
        ),
        config_deny_violations,
    ),
    (
        "audit inventory configuration not denied",
        lambda t: _sid(t, "audit-bucket-policy", "DenyBucketConfigExceptAuditAdmin")[
            "Action"
        ].remove("s3:PutInventoryConfiguration"),
        config_deny_violations,
    ),
    (
        "ingest may pass roles",
        lambda t: _drop_sid(t, "role-ingest", "NeverPassOrAttachDatasetRoles"),
        lambda t: pass_role_violations(t, proof_text()),
    ),
    (
        "audit reader may pass roles",
        lambda t: _drop_sid(t, "role-audit-reader", "NeverPassOrAttachDatasetRoles"),
        lambda t: pass_role_violations(t, proof_text()),
    ),
]


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
    (
        "production bucket written by the staging proof",
        lambda t: _insert_into(
            t,
            "P04-01",
            "aws s3api put-object --profile proof-api "
            '--bucket "nlw-production-datasets-${ACCOUNT}-us-east-1" '
            "--key k --body f",
        ),
        staging_only_violations,
    ),
    (
        "production role created by the staging proof",
        lambda t: _insert_into(
            t,
            "P03-01",
            "aws iam create-role "
            "--role-name nlw-production-dataset-api "
            "--assume-role-policy-document file://x",
        ),
        staging_only_violations,
    ),
    (
        "inventory names a production bucket",
        lambda t: t.replace(
            '"name": "nlw-staging-datasets-<ACCOUNT>-us-east-1<SUFFIX>"',
            '"name": "nlw-production-datasets-<ACCOUNT>-us-east-1<SUFFIX>"',
        ),
        staging_only_violations,
    ),
    (
        "lib.sh bucket points at production",
        lambda t: t.replace('BUCKET="nlw-staging-datasets-', 'BUCKET="nlw-production-datasets-', 1),
        staging_only_violations,
    ),
    (
        "IMDS hop limit raised to 2",
        lambda t: t.replace("HttpPutResponseHopLimit=1", "HttpPutResponseHopLimit=2"),
        imds_violations,
    ),
    (
        "IMDS firewall rule removed",
        lambda t: t.replace("sudo iptables -I DOCKER-USER -d 169.254.169.254/32 -j DROP\n", ""),
        imds_violations,
    ),
    (
        "static credentials file allowed",
        lambda t: t.replace("export AWS_SHARED_CREDENTIALS_FILE=/dev/null\n", ""),
        imds_violations,
    ),
    (
        "mutating call in a READ-ONLY block",
        lambda t: _insert_into(t, "P06-02", "aws s3api delete-object --bucket b --key k"),
        label_violations,
    ),
    (
        "unwrapped call in an EXPECT-DENIED block",
        lambda t: _insert_into(
            t, "P11-01", "aws s3api delete-object --profile proof-api --bucket b --key k"
        ),
        label_violations,
    ),
    (
        "unlabelled command block",
        lambda t: t.replace("**P08-01 · READ-ONLY · proof instance**", "P08-01"),
        label_violations,
    ),
    (
        "assume-role prints the session",
        lambda t: _insert_into(
            t, "P12-02", "aws sts assume-role --role-arn x --role-session-name y"
        ),
        secret_print_violations,
    ),
    (
        "debug tracing enabled",
        lambda t: _insert_into(t, "P04-01", "set -x"),
        secret_print_violations,
    ),
    (
        "credentials exported to the terminal",
        lambda t: _insert_into(t, "P14-02", "aws configure export-credentials --profile proof-api"),
        secret_print_violations,
    ),
    (
        "cleanup deletes by wildcard",
        lambda t: _insert_into(
            t, "X06", 'aws s3api delete-object --bucket "${REC_BUCKET}" --key "versions/*"'
        ),
        cleanup_violations,
    ),
    (
        "cleanup uses an unrecorded id",
        lambda t: _insert_into(
            t, "X03", "aws ec2 terminate-instances --instance-ids i-proofexample"
        ),
        cleanup_violations,
    ),
    (
        "cleanup empties a bucket recursively",
        lambda t: _insert_into(t, "X06", 'aws s3 rm "s3://${REC_BUCKET}" --recursive'),
        cleanup_violations,
    ),
    (
        "a stop condition is never checked",
        lambda t: re.sub(r"\bS5\b(?! \|)", "S9", t),
        stop_violations,
    ),
    (
        "a created resource is never recorded",
        lambda t: t.replace("record REC_SG_ID", "SG_ID=$(true) #", 1),
        inventory_violations,
    ),
    # M1: production reached indirectly
    (
        "MUTATING block writes to $OTHER_BUCKET",
        lambda t: _insert_into(
            t,
            "P04-01",
            'aws s3api put-object --profile proof-api --bucket "$OTHER_BUCKET" --key k --body f',
        ),
        staging_only_violations,
    ),
    (
        "MUTATING block uses ${PROD_KEY}",
        lambda t: _insert_into(
            t,
            "P04-01",
            'aws s3api put-object --profile proof-api --bucket "$BUCKET" '
            '--key k --body f --ssekms-key-id "${PROD_KEY}"',
        ),
        staging_only_violations,
    ),
    (
        "MUTATING block builds a production name by concatenation",
        lambda t: _insert_into(
            t,
            "P04-01",
            "P=prod; aws s3api put-object --profile proof-api "
            '--bucket "nlw-${P}uction-datasets-x" --key k --body f',
        ),
        staging_only_violations,
    ),
    # L6: parsing and output safety
    (
        "READ-ONLY block: global option before the service",
        lambda t: _insert_into(
            t, "P06-02", "aws --profile proof-api s3api delete-object --bucket b --key k"
        ),
        label_violations,
    ),
    (
        "aws configure get prints a secret",
        lambda t: _insert_into(
            t, "P04-01", "aws configure get aws_secret_access_key --profile proof-api"
        ),
        secret_print_violations,
    ),
    (
        "env prints the environment",
        lambda t: _insert_into(t, "P04-01", "env | sort"),
        secret_print_violations,
    ),
    (
        "printenv prints a credential",
        lambda t: _insert_into(t, "P04-01", "printenv AWS_SECRET_ACCESS_KEY"),
        secret_print_violations,
    ),
    (
        "echo prints a credential variable",
        lambda t: _insert_into(t, "P04-01", 'echo "$AWS_SESSION_TOKEN"'),
        secret_print_violations,
    ),
    (
        "get-session-token prints a session",
        lambda t: _insert_into(t, "P04-01", "aws sts get-session-token"),
        secret_print_violations,
    ),
    (
        "EXPECT-DENIED line carries a second, unwrapped AWS call",
        lambda t: _insert_into(
            t,
            "P11-01",
            "expect_denied aws s3api delete-object --profile proof-api "
            "--bucket b --key k; aws s3api delete-object --bucket b --key k",
        ),
        label_violations,
    ),
    (
        "EXPECT-DENIED line carries a second command",
        lambda t: _insert_into(
            t,
            "P11-01",
            "expect_denied aws s3api delete-object --profile proof-api "
            "--bucket b --key k && rm -f x",
        ),
        label_violations,
    ),
    (
        "a stop condition is only an echoed token",
        lambda t: t.replace("stop S5 ", "echo S5 "),
        stop_violations,
    ),
    ("S10 never enforced", lambda t: t.replace("stop S10", "echo S10"), stop_violations),
    # H1
    (
        "dataset bucket created without the same-block absence check",
        lambda t: t.replace(
            'absent 404 aws s3api head-bucket --profile nlw-proof-admin --bucket "$BUCKET"\n', "", 1
        ),
        bucket_creation_violations,
    ),
    (
        "audit bucket configured before the pristine checks",
        lambda t: t.replace(
            "  --object-ownership BucketOwnerEnforced --object-lock-enabled-for-bucket\n",
            "  --object-ownership BucketOwnerEnforced --object-lock-enabled-for-bucket\n"
            "aws s3api put-bucket-tagging --profile nlw-proof-audit-admin "
            '--bucket "$AUDIT_BUCKET" --tagging x\n',
            1,
        ),
        bucket_creation_violations,
    ),
    (
        "dataset bucket recorded before the pristine checks",
        lambda t: t.replace(
            'aws s3api create-bucket --profile nlw-proof-admin --bucket "$BUCKET" '
            "--object-ownership BucketOwnerEnforced\n",
            'aws s3api create-bucket --profile nlw-proof-admin --bucket "$BUCKET" '
            '--object-ownership BucketOwnerEnforced\nrecord REC_BUCKET "$BUCKET"\n',
            1,
        ),
        bucket_creation_violations,
    ),
    (
        "proof suffix loses its entropy",
        lambda t: t.replace("openssl rand -hex 6)", "openssl rand -hex 1)"),
        bucket_creation_violations,
    ),
    # M2
    (
        "recovery lists the whole versions/ prefix",
        lambda t: t.replace('--prefix "versions/$ws/"', "--prefix versions/"),
        recovery_violations,
    ),
    (
        "recovery accepts versions older than the run",
        lambda t: t.replace('[[ "$modified" > "$started" ]] || stop S8', "true"),
        recovery_violations,
    ),
    (
        "X05 no longer refuses unrecorded versions",
        lambda t: t.replace(
            '|| stop S8 "the dataset bucket holds versions this proof did not record; '
            'nothing more is deleted"',
            "|| true",
        ),
        recovery_violations,
    ),
    (
        "an expected-denied write lands outside the proof prefixes",
        lambda t: t.replace('--key "outside/$REC_PROOF_WS/x"', '--key "other/x"'),
        denied_write_violations,
    ),
    # L3
    (
        "P00 no longer binds the reviewed commit",
        lambda t: t.replace(
            '[[ "$(git rev-parse HEAD)" == "$REVIEWED_COMMIT" ]] || { echo "STOP S9: '
            'not the reviewed commit" >&2; exit 1; }\n',
            "",
        ),
        commit_binding_violations,
    ),
    (
        "render no longer verifies the commit",
        lambda t: t.replace("render() {\n  verify_reviewed_commit\n", "render() {\n"),
        commit_binding_violations,
    ),
    # L7
    (
        "budget limit no longer verified",
        lambda t: t.replace('|| stop S9 "the budget limit differs from decision E4"', "|| true"),
        budget_violations,
    ),
    (
        "budget created after other resources",
        lambda t: t.replace(
            "**P03-00 · MUTATING · workstation**", "**P03-00 · LOCAL · workstation**"
        ),
        budget_violations,
    ),
    # L10
    (
        "X01 no longer checks the trail identity",
        lambda t: t.replace('    REC_TRAIL_ARN) [[ "$value" == "$TRAIL_ARN" ]] ;;\n', ""),
        cleanup_identity_violations,
    ),
    (
        "X02 no longer checks the trail's tag",
        lambda t: t.replace('tagged "$(aws cloudtrail list-tags', 'tagged "$(true list-tags'),
        cleanup_identity_violations,
    ),
]


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
