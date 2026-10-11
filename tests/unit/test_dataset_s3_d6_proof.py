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

import configparser
import copy
import hashlib
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
    r"|export-credentials|assume-role|login|logout)$"
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


def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """json object hook: a duplicate key is an error, never last-one-wins."""
    keys = [k for k, _ in pairs]
    duplicates = sorted({k for k in keys if keys.count(k) > 1})
    if duplicates:
        raise ValueError(f"duplicate JSON keys {duplicates}")
    return dict(pairs)


def load_templates(text: str | None = None) -> Templates:
    body = PROVISIONING.read_text() if text is None else text
    return {
        name: json.loads(raw, object_pairs_hook=strict_pairs)
        for name, raw in TEMPLATE.findall(body)
    }


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
    """Every statement that is not exactly a Deny is treated as an Allow, so
    a lowercase, misspelt or missing Effect is checked as the broader case."""
    return [s for s in statements(doc) if s.get("Effect") != "Deny"]


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
        out.append({"label": label, "body": body, "raw": block.group(1), "start": block.start()})
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
        "AuditKeyAlias": (
            {"kms:CreateAlias"},
            {"arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-dataset-audit"},
            None,
        ),
        "AdministerAuditKey": (
            {
                "kms:CreateAlias",
                "kms:DescribeKey",
                "kms:GetKeyPolicy",
                "kms:PutKeyPolicy",
                "kms:EnableKeyRotation",
                "kms:GetKeyRotationStatus",
                "kms:ListGrants",
                "kms:ListResourceTags",
            },
            {"<AUDIT_KEY_ARN>"},
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
    "kms:ListGrants",
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
    "trust-human": {
        "<HUMAN_PRINCIPAL_ARNS>": (
            {"sts:AssumeRole"},
            lambda c: c == {"StringLike": {"sts:RoleSessionName": "nlw-d6-*"}},
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
            if s.get("Effect") == "Deny":
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
    trust = t["trust-human"]
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


def sso_trust_violations(t: Templates) -> list[str]:
    """The human roles admit only Identity Center permission-set roles: an
    IAM user with a long-term key, or any other principal, is refused."""
    v = []
    trust = t["trust-human"]
    sids = by_sid(trust)
    deny = sids.get("DenyAnythingButIdentityCenter", {})
    if not (
        deny.get("Effect") == "Deny"
        and deny.get("Principal") == {"AWS": "*"}
        and actions(deny) == {"sts:AssumeRole"}
        and deny.get("Condition")
        == {
            "ArnNotLike": {
                "aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/aws-reserved/sso.amazonaws.com/*"
            }
        }
    ):
        v.append("the human trust admits principals other than Identity Center roles")
    (allow,) = allows(trust)
    if allow.get("Condition") != {"StringLike": {"sts:RoleSessionName": "nlw-d6-*"}}:
        v.append("the human trust does not require run-scoped session names")
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
    p00 = [c for c in commands(block(text, "P00-02"))]
    first_effect = next(
        i
        for i, c in enumerate(p00)
        if c.name in ("mkdir", "python3", "git") and (c.name != "git" or "show" in c.words)
    )
    head = [
        i
        for i, c in enumerate(p00)
        if c.name == "[[" and "$(git rev-parse HEAD)" in c.words and "$REVIEWED_COMMIT" in c.words
    ]
    clean = [
        i for i, c in enumerate(p00) if c.name == "[[" and "$(git status --porcelain)" in c.words
    ]
    if not head or not clean or max(head + clean) > first_effect:
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
    if "AKIA" in x01 or "REC_HUMAN_" in x01:
        v.append("X01 still accepts a long-term access key id")
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
        if not re.search(rf"(record|make_role [a-z-]+ [a-z-]+ [a-z-]+) {re.escape(ledger)}", proc):
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


# --- N1/N2: canonical statements and every Deny pinned exactly -------------------------------

PINS: dict[str, Any] = json.loads(
    (ROOT / "tests" / "fixtures" / "dataset_s3_policy_pins.json").read_text(),
    object_pairs_hook=strict_pairs,
)
NON_POLICY = {
    "dataset-bucket-lifecycle",
    "audit-bucket-lifecycle",
    "trail-advanced-event-selectors",
}
# PINS["policies"]: each policy's Sid list and every Deny; PINS["documents"]:
# the lifecycle rules and event selectors, pinned whole (F3).
STATEMENT_KEYS = {
    "Sid",
    "Effect",
    "Principal",
    "NotPrincipal",
    "Action",
    "NotAction",
    "Resource",
    "NotResource",
    "Condition",
}


def effect_violations(t: Templates) -> list[str]:
    """Every statement of every policy template is a dict with a Sid, only
    known keys, and an Effect that is exactly Allow or Deny."""
    v = []
    for name, doc in t.items():
        if name in NON_POLICY:
            continue
        for s in statements(doc):
            if not isinstance(s, dict):
                v.append(f"{name}: a statement is not an object")
                continue
            if s.get("Effect") not in ("Allow", "Deny"):
                v.append(f"{name}/{s.get('Sid')}: Effect {s.get('Effect')!r} is not Allow or Deny")
            if not s.get("Sid"):
                v.append(f"{name}: a statement has no Sid")
            if set(s) - STATEMENT_KEYS:
                v.append(f"{name}/{s.get('Sid')}: unknown keys {sorted(set(s) - STATEMENT_KEYS)}")
    return v


def deny_pin_violations(t: Templates) -> list[str]:
    """Every policy template has exactly its reviewed Sids, every Deny is the
    reviewed statement (principal, actions, resources, condition), and the
    lifecycle rules and event selectors are the reviewed documents."""
    v = []
    policies, documents = PINS["policies"], PINS["documents"]
    if set(t) - NON_POLICY != set(policies) or set(t) & NON_POLICY != set(documents):
        v.append(f"templates {sorted(t)} differ from the reviewed set")
    for name, pin in policies.items():
        if name not in t:
            continue
        sids = [s.get("Sid") for s in statements(t[name])]
        if len(sids) != len(set(sids)) or set(sids) != set(pin["sids"]):
            v.append(f"{name}: Sids {sids} differ from the reviewed {pin['sids']}")
        got = {s.get("Sid"): s for s in statements(t[name])}
        for sid, expected in pin["denies"].items():
            actual = got.get(sid)
            if actual is None:
                v.append(f"{name}/{sid}: a mandatory Deny is missing")
            elif {k: x for k, x in actual.items() if k != "Sid"} != expected:
                v.append(f"{name}/{sid}: the Deny differs from the reviewed statement")
        for sid, statement in got.items():
            if (
                sid not in pin["denies"]
                and statement.get("Effect") == "Deny"
                and sid in pin["sids"]
            ):
                v.append(f"{name}/{sid}: became a Deny")
    for name, expected in documents.items():
        if t.get(name) != expected:
            v.append(f"{name}: differs from the reviewed document")
    return v


# --- N3/N4: run the procedure itself with a stub `aws` ------------------------------------------
#
# Every step (lib.sh included) is executed by bash with PATH holding only stubs
# and a fixed set of local tools. The stub `aws` records its fully expanded
# argv and never touches a network or the real AWS CLI, which is not on PATH.
# What the shell actually runs is checked, so indirection (helper functions,
# substitutions, indirect or case-converted variables, ledger values, and
# wrappers such as timeout, xargs, nohup, sudo or bash -c) cannot hide a call.

STUB_ACCOUNT = "111122223333"
STUB_SUFFIX = "-d6a1b2c3d4e5f6"
STUB_PROOF_ID = "d6-20261011-a1b2c3"
STUB_OTHER_BUCKET = f"nlw-production-datasets-{STUB_ACCOUNT}-us-east-1{STUB_SUFFIX}"
REAL_TOOLS = (
    "base64",
    "basename",
    "cat",
    "chmod",
    "cmp",
    "cp",
    "cut",
    "date",
    "diff",
    "dirname",
    "git",
    "grep",
    "head",
    "jq",
    "ls",
    "mkdir",
    "mktemp",
    "mv",
    "printf",
    "cksum",
    "rm",
    "sed",
    "seq",
    "sort",
    "tail",
    "tee",
    "touch",
    "tr",
    "uniq",
    "wc",
    "xargs",
    "awk",
    "true",
    "false",
    "expr",
)
# stub-record KIND ARG...: one record per file, written whole under a temporary
# name and renamed into place, so concurrent stubs (P05-02's parallel writes,
# a pipeline) can neither interleave nor truncate a record. A file left
# without the .rec suffix is an incomplete record and fails the run.
STUB_RECORD = r"""#!/bin/bash
tmp="$(mktemp "$STUB_LOG/rec.XXXXXXXX")" || exit 97
{ printf '%s\037%s' "$1" "${STEP:-?}"; shift
  for a in "$@"; do printf '\037%s' "$a"; done
  printf '\036\n'; } > "$tmp" || exit 97
mv "$tmp" "$tmp.rec" || exit 97
"""
# Identities answered from the generated aws-config, so that an identity
# check compares against what the reviewed profiles actually produce (H2).
STUB_IDENTITY = r"""
import configparser, os, sys
profile, account = sys.argv[1], os.environ["APPROVED_ACCOUNT"]
config = configparser.RawConfigParser()
config.read(os.environ.get("AWS_CONFIG_FILE", ""))
section = f"profile {profile}"
if config.has_section(section) and config.has_option(section, "role_arn"):
    role = config.get(section, "role_arn").rsplit("/", 1)[1]
    session = config.get(section, "role_session_name", fallback="botocore-session-1")
elif config.has_section(section) and config.has_option(section, "sso_role_name"):
    role = "AWSReservedSSO_%s_0123456789abcdef" % config.get(section, "sso_role_name")
    session = "person"
elif profile in ("nlw-proof-operator-from-audit", "proof-api-wrong-session"):
    # The reviewed negative controls: their trust refuses them.
    print("An error occurred (AccessDenied) when calling the AssumeRole operation", file=sys.stderr)
    sys.exit(254)
elif profile == "proof-bootstrap":
    role, session = "nlw-staging-dataset-bootstrap", "i-0stub"
else:
    sys.exit(f"no such profile {profile}")
print(f"arn:aws:sts::{account}:assumed-role/{role}/{session}")
"""
STUB_AWS = r"""#!/bin/bash
"$STUB_DIR/stub-record" aws "$@" || exit 97
op=""; svc=""; out=""; prefix=""; query=""; profile=""; named=""; bucket=""; key=""
conditional=""; i=0; args=("$@")
while [[ $i -lt ${#args[@]} ]]; do
  a="${args[$i]}"
  case "$a" in
    --output) out="${args[$((i + 1))]}"; i=$((i + 2)); continue ;;
    --prefix) prefix="${args[$((i + 1))]}"; i=$((i + 2)); continue ;;
    --query) query="${args[$((i + 1))]}"; i=$((i + 2)); continue ;;
    --profile) profile="${args[$((i + 1))]}"; i=$((i + 2)); continue ;;
    --role-name|--instance-profile-name|--name)
      named="${args[$((i + 1))]}"; i=$((i + 2)); continue ;;
    --bucket) bucket="${args[$((i + 1))]}"; i=$((i + 2)); continue ;;
    --key) key="${args[$((i + 1))]}"; i=$((i + 2)); continue ;;
    --if-none-match) conditional=1; i=$((i + 2)); continue ;;
    --region|--endpoint-url) i=$((i + 2)); continue ;;
    --version) echo "aws-cli/2.22.0 Python/3.12.6 Linux/6.1 exe/x86_64"; exit 0 ;;
    --*) i=$((i + 1)); continue ;;
  esac
  if [[ -z "$svc" ]]; then svc="$a"; elif [[ -z "$op" ]]; then op="$a"; fi
  i=$((i + 1))
done
# A conditional create succeeds once per bucket and key, as S3's If-None-Match
# does (mkdir is atomic), so P05's duplicate and racing writes see a 412.
if [[ -n "$conditional" && "$op" =~ ^(put-object|complete-multipart-upload)$ ]]; then
  marker="$STUB_LOG/../objects/$(printf '%s' "$bucket/$key" | cksum | cut -d' ' -f1)"
  if ! mkdir "$marker" 2> /dev/null; then
    echo "An error occurred (PreconditionFailed) when calling the PutObject operation" >&2
    exit 254
  fi
fi
# Creates answer with identifiers of the real form, so the ledger checks (X01)
# see what AWS would return.
case "$svc $op" in
  "iam create-role") echo "arn:aws:iam::$APPROVED_ACCOUNT:role/$named"; exit 0 ;;
  "iam create-instance-profile")
    echo "arn:aws:iam::$APPROVED_ACCOUNT:instance-profile/$named"; exit 0 ;;
  "kms create-key") echo "arn:aws:kms:us-east-1:$APPROVED_ACCOUNT:key/$(uuidgen)"; exit 0 ;;
  "cloudtrail create-trail")
    echo "arn:aws:cloudtrail:us-east-1:$APPROVED_ACCOUNT:trail/$named"; exit 0 ;;
  "ec2 create-security-group") echo sg-0123456789abcdef0; exit 0 ;;
  "ec2 run-instances") echo i-0123456789abcdef0; exit 0 ;;
esac
case "$svc $op $query" in
  "sts get-caller-identity Account") echo "$APPROVED_ACCOUNT"; exit 0 ;;
  "sts get-caller-identity Arn") exec python3 "$STUB_DIR/identity.py" "$profile" ;;
  "configure get "*) echo us-east-1; exit 0 ;;
  *RegionName*) echo us-east-1; exit 0 ;;
  *PermissionsBoundaryArn*) echo "$PROOF_BOUNDARY_ARN"; exit 0 ;;
esac
case "$op" in
  export-credentials)
    printf '%s\n' '{"Version": 1, "AccessKeyId": "stub", "SecretAccessKey": "stub",' \
      '"SessionToken": "stub", "Expiration": "2999-01-01T00:00:00+00:00"}' ;;
  list-object-versions|list-multipart-uploads)
    if [[ "$out" == text ]]; then
      printf '%sstub-object\tstub-%s\t2999-01-01T00:00:00+00:00\n' "$prefix" "$RANDOM$RANDOM"
    else echo '{}'; fi ;;
  *)
    if [[ "$out" == text ]]; then echo "arn:aws:stub:::$op/$RANDOM"; else echo '{}'; fi ;;
esac
exit 0
"""
STUB_SIMPLE = {
    "uuidgen": "printf '%08x-0000-4000-8000-%012x\\n' $RANDOM $RANDOM$RANDOM",
    "openssl": 'if [[ "${1:-}" == rand ]]; then echo a1b2c3d4e5f6; else echo c3R1Yg==; fi',
    "uname": "echo Darwin",
}
STUB_LOGGED = (
    "docker",
    "ssh",
    "scp",
    "ssh-keygen",
    "iptables",
    "install",
    "find",
    "gunzip",
    "curl",
    "wget",
    "nc",
    "security",
    "dnf",
    "systemctl",
    "sleep",
    "shasum",
    "sha256sum",
)
STUB_WRAPPERS = {
    "sudo": 'while [[ $# -gt 0 && "$1" == -* ]]; do\n'
    'case "$1" in -u|-g|-C) shift 2 ;; *) shift ;; esac; done\n'
    'if [[ -f "$STUB_DIR/$1" && ! -L "$STUB_DIR/$1" ]]; then exec "$@"; fi\n'
    "[[ -t 0 ]] || cat > /dev/null  # a real program reads its input: no SIGPIPE upstream\n"
    '"$STUB_DIR/stub-record" sudo-skipped "$@"',
    "timeout": 'while [[ "${1:-}" == -* ]]; do shift; done; shift; exec "$@"',
    "nohup": 'exec "$@"',
    "nice": 'while [[ "${1:-}" == -* ]]; do shift; done; exec "$@"',
    "env": 'if [[ $# -eq 0 ]]; then "$STUB_DIR/stub-record" env-printed; exit 0; fi\n'
    'while [[ "${1:-}" == *=* || "${1:-}" == -* ]]; do shift; done; exec "$@"',
}
# The harness keeps the reviewed lib.sh semantics (set -euo pipefail and the
# EXIT handler that records S10) and replaces only `stop`, which logs and
# returns so that a stop caused by a fake answer does not end the run.
HARNESS_OVERRIDES = """
# --- test harness: a stop is logged and the step continues -----------------
stop() { printf '%s\\n' "STOP ${1:-} ${2:-}" >> "$PROOF_DIR/harness-stops.log"; return 0; }
"""
# Stops that no fake AWS answer can cause: the run fails at once on any of
# them (L2). Identity answers come from the generated profiles, so a wrong
# session or role name stops the run (H2).
FATAL_STOPS = re.compile(
    r"STOP S10\b|not the reviewed commit|local changes|REVIEWED_COMMIT is not"
    r"|a principal list is invalid|ledger belongs to another|bad ledger name|wildcard ledger value"
    r"|does not name this proof run|(?<!caller-)identity|Identity Center"
    r"|permission-set role is not the approved"
    r"|admin profile is not|region|AWS CLI v2\.22\+ required|not a dedicated account"
    r"|could not be rendered safely|instance bundle differs"
)
KNOWN_RECORDS = {"aws", "sudo-skipped", "env-printed", *STUB_LOGGED}


@dataclass
class StubRun:
    calls: list[tuple[str, list[str]]]
    other: list[tuple[str, str]]
    classes: dict[str, str]
    fatal: list[str]
    symbols: dict[str, str]


def _write_exec(path: Path, body: str) -> None:
    path.write_text(body if body.startswith("#!") else f"#!/bin/bash\n{body}\n")
    path.chmod(0o755)


def stub_toolbox(root: Path, bash: str) -> Path:
    stub = root / "stub"
    stub.mkdir()
    for tool in REAL_TOOLS:
        found = shutil.which(tool)
        if found:
            (stub / tool).symlink_to(found)
    (stub / "bash").symlink_to(bash)
    (stub / "python3").symlink_to(sys.executable)
    _write_exec(stub / "stub-record", STUB_RECORD)
    (stub / "identity.py").write_text(STUB_IDENTITY)
    _write_exec(stub / "aws", STUB_AWS)
    for name, body in STUB_SIMPLE.items():
        _write_exec(stub / name, body)
    for name in STUB_LOGGED:
        _write_exec(stub / name, f'"$STUB_DIR/stub-record" {name} "$@"')
    for name, body in STUB_WRAPPERS.items():
        _write_exec(stub / name, body)
    return stub


def stub_env() -> dict[str, str]:
    """The session variables of P00-01, with dummy values."""
    return {
        "PROOF_ID": STUB_PROOF_ID,
        "APPROVED_ACCOUNT": STUB_ACCOUNT,
        "STAGING_ACCOUNT_IDS_JSON": json.dumps([STAGING_ACCOUNT]),
        "PRODUCTION_ACCOUNT_IDS_JSON": json.dumps([PROD_ACCOUNT]),
        "BUCKET_SUFFIX": STUB_SUFFIX,
        "ADMIN_ROLE": ADMIN_ROLE_NAME,
        "AUDIT_RETENTION_DAYS": "90",
        "E11_IDENTITY": "identity-center",
        "SSO_START_URL": "https://d-0000000000.awsapps.com/start/#/",
        "SSO_REGION": "us-east-1",
        "PROOF_ADMIN_PERMISSION_SET": "NlwD6ProofAdmin",
        "OPERATOR_PERMISSION_SET": "NlwD6Operator",
        "AUDIT_ADMIN_PERMISSION_SET": "NlwD6AuditAdmin",
        "AUDIT_READER_PERMISSION_SET": "NlwD6AuditReader",
        "OPERATOR_NAME": "operator",
        "PROOF_BOUNDARY_ARN": f"arn:aws:iam::{STUB_ACCOUNT}:policy/nlw-staging-d6-proof-boundary",
        "BUDGET_LIMIT_USD": "25",
        "BUDGET_EMAIL": "owner@example.invalid",
        "IMAGE": "ghcr.io/example/image@sha256:" + "0" * 64,
        "OPERATOR_CIDR": "192.0.2.1/32",
        "OBJECT_LOCK_MODE": "GOVERNANCE",
        "E3_DECISION": "delete",
        "OPERATOR_HUMANS_JSON": json.dumps([sso_role(STUB_ACCOUNT, "NlwD6Operator")]),
        "AUDIT_ADMIN_HUMANS_JSON": json.dumps([sso_role(STUB_ACCOUNT, "NlwD6AuditAdmin")]),
        "AUDIT_READER_HUMANS_JSON": json.dumps([sso_role(STUB_ACCOUNT, "NlwD6AuditReader")]),
        "E12_MUST_NOT_PASS_JSON": json.dumps([f"arn:aws:iam::{STUB_ACCOUNT}:user/x"]),
    }


def _stub_gate() -> dict[str, Any]:
    gate = _good_gate()
    gate["proof_boundary_arn"] = stub_env()["PROOF_BOUNDARY_ARN"]
    gate["proof_admin_role_arn"] = f"arn:aws:iam::{STUB_ACCOUNT}:role/{ADMIN_ROLE_NAME}"
    return gate


def _patch_lib(proof_dir: Path, extra: str) -> None:
    """Append the harness override to an extracted lib.sh and re-hash it in
    that directory's manifest, as run-step would otherwise refuse it."""
    lib = proof_dir / "lib.sh"
    if HARNESS_OVERRIDES not in lib.read_text():  # the bundle copies an already patched lib.sh
        lib.write_text(lib.read_text() + extra + HARNESS_OVERRIDES)
    manifest = json.loads((proof_dir / "manifest.json").read_text())
    manifest["lib.sh"] = hashlib.sha256(lib.read_bytes()).hexdigest()
    (proof_dir / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True))


def config_violations(path: Path) -> list[str]:
    """The generated aws-config parses, holds no placeholder or key, and every
    profile resolves to an SSO session or an existing source profile."""
    v = []
    text = path.read_text() if path.exists() else ""
    if not text:
        return [f"{path.name} was not generated"]
    if re.search(r"<[A-Z_]+>|aws_access_key_id|aws_secret_access_key|credential_process", text):
        v.append(f"{path.name} holds a placeholder or a credential source")
    config = configparser.RawConfigParser(strict=True)
    try:
        config.read_string(text)
    except configparser.Error as exc:
        return [f"{path.name} does not parse: {type(exc).__name__}"]
    sessions = {s[12:] for s in config.sections() if s.startswith("sso-session ")}
    profiles = {s[8:] for s in config.sections() if s.startswith("profile ")}
    for name in profiles:
        section = config[f"profile {name}"]
        if "sso_session" in section and section["sso_session"] not in sessions:
            v.append(f"profile {name} names an unknown sso-session")
        if "source_profile" in section and section["source_profile"] not in profiles:
            v.append(f"profile {name} names an unknown source profile")
    return v


def _sync_ledgers(a: Path, b: Path) -> None:
    """The documented manual copies between workstation and instance ledgers."""
    lines_a = a.read_text().splitlines(True) if a.exists() else []
    lines_b = b.read_text().splitlines(True) if b.exists() else []
    merged = list(dict.fromkeys(lines_a + lines_b))
    a.write_text("".join(merged))
    b.write_text("".join(merged))


def run_with_stub(
    root: Path, text: str, bash: str, lib_extra: str = "", stop_at_fatal: bool = True
) -> StubRun:
    """Run the reviewed P00-02 for real against a committed gate record, then
    every later step in order through `run-step`, against the stub toolbox.
    Proof-instance steps run in their own directory, from the bundle P03-12
    builds. The run stops at the first genuine failure (``fatal``)."""
    home, repo = root / "home", root / "repo"
    (repo / "docs" / "runbooks").mkdir(parents=True)
    shutil.copy(PROVISIONING, repo / "docs" / "runbooks" / PROVISIONING.name)
    (repo / "docs" / "runbooks" / PROOF.name).write_text(text)
    git_env = {
        "PATH": os.environ["PATH"],
        "HOME": str(root),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    _git(repo, git_env, "init", "-q")
    _git(repo, git_env, "add", "-A")
    _git(repo, git_env, "commit", "-q", "--no-gpg-sign", "-m", "procedure")
    procedure = _git(repo, git_env, "rev-parse", "HEAD")
    (repo / GATE_PATH).parent.mkdir(parents=True)
    (repo / GATE_PATH).write_text(json.dumps({**_stub_gate(), "procedure_commit": procedure}))
    _git(repo, git_env, "add", "-A")
    _git(repo, git_env, "commit", "-q", "--no-gpg-sign", "-m", "gate")
    head = _git(repo, git_env, "rev-parse", "HEAD")
    ws, inst = home / "nlw-d6" / STUB_PROOF_ID, home / "proof"
    stub = stub_toolbox(root, bash)
    log = root / "records"
    log.mkdir()
    (root / "objects").mkdir()
    base = {
        "PATH": str(stub),
        "HOME": str(home),
        "LANG": "C",
        "STUB_LOG": str(log),
        "STUB_DIR": str(stub),
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "AWS_EC2_METADATA_DISABLED": "true",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    env = {
        **base,
        **stub_env(),
        "PROOF_DIR": str(ws),
        "RUNBOOK_DIR": str(repo / "docs" / "runbooks"),
        "REVIEWED_COMMIT": head,
    }
    inst_env = {
        **base,
        **{k: stub_env()[k] for k in ("PROOF_ID", "APPROVED_ACCOUNT", "BUCKET_SUFFIX", "IMAGE")},
        "PROOF_DIR": str(inst),
        "RUNBOOK_DIR": "/nonexistent",
        "PROOF_BOUNDARY_ARN": stub_env()["PROOF_BOUNDARY_ARN"],
    }
    fatal: list[str] = []
    classes: dict[str, str] = {}
    p0002 = next(b for b in labelled_blocks(text) if b["label"] and b["label"]["id"] == "P00-02")
    script = root / "p00-02.sh"
    script.write_text(p0002["raw"])
    first = subprocess.run(
        [bash, str(script)], cwd=repo, env=env, capture_output=True, text=True, timeout=120
    )
    if first.returncode != 0:
        fatal.append(f"P00-02 failed: {first.stderr.strip()[:300]}")
    else:
        fatal += config_violations(ws / "aws-config")
        _patch_lib(ws, lib_extra)
    seen = {ws: 0, inst: 0}
    for b in labelled_blocks(text):
        if fatal and stop_at_fatal:
            break
        if not b["label"]:
            continue
        step = b["label"]["id"]
        classes[step] = b["label"]["cls"]
        if step in ("P00-01", "P00-02"):
            continue
        on_instance = b["label"]["where"] == "proof instance"
        where, step_env = (inst, inst_env) if on_instance else (ws, env)
        if on_instance and not (inst / "run-step").exists():
            fatal.append(f"{step}: the instance bundle does not exist")
            continue
        if step == "X12":  # the orphan case: the buckets were created but never recorded
            ledger = ws / "created.env"
            ledger.write_text(
                "".join(
                    line
                    for line in ledger.read_text().splitlines(True)
                    if not line.startswith(("REC_BUCKET=", "REC_AUDIT_BUCKET="))
                )
            )
        result = subprocess.run(
            [bash, str(where / "run-step"), step],
            cwd=repo if not on_instance else inst,
            env={**step_env, "STEP": step},
            capture_output=True,
            text=True,
            timeout=120,
        )
        if step == "P03-12" and (ws / "instance-bundle").exists() and not inst.exists():
            shutil.copytree(ws / "instance-bundle", inst)  # the scp
            fatal += config_violations(inst / "aws-config")
            _patch_lib(inst, lib_extra)
        if inst.exists():
            _sync_ledgers(ws / "created.env", inst / "created.env")
        if result.returncode != 0:
            fatal.append(f"{step} failed: {result.stderr.strip()[-300:]}")
        stops = where / "harness-stops.log"
        new = stops.read_text().splitlines()[seen[where] :] if stops.exists() else []
        seen[where] += len(new)
        fatal += [f"{step}: {line}" for line in new if FATAL_STOPS.search(line)]
    calls, other = [], []
    for path in sorted(log.iterdir()):
        raw = path.read_text()
        fields = raw[:-2].split("\x1f") if raw.endswith("\x1e\n") else []
        if path.suffix != ".rec" or len(fields) < 2 or fields[0] not in KNOWN_RECORDS:
            fatal.append(f"a malformed or incomplete stub record: {path.name}")
            continue
        kind, step, argv = fields[0], fields[1], fields[2:]
        if kind == "aws":
            calls.append((step, argv))
        else:
            other.append((kind, " ".join(argv)))
    symbols = {**stub_env(), **_ledger(ws / "created.env")}
    return StubRun(calls, other, classes, fatal, symbols)


def _ledger(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text().splitlines() if path.exists() else []:
        name, _, value = line.partition("=")
        out[name] = shlex.split(value)[0] if value else ""
    return out


# --- F2: every executed AWS call against a reviewed allow-list ---------------------------------
#
# Each operation the procedure may run, with the steps it may run in, the
# profiles (identities) it may use, and the values each resource option may
# take. Values are templates over the run's own variables ({BUCKET}, {KEY},
# ...); "*" in a template matches any characters. A call whose operation, step,
# profile or resource value is not listed, or that carries a resource option
# the entry does not list, is a violation. A deliberate change updates this
# table in review.

ADMIN, OPERATOR, AUDIT_ADMIN, AUDIT_READER = (
    "nlw-proof-admin",
    "nlw-proof-operator",
    "nlw-proof-audit-admin",
    "nlw-proof-audit-reader",
)
H_OPERATOR, H_AUDIT_ADMIN, H_AUDIT_READER = (
    "nlw-proof-human-operator",
    "nlw-proof-human-audit-admin",
    "nlw-proof-human-audit-reader",
)
P_BOOT, P_API, P_INGEST = "proof-bootstrap", "proof-api", "proof-ingest"
RUNTIME = {P_BOOT, P_API, P_INGEST}
NO_PROFILE = "-"
RESOURCE_OPTIONS = {
    "--account-id",
    "--alias-name",
    "--bucket",
    "--budget-name",
    "--caller-arn",
    "--copy-source",
    "--filters",
    "--group-id",
    "--iam-instance-profile",
    "--instance-id",
    "--instance-ids",
    "--instance-profile-name",
    "--key-id",
    "--kms-key-id",
    "--name",
    "--names",
    "--policy-arn",
    "--policy-source-arn",
    "--resource-arns",
    "--resource-id-list",
    "--role-arn",
    "--role-name",
    "--s3-bucket-name",
    "--security-group-ids",
    "--sso-session",
    "--tag-filters",
    "--target-key-id",
    "--trail-arn",
    "--trail-name",
}
_ROLE = "arn:aws:iam::{ACCOUNT}:role/"
_SSO = _ROLE + "aws-reserved/sso.amazonaws.com/AWSReservedSSO_"


def _names(*roles: str) -> set[str]:
    return {f"nlw-staging-dataset-{r}" for r in roles}


def _arns(*roles: str) -> set[str]:
    return {f"{_ROLE}nlw-staging-dataset-{r}" for r in roles}


DATASET_ROLES = ("bootstrap", "api", "ingest", "operator")
AUDIT_ROLES = ("audit-admin", "audit-reader")
SSO_ROLE_NAMES = {
    f"AWSReservedSSO_{{{ps}}}_*" for ps in ("OPERATOR_PS", "AUDIT_ADMIN_PS", "AUDIT_READER_PS")
}
PRINCIPALS = {
    "{ADMIN_ARN}",
    *(f"{_SSO}{{{ps}}}_*" for ps in ("OPERATOR_PS", "AUDIT_ADMIN_PS", "AUDIT_READER_PS")),
}
SHAPE_ROLES = _names(*DATASET_ROLES, *AUDIT_ROLES) | SSO_ROLE_NAMES | {"{ADMIN_ROLE_NAME}"}
Rule = tuple[set[str], set[str], dict[str, set[str]]]
EXECUTED_CALLS: dict[tuple[str, str], Rule] = {
    ("cli", "--version"): ({"P01-01"}, {NO_PROFILE}, {}),
    ("configure", "get"): ({"P01-01"}, {ADMIN}, {}),
    ("configure", "export-credentials"): (
        {"P14-02", "P14-03", "P14-05", "P15-01"},
        {P_API, P_INGEST},
        {},
    ),
    ("sso", "login"): (
        {"P00-03"},
        {NO_PROFILE},
        {"--sso-session": {"nlw-d6-{PROOF_ID}-operator", "nlw-d6-{PROOF_ID}-audit"}},
    ),
    ("sts", "get-caller-identity"): (
        {"P00-03", "P01-01", "P03-14", "P08-02", "P12-01", "P12-03"},
        {
            ADMIN,
            H_OPERATOR,
            H_AUDIT_ADMIN,
            H_AUDIT_READER,
            OPERATOR,
            *RUNTIME,
            "nlw-proof-operator-from-audit",
            "proof-api-wrong-session",
        },
        {},
    ),
    ("sts", "assume-role"): ({"P12-02"}, {P_BOOT, P_API}, {"--role-arn": _arns("operator")}),
    ("organizations", "describe-organization"): ({"P01-03"}, {ADMIN}, {}),
    ("iam", "list-account-aliases"): ({"P01-03"}, {ADMIN}, {}),
    ("iam", "list-roles"): ({"P01-03"}, {ADMIN}, {}),
    ("s3api", "list-buckets"): ({"P01-03"}, {ADMIN}, {}),
    ("kms", "list-aliases"): ({"P01-03"}, {ADMIN}, {}),
    ("resourcegroupstaggingapi", "get-resources"): (
        {"P01-03", "P18-01"},
        {ADMIN},
        {"--tag-filters": {"Key=nlw-env,Values=production", "Key=nlw-proof,Values={PROOF_ID}"}},
    ),
    ("iam", "get-policy"): ({"P01-02"}, {ADMIN}, {"--policy-arn": {"{BOUNDARY}", "{DENIES}"}}),
    ("iam", "get-policy-version"): (
        {"P01-02"},
        {ADMIN},
        {"--policy-arn": {"{BOUNDARY}", "{DENIES}"}},
    ),
    ("iam", "get-role"): (
        {"P01-02", "P02-01", "P03-11", "P18-01"},
        {ADMIN},
        {"--role-name": SHAPE_ROLES},
    ),
    ("iam", "get-role-policy"): ({"P01-02", "P03-11"}, {ADMIN}, {"--role-name": SHAPE_ROLES}),
    ("iam", "list-role-policies"): ({"P01-02", "P03-11"}, {ADMIN}, {"--role-name": SHAPE_ROLES}),
    ("iam", "list-attached-role-policies"): (
        {"P01-02", "P03-11"},
        {ADMIN},
        {"--role-name": SHAPE_ROLES},
    ),
    ("iam", "simulate-principal-policy"): (
        {"P01-02", "P03-11", "P09-03", "P10-01", "P11-03"},
        {ADMIN},
        {
            "--policy-source-arn": PRINCIPALS
            | _arns(*DATASET_ROLES, *AUDIT_ROLES)
            | {"arn:aws:iam::{ACCOUNT}:user/x"},
            "--resource-arns": PRINCIPALS
            | _arns("bootstrap", "operator", "audit-admin")
            | {
                "*",
                f"{_ROLE}nlw-production-dataset-api",
                f"{_ROLE}nlw-staging-dataset-unreviewed",
                "arn:aws:kms:us-east-1:{ACCOUNT}:key/00000000-0000-0000-0000-000000000000",
                "arn:aws:s3:::{OTHER_BUCKET}/versions/x",
                "arn:aws:s3:::{BUCKET}/versions/x",
                "arn:aws:s3:::{BUCKET}/outside/x",
                "arn:aws:s3:::{AUDIT_BUCKET}",
                "arn:aws:s3:::{AUDIT_BUCKET}/dataset-data-events/x",
                "{KEY}",
                "{AUDIT_KEY}",
                "{TRAIL_ARN}",
            },
        },
    ),
    ("iam", "simulate-custom-policy"): (
        {"P10-02"},
        {ADMIN},
        {
            "--caller-arn": {"arn:aws:iam::{ACCOUNT}:user/nlw-d6-simulated-caller"},
            "--resource-arns": {"arn:aws:s3:::{BUCKET}/versions/x"},
        },
    ),
    ("iam", "create-role"): (
        {"P03-01", "P03-03"},
        {ADMIN, H_AUDIT_ADMIN},
        {"--role-name": _names(*DATASET_ROLES, *AUDIT_ROLES)},
    ),
    ("iam", "wait"): (
        {"P03-01", "P03-03"},
        {ADMIN, H_AUDIT_ADMIN},
        {"--role-name": _names(*DATASET_ROLES, *AUDIT_ROLES)},
    ),
    ("iam", "put-role-policy"): (
        {"P03-03", "P03-05", "P03-09"},
        {ADMIN, H_AUDIT_ADMIN},
        {"--role-name": _names(*DATASET_ROLES, *AUDIT_ROLES)},
    ),
    ("iam", "create-instance-profile"): (
        {"P03-01"},
        {ADMIN},
        {"--instance-profile-name": _names("bootstrap")},
    ),
    ("iam", "add-role-to-instance-profile"): (
        {"P03-01"},
        {ADMIN},
        {"--instance-profile-name": _names("bootstrap"), "--role-name": _names("bootstrap")},
    ),
    ("iam", "get-instance-profile"): (
        {"P02-01", "X02"},
        {ADMIN},
        {"--instance-profile-name": _names("bootstrap")},
    ),
    ("iam", "list-instance-profile-tags"): (
        {"X02"},
        {ADMIN},
        {"--instance-profile-name": _names("bootstrap")},
    ),
    ("iam", "list-role-tags"): ({"X02"}, {ADMIN}, {"--role-name": _names(*DATASET_ROLES)}),
    ("iam", "remove-role-from-instance-profile"): (
        {"X06"},
        {ADMIN},
        {"--instance-profile-name": _names("bootstrap"), "--role-name": _names("bootstrap")},
    ),
    ("iam", "delete-instance-profile"): (
        {"X06"},
        {ADMIN},
        {"--instance-profile-name": _names("bootstrap")},
    ),
    ("iam", "delete-role-policy"): ({"X06"}, {ADMIN}, {"--role-name": _names(*DATASET_ROLES)}),
    ("iam", "delete-role"): ({"X06"}, {ADMIN}, {"--role-name": _names(*DATASET_ROLES)}),
    ("budgets", "create-budget"): ({"P03-00"}, {ADMIN}, {"--account-id": {"{ACCOUNT}"}}),
    ("budgets", "describe-budget"): (
        {"P03-00"},
        {ADMIN},
        {"--account-id": {"{ACCOUNT}"}, "--budget-name": {"{BUDGET}"}},
    ),
    ("budgets", "describe-notifications-for-budget"): (
        {"P03-00"},
        {ADMIN},
        {"--account-id": {"{ACCOUNT}"}, "--budget-name": {"{BUDGET}"}},
    ),
    ("kms", "create-key"): ({"P03-02", "P03-04"}, {ADMIN, AUDIT_ADMIN}, {}),
    ("kms", "create-alias"): (
        {"P03-02", "P03-04"},
        {ADMIN, AUDIT_ADMIN},
        {
            "--alias-name": {"alias/nlw-staging-datasets", "alias/nlw-staging-dataset-audit"},
            "--target-key-id": {"{KEY}", "{AUDIT_KEY}"},
        },
    ),
    ("kms", "enable-key-rotation"): (
        {"P03-02", "P03-04"},
        {ADMIN, AUDIT_ADMIN},
        {"--key-id": {"{KEY}", "{AUDIT_KEY}"}},
    ),
    ("kms", "describe-key"): (
        {"P02-01", "P10-03", "P11-02"},
        {ADMIN, H_AUDIT_ADMIN, *RUNTIME},
        {
            "--key-id": {
                "alias/nlw-staging-datasets",
                "alias/nlw-staging-dataset-audit",
                "{KEY}",
                "{AUDIT_KEY}",
            }
        },
    ),
    ("kms", "get-key-policy"): (
        {"P03-11"},
        {ADMIN, AUDIT_ADMIN},
        {"--key-id": {"{KEY}", "{AUDIT_KEY}"}},
    ),
    ("kms", "get-key-rotation-status"): (
        {"P03-11"},
        {ADMIN, AUDIT_ADMIN},
        {"--key-id": {"{KEY}", "{AUDIT_KEY}"}},
    ),
    ("kms", "list-grants"): (
        {"P03-11"},
        {ADMIN, AUDIT_ADMIN},
        {"--key-id": {"{KEY}", "{AUDIT_KEY}"}},
    ),
    ("kms", "list-resource-tags"): ({"X02"}, {ADMIN}, {"--key-id": {"{KEY}"}}),
    ("kms", "disable-key"): ({"X06"}, {ADMIN}, {"--key-id": {"{KEY}"}}),
    ("kms", "schedule-key-deletion"): ({"X06"}, {ADMIN}, {"--key-id": {"{KEY}"}}),
    ("cloudtrail", "describe-trails"): ({"P01-03", "P02-01"}, {ADMIN}, {}),
    ("cloudtrail", "get-trail"): (
        {"P02-01", "X02"},
        {H_AUDIT_ADMIN, AUDIT_ADMIN},
        {"--name": {"{TRAIL_ARN}"}},
    ),
    ("cloudtrail", "create-trail"): (
        {"P03-08"},
        {AUDIT_ADMIN},
        {
            "--name": {"nlw-staging-dataset-data-events"},
            "--s3-bucket-name": {"{AUDIT_BUCKET}"},
            "--kms-key-id": {"{AUDIT_KEY}"},
        },
    ),
    ("cloudtrail", "put-event-selectors"): (
        {"P03-08", "P11-02"},
        {AUDIT_ADMIN, *RUNTIME},
        {"--trail-name": {"{TRAIL_ARN}"}},
    ),
    ("cloudtrail", "start-logging"): ({"P03-08"}, {AUDIT_ADMIN}, {"--name": {"{TRAIL_ARN}"}}),
    ("cloudtrail", "stop-logging"): (
        {"P11-02", "X07"},
        {AUDIT_ADMIN, *RUNTIME},
        {"--name": {"{TRAIL_ARN}"}},
    ),
    ("cloudtrail", "delete-trail"): ({"X07"}, {AUDIT_ADMIN}, {"--name": {"{TRAIL_ARN}"}}),
    ("cloudtrail", "get-trail-status"): ({"P03-11"}, {AUDIT_ADMIN}, {"--name": {"{TRAIL_ARN}"}}),
    ("cloudtrail", "get-event-selectors"): (
        {"P03-11"},
        {AUDIT_ADMIN},
        {"--trail-name": {"{TRAIL_ARN}"}},
    ),
    ("cloudtrail", "list-tags"): ({"X02"}, {AUDIT_ADMIN}, {"--resource-id-list": {"{TRAIL_ARN}"}}),
    ("cloudtrail", "validate-logs"): ({"P13-01"}, {AUDIT_READER}, {"--trail-arn": {"{TRAIL_ARN}"}}),
    ("ec2", "describe-availability-zones"): ({"P01-01"}, {ADMIN}, {}),
    ("ec2", "describe-vpcs"): (
        {"P02-01", "P03-10"},
        {ADMIN},
        {"--filters": {"Name=isDefault,Values=true"}},
    ),
    ("ec2", "describe-instances"): (
        {"P02-01", "P03-11", "P03-12", "P18-01"},
        {ADMIN},
        {
            "--instance-ids": {"{INSTANCE}"},
            "--filters": {
                "Name=tag:Name,Values=nlw-staging-dataset-proof",
                "Name=instance-state-name,Values=pending,running,stopping,stopped",
            },
        },
    ),
    ("ec2", "describe-tags"): (
        {"X02"},
        {ADMIN},
        {
            "--filters": {
                "Name=resource-id,Values={INSTANCE}",
                "Name=resource-id,Values={SG}",
                "Name=key,Values=nlw-proof",
            }
        },
    ),
    ("ssm", "get-parameters"): (
        {"P03-10"},
        {ADMIN},
        {"--names": {"/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64"}},
    ),
    ("ec2", "create-security-group"): ({"P03-10"}, {ADMIN}, {}),
    ("ec2", "authorize-security-group-ingress"): ({"P03-10"}, {ADMIN}, {"--group-id": {"{SG}"}}),
    ("ec2", "run-instances"): (
        {"P03-10"},
        {ADMIN},
        {
            "--security-group-ids": {"{SG}"},
            "--iam-instance-profile": {"Name=nlw-staging-dataset-bootstrap"},
        },
    ),
    ("ec2", "wait"): ({"P03-10", "X03"}, {ADMIN}, {"--instance-ids": {"{INSTANCE}"}}),
    ("ec2-instance-connect", "send-ssh-public-key"): (
        {"P03-12"},
        {ADMIN},
        {"--instance-id": {"{INSTANCE}"}},
    ),
    ("ec2", "terminate-instances"): ({"X03"}, {ADMIN}, {"--instance-ids": {"{INSTANCE}"}}),
    ("ec2", "delete-security-group"): ({"X03"}, {ADMIN}, {"--group-id": {"{SG}"}}),
    ("s3api", "head-bucket"): (
        {"P02-01", "P03-06", "P03-07", "X12"},
        {ADMIN, AUDIT_ADMIN, H_AUDIT_ADMIN},
        {"--bucket": {"{BUCKET}", "{AUDIT_BUCKET}"}},
    ),
    **{
        ("s3api", op): (
            {"P03-06", "P03-07"},
            {ADMIN, AUDIT_ADMIN},
            {"--bucket": {"{BUCKET}", "{AUDIT_BUCKET}"}},
        )
        for op in (
            "create-bucket",
            "put-public-access-block",
            "put-bucket-tagging",
            "put-bucket-encryption",
        )
    },
    ("s3api", "put-bucket-versioning"): ({"P03-06"}, {ADMIN}, {"--bucket": {"{BUCKET}"}}),
    ("s3api", "put-object-lock-configuration"): (
        {"P03-07"},
        {AUDIT_ADMIN},
        {"--bucket": {"{AUDIT_BUCKET}"}},
    ),
    ("s3api", "put-bucket-lifecycle-configuration"): (
        {"P03-06", "P03-07", "P11-02"},
        {ADMIN, AUDIT_ADMIN, *RUNTIME},
        {"--bucket": {"{BUCKET}", "{AUDIT_BUCKET}"}},
    ),
    ("s3api", "put-bucket-policy"): (
        {"P03-06", "P03-07", "P11-02"},
        {ADMIN, AUDIT_ADMIN, *RUNTIME},
        {"--bucket": {"{BUCKET}", "{AUDIT_BUCKET}"}},
    ),
    ("s3api", "get-bucket-tagging"): (
        {"P03-06", "P03-07", "X02", "X12"},
        {ADMIN, AUDIT_ADMIN},
        {"--bucket": {"{BUCKET}", "{AUDIT_BUCKET}"}},
    ),
    ("s3api", "get-bucket-policy"): (
        {"P03-06", "P03-07", "P03-11", "X12"},
        {ADMIN, AUDIT_ADMIN},
        {"--bucket": {"{BUCKET}", "{AUDIT_BUCKET}"}},
    ),
    **{
        ("s3api", op): (
            {"P03-11"},
            {ADMIN, AUDIT_ADMIN},
            {"--bucket": {"{BUCKET}", "{AUDIT_BUCKET}"}},
        )
        for op in (
            "get-bucket-encryption",
            "get-bucket-lifecycle-configuration",
            "get-bucket-ownership-controls",
            "get-public-access-block",
        )
    },
    ("s3api", "get-bucket-versioning"): ({"P03-11"}, {ADMIN}, {"--bucket": {"{BUCKET}"}}),
    ("s3api", "get-object-lock-configuration"): (
        {"P03-11"},
        {AUDIT_ADMIN},
        {"--bucket": {"{AUDIT_BUCKET}"}},
    ),
    ("s3api", "list-object-versions"): (
        {"P03-06", "P03-07", "P08-02", "P12-03", "X05", "X10", "X12"},
        {ADMIN, AUDIT_ADMIN, OPERATOR, P_API},
        {"--bucket": {"{BUCKET}", "{AUDIT_BUCKET}"}},
    ),
    ("s3api", "list-objects-v2"): (
        {"P08-02", "P09-04", "P11-02", "P13-01"},
        {AUDIT_READER, *RUNTIME},
        {"--bucket": {"{BUCKET}", "{AUDIT_BUCKET}"}},
    ),
    ("s3api", "list-multipart-uploads"): ({"X05", "X10"}, {OPERATOR}, {"--bucket": {"{BUCKET}"}}),
    ("s3api", "put-object"): (
        {"P04-01", "P05-01", "P05-02", "P06-01", "P09-01", "P09-04", "P12-03", "P14-01"},
        {P_API, P_INGEST, OPERATOR},
        {"--bucket": {"{BUCKET}"}},
    ),
    ("s3api", "copy-object"): (
        {"P05-01"},
        {P_API},
        {"--bucket": {"{BUCKET}"}, "--copy-source": {"{BUCKET}/versions/*"}},
    ),
    ("s3api", "create-multipart-upload"): (
        {"P06-01", "P07-01", "P07-02"},
        {P_API},
        {"--bucket": {"{BUCKET}"}},
    ),
    ("s3api", "upload-part"): ({"P07-01", "P07-02"}, {P_API}, {"--bucket": {"{BUCKET}"}}),
    ("s3api", "complete-multipart-upload"): (
        {"P07-01", "P07-02"},
        {P_API},
        {"--bucket": {"{BUCKET}"}},
    ),
    ("s3api", "abort-multipart-upload"): (
        {"P07-02", "X04"},
        {P_API, OPERATOR},
        {"--bucket": {"{BUCKET}"}},
    ),
    ("s3api", "head-object"): (
        {"P06-02", "P07-01", "P10-03", "X11"},
        {P_API, P_BOOT, ADMIN},
        {"--bucket": {"{BUCKET}"}},
    ),
    ("s3api", "get-object-attributes"): ({"P07-01", "P08-01"}, {P_API}, {"--bucket": {"{BUCKET}"}}),
    ("s3api", "get-object"): (
        {"P08-01", "P09-02", "P13-01"},
        {P_API, P_INGEST, AUDIT_READER},
        {"--bucket": {"{BUCKET}", "{AUDIT_BUCKET}"}},
    ),
    ("s3api", "delete-object"): (
        {"P11-01", "P12-03", "X04"},
        {*RUNTIME, OPERATOR},
        {"--bucket": {"{BUCKET}"}},
    ),
    ("s3api", "delete-bucket"): (
        {"X06", "X12"},
        {ADMIN, AUDIT_ADMIN},
        {"--bucket": {"{BUCKET}", "{AUDIT_BUCKET}"}},
    ),
}


def _call_parts(argv: list[str]) -> tuple[str, str, dict[str, list[str]]]:
    """(service, operation, options) of an executed CLI argv; `--version`
    alone is ("cli", "--version")."""
    svc = op = ""
    opts: dict[str, list[str]] = {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--"):
            j = i + 1
            while j < len(argv) and not argv[j].startswith("--"):
                j += 1
            opts.setdefault(a, []).extend(argv[i + 1 : j])
            i = j
            continue
        if not svc:
            svc = a
        elif not op:
            op = a
        i += 1
    if not svc and "--version" in opts:
        return "cli", "--version", {}
    return svc, op, opts


def _run_values(symbols: dict[str, str]) -> dict[str, str]:
    account, suffix = symbols["APPROVED_ACCOUNT"], symbols["BUCKET_SUFFIX"]
    return {
        "ACCOUNT": account,
        "PROOF_ID": symbols["PROOF_ID"],
        "BUCKET": f"nlw-staging-datasets-{account}-us-east-1{suffix}",
        "AUDIT_BUCKET": f"nlw-staging-dataset-audit-{account}-us-east-1{suffix}",
        "OTHER_BUCKET": f"nlw-production-datasets-{account}-us-east-1{suffix}",
        "TRAIL_ARN": f"arn:aws:cloudtrail:us-east-1:{account}:trail/"
        "nlw-staging-dataset-data-events",
        "BOUNDARY": symbols["PROOF_BOUNDARY_ARN"],
        "DENIES": f"arn:aws:iam::{account}:policy/nlw-staging-d6-proof-denies",
        "ADMIN_ARN": f"arn:aws:iam::{account}:role/{symbols['ADMIN_ROLE']}",
        "ADMIN_ROLE_NAME": symbols["ADMIN_ROLE"].rsplit("/", 1)[-1],
        "OPERATOR_PS": symbols["OPERATOR_PERMISSION_SET"],
        "AUDIT_ADMIN_PS": symbols["AUDIT_ADMIN_PERMISSION_SET"],
        "AUDIT_READER_PS": symbols["AUDIT_READER_PERMISSION_SET"],
        "KEY": symbols.get("REC_KEY_ARN", "<unrecorded>"),
        "AUDIT_KEY": symbols.get("REC_AUDIT_KEY_ARN", "<unrecorded>"),
        "INSTANCE": symbols.get("REC_INSTANCE_ID", "<unrecorded>"),
        "SG": symbols.get("REC_SG_ID", "<unrecorded>"),
        "BUDGET": symbols.get("REC_BUDGET_NAME", "<unrecorded>"),
    }


def _allowed(value: str, templates: set[str], values: dict[str, str]) -> bool:
    for template in templates:
        concrete = template.format(**values)
        regex = "".join(".*" if ch == "*" else re.escape(ch) for ch in concrete)
        if re.fullmatch(regex, value):
            return True
    return False


def executed_call_violations(run: StubRun) -> list[str]:
    """Every executed AWS call is a reviewed operation, from a reviewed step,
    as a reviewed identity, on reviewed resource values (F2)."""
    v = []
    values = _run_values(run.symbols)
    for step, argv in run.calls:
        svc, op, opts = _call_parts(argv)
        rule = EXECUTED_CALLS.get((svc, op))
        what = f"{step}: aws {svc} {op}"
        if rule is None:
            v.append(f"{what} is not a reviewed operation")
            continue
        steps, profiles, resources = rule
        if step not in steps:
            v.append(f"{what} runs outside its reviewed steps {sorted(steps)}")
        profile = (opts.get("--profile") or [NO_PROFILE])[0]
        if profile not in profiles:
            v.append(f"{what} runs as {profile}, not a reviewed identity")
        for opt, given in opts.items():
            if opt not in RESOURCE_OPTIONS:
                continue
            if opt not in resources:
                v.append(f"{what} names an unreviewed resource option {opt}")
                continue
            for value in given:
                if not _allowed(value, resources[opt], values):
                    v.append(f"{what} {opt} {value!r} is not a reviewed resource")
    return v


def stub_violations(run: StubRun, text: str) -> list[str]:
    """A genuine failure in the run (``fatal``), any executed call outside the
    reviewed allow-list, and the round-2 checks: production reached by a
    mutation, a call in a step whose class forbids it, and a statically
    parsed call that never executed."""
    v = [f"fatal: {f}" for f in run.fatal] + executed_call_violations(run)
    executed: dict[str, set[tuple[str, str]]] = {}
    for step, argv in run.calls:
        call = aws_call(Cmd(["aws", *argv], ""))
        if call is None:
            continue
        executed.setdefault(step, set()).add(call)
        cls = run.classes.get(step, "?")
        joined = " ".join(argv)
        production = "production" in joined.lower() or STUB_OTHER_BUCKET in joined
        if production and (cls == "MUTATING" or not is_read(call[1])):
            v.append(f"{step}: ran aws {call[0]} {call[1]} against production")
        if call[0] == "s3":
            v.append(f"{step}: ran the high-level aws s3 {call[1]}")
        if cls == "READ-ONLY" and not is_read(call[1]):
            v.append(f"{step}: READ-ONLY step ran aws {call[0]} {call[1]}")
        if cls in ("HOST", "LOCAL"):
            v.append(f"{step}: {cls} step ran aws {call[0]} {call[1]}")
    for kind, _detail in run.other:
        if kind == "env-printed":
            v.append("a step printed the environment")
    for b in labelled_blocks(text):
        if not b["label"] or b["label"]["id"] in ("P00-01", "P00-02"):
            continue
        static = {(svc, op) for svc, op, _ in aws_ops(b["body"])}
        missing = static - executed.get(b["label"]["id"], set())
        if missing:
            v.append(f"{b['label']['id']}: calls never executed: {sorted(missing)}")
    return v


AVAILABLE_BASHES = sorted(
    {
        b
        for b in (
            shutil.which("bash"),
            "/bin/bash",
            "/usr/bin/bash",
            "/opt/homebrew/bin/bash",
            "/usr/local/bin/bash",
        )
        if b and Path(b).exists()
    }
)
needs_harness = pytest.mark.skipif(
    shutil.which("jq") is None or shutil.which("git") is None or not AVAILABLE_BASHES,
    reason="jq, git and bash are required",
)


def _bash_version(bash: str) -> tuple[int, int]:
    out = subprocess.run(
        [bash, "-c", "echo ${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}"], capture_output=True, text=True
    ).stdout.split()
    return int(out[0]), int(out[1])


# --- N4/N6/N7/N8/N9/N10/N11/N12 static checks ---------------------------------------------------

WRAPPER_NAMES = {
    "timeout",
    "xargs",
    "nohup",
    "env",
    "nice",
    "stdbuf",
    "time",
    "watch",
    "parallel",
    "bash",
    "sh",
    "zsh",
    "eval",
    "-u",
    "-E",
    "exec",
    "command",
}


def wrapper_violations(text: str) -> list[str]:
    """An AWS call must be the command itself (or inside an expectation
    helper), never an argument of another program or a string for a shell."""
    v = []
    for where, body in all_code(text):
        for c in commands(body):
            if c.name == "aws":
                continue
            if "aws" in c.words[1:] and c.name in WRAPPER_NAMES | {"sudo"}:
                v.append(f"{where}: aws runs behind {c.name}")
            elif "aws" in c.words[1:] and c.name not in ("grep", "note", "echo", "printf", "stop"):
                v.append(f"{where}: aws appears as an argument of {c.name}")
            if c.name in ("bash", "sh", "zsh", "eval") and any(
                re.search(r"(^|[\s;&|(])aws\s+[a-z]", w) for w in c.words[1:]
            ):
                v.append(f"{where}: aws runs inside a {c.name} string")
    return v


def credential_source_violations(text: str) -> list[str]:
    """Only short-lived Identity Center credentials: every profile is an SSO
    profile or chains from one with a run-scoped session name; no key, no
    credential_process, no access key created anywhere; X08 cleans only this
    run's cache, and recovery always runs it."""
    v = []
    files = dict(FILE_BLOCK.findall(text))
    config = files["aws-config.workstation"]
    if re.search(
        r"aws_access_key_id|aws_secret_access_key|aws_session_token|credential_process", config
    ):
        v.append("the workstation config holds a key or a credential process")
    if "credential-process.sh" in files:
        v.append("a long-term-key credential helper is still part of the procedure")
    sessions = set(re.findall(r"^\[sso-session (\S+)\]$", config, re.M))
    if sessions != {"nlw-d6-<PROOF_ID>-operator", "nlw-d6-<PROOF_ID>-audit"}:
        v.append(f"SSO sessions are not the two run-scoped ones: {sorted(sessions)}")
    profiles = dict(re.findall(r"^\[profile ([a-z0-9-]+)\]\n(.*?)(?=^\[|\Z)", config, re.M | re.S))
    for name, body in profiles.items():
        sso = re.findall(r"^sso_session = (\S+)$", body, re.M)
        source = re.findall(r"^source_profile = (\S+)$", body, re.M)
        if sso:
            if sso[0] not in sessions or not re.search(
                r"^sso_role_name = <[A-Z_]+_PERMISSION_SET>$", body, re.M
            ):
                v.append(f"profile {name} is not a reviewed Identity Center profile")
        elif source:
            parent = profiles.get(source[0], "")
            if "sso_session = " not in parent:
                v.append(f"profile {name} does not chain from an Identity Center profile")
            if not re.search(r"^role_session_name = nlw-d6-<PROOF_ID>-[a-z-]+$", body, re.M):
                v.append(f"profile {name} has no run-scoped session name")
        else:
            v.append(f"profile {name} has no Identity Center credential source")
    for where, body in all_code(text):
        for c in commands(body):
            call = aws_call(c)
            if call and call[1] in (
                "create-access-key",
                "update-access-key",
                "create-login-profile",
            ):
                v.append(f"{where}: {call[1]} creates a long-term credential")
    if '[[ "$E11_IDENTITY" == identity-center ]]' not in block(text, "P00-02"):
        v.append("P00-02 does not require Identity Center (E11)")
    x08 = block(text, "X08")
    if "nlw-d6-%s-(operator|audit-admin|audit-reader)" not in x08 or "re.escape(proof)" not in x08:
        v.append("X08 does not scope cache deletion to this run")
    if "-delete" in x08 or "-newer" in x08 or "sso logout" in x08:
        v.append("X08 removes sessions beyond this run's")
    if "4. **Always, whatever else happens:** run X08" not in text:
        v.append("recovery does not require X08 after a stop")
    renderer = files.get("render-config.py", "")
    if (
        "aws_access_key_id|aws_secret_access_key|aws_session_token|credential_process"
        not in renderer
        or 'python3 "$PROOF_DIR/render-config.py" "$PROOF_DIR/aws-config.workstation"'
        not in block(text, "P00-02")
    ):
        v.append("P00-02 does not refuse a key in aws-config")
    return v


def bucket_creation_strict_violations(text: str) -> list[str]:
    """N6: between create-bucket and the ledger entry, nothing but the
    pristine checks may touch the bucket."""
    v = []
    for step, ledger in (("P03-06", "REC_BUCKET"), ("P03-07", "REC_AUDIT_BUCKET")):
        cmds = commands(block(text, step))
        create = _call_index(cmds, "s3api", "create-bucket")
        recorded = [
            i for i, c in enumerate(cmds) if c.name == "record" and c.words[1:2] == [ledger]
        ]
        if create < 0 or not recorded:
            v.append(f"{step}: no create-bucket or no ledger entry")
            continue
        for c in cmds[create + 1 : recorded[0]]:
            call = aws_call(c)
            if call and not is_read(call[1]):
                v.append(f"{step}: {call[1]} runs on the new bucket before it is proven new")
        if not any(c.name == "note" and "absence confirmed:" in c.text for c in cmds[:create]):
            v.append(f"{step}: the absence check is not journalled for orphan recovery")
    return v


def _key_args(c: Cmd) -> list[str]:
    keys = []
    for i, w in enumerate(c.words):
        if w == "--key" and i + 1 < len(c.words):
            keys.append(c.words[i + 1])
        elif w.startswith("--key="):
            keys.append(w.split("=", 1)[1])
        elif w == "--delete" and i + 1 < len(c.words):
            keys += re.findall(r"Key\s*[=:]\s*\"?([^,}\" ]+)", c.words[i + 1])
        elif w == "--copy-source" and i + 1 < len(c.words):
            pass
    return keys


def denied_write_strict_violations(text: str) -> list[str]:
    """N7: every expected-denied write names its keys in a parsed form inside
    the proof prefixes; the high-level ``aws s3`` commands are not used."""
    v = []
    for b in labelled_blocks(text):
        if not b["label"]:
            continue
        sid = b["label"]["id"]
        env = dict(PROOF_KEY_ENV)
        env.update({f"REC_OBJ_K{n}": f"versions/<WS1>/k{n}" for n in range(1, 10)})
        env.update({f"REC_MPU_K{n}": f"versions/<WS1>/k{n}" for n in range(1, 10)})
        for name, value in assignments(b["body"]):
            env[name] = expand(value, env)
        for c in commands(b["body"]):
            call = aws_call(c)
            if not call:
                continue
            if call[0] == "s3":
                v.append(f"{sid}: high-level aws s3 {call[1]}")
            if not (c.wrapper and call[1] in WRITE_OPS | {"delete-objects"}):
                continue
            if "--bucket" in c.words and c.words[c.words.index("--bucket") + 1] != "$BUCKET":
                v.append(
                    f"{sid}: expected-denied {call[1]} targets a bucket other than the "
                    f"dataset bucket"
                )
            keys = _key_args(c)
            if not keys:
                v.append(f"{sid}: expected-denied {call[1]} names no parsable key")
            for key in (expand(k, env) for k in keys):
                if not (
                    key.startswith(("versions/<WS1>/", "versions/<WS2>/"))
                    or key == "outside/<WS1>/x"
                ):
                    v.append(f"{sid}: expected-denied {call[1]} on {key}")
    return v


def multipart_recovery_violations(text: str) -> list[str]:
    v = []
    x10 = commands(block(text, "X10"))
    mpu = [c for c in x10 if aws_call(c) == ("s3api", "list-multipart-uploads")]
    if not mpu or any(c.words[c.words.index("--prefix") + 1] != "versions/$ws/" for c in mpu):
        v.append("X10 does not list open uploads under exactly the proof prefixes")
    if not any(c.name == "record" and c.words[1].startswith("REC_RECOVERED_MPU_") for c in x10):
        v.append("X10 does not record open uploads")
    body = block(text, "X10")
    if '[[ "$initiated" > "$started" ]] || stop S8' not in body:
        v.append("X10 does not refuse uploads older than the run")
    x04 = block(text, "X04")
    if "REC_RECOVERED_MPU_" not in x04 or not any(
        aws_call(c) == ("s3api", "abort-multipart-upload") and "${!v}" in c.words
        for c in commands(x04)
    ):
        v.append("X04 does not abort recovered uploads by their recorded ids")
    return v


def human_and_drift_violations(text: str) -> list[str]:
    """Principal lists validated before use; P03-11 compares deployed
    documents with the rendered files and checks each role's shape, the keys'
    grants and the buckets' controls; simulations fail closed."""
    v = []
    validated: set[str] = set()
    for step in ("P03-01", "P03-03"):
        cmds = commands(block(text, step))
        first_role = next((i for i, c in enumerate(cmds) if c.name == "make_role"), -1)
        checks = [i for i, c in enumerate(cmds) if c.name == "validate_principals"]
        if not checks or first_role < 0 or max(checks) > first_role:
            v.append(f"{step} does not validate its principal lists before creating roles")
        validated |= {c.words[2] for c in cmds if c.name == "validate_principals"}
        for c in cmds:
            if c.name == "make_role" and len(c.words) > 5 and c.words[5] not in validated:
                v.append(f"{step}: {c.words[5]} is used before it is validated")
    if validated != {
        "$OPERATOR_HUMANS_JSON",
        "$AUDIT_ADMIN_HUMANS_JSON",
        "$AUDIT_READER_HUMANS_JSON",
    }:
        v.append("P03-01 and P03-03 do not validate all three principal lists")
    lib = dict(FILE_BLOCK.findall(text))["lib.sh"]
    if (
        "json.dumps(people)" not in lib
        or "invalid human principals" not in lib
        or "sso.fullmatch(p)" not in lib
    ):
        v.append("render does not fully validate and re-serialise the human principals")
    if "pattern.fullmatch(p)" not in lib:
        v.append("validate_principals does not match in full")
    p0311 = commands(block(text, "P03-11"))
    compared = {aws_call(c) for c in p0311}
    for needed in (
        ("iam", "get-role"),
        ("iam", "get-role-policy"),
        ("kms", "get-key-policy"),
        ("s3api", "get-bucket-policy"),
        ("s3api", "get-bucket-lifecycle-configuration"),
        ("cloudtrail", "get-event-selectors"),
    ):
        if needed not in compared:
            v.append(f"P03-11 does not compare {needed[1]}")
    body = block(text, "P03-11")
    if body.count('same "') < 9:
        v.append("P03-11 compares fewer deployed documents than reviewed")
    for snippet in (
        'verify_role_shape "nlw-staging-dataset-$r" "nlw-dataset-$r"',
        'verify_no_grants "$REC_KEY_ARN"',
        'verify_no_grants "$REC_AUDIT_KEY_ARN"',
        'verify_bucket_controls "$BUCKET"',
        'verify_bucket_controls "$AUDIT_BUCKET"',
        '--key-id "$REC_AUDIT_KEY_ARN" \\\n  --query KeyRotationEnabled'.replace("\\\n", " "),
        'validate_principals iam "$E12_MUST_NOT_PASS_JSON"',
        'sim_denied "$principal"',
        "audit bucket encryption differs",
    ):
        if snippet not in body.replace("\\\n", " "):
            v.append(f"P03-11 lacks: {snippet}")
    if "!= allowed" in body:
        v.append("P03-11 accepts a failed or empty simulation")
    for snippet in (
        '[[ -n "${out//[[:space:]]/}" ]] || stop S9',
        'stop S4 "$who is allowed',
        '|| stop S9 "the simulation for $who failed"',
        "$role has attached managed policies",
        "$role does not carry exactly the proof boundary",
        "a KMS grant exists on $1",
        "public access is not fully blocked on $1",
        "ACLs are not disabled on $1",
        '[[ -n "$got" ]] || stop S9 "the simulator returned no decision"',
    ):
        if snippet not in lib:
            v.append(f"lib.sh lacks: {snippet}")
    return v


def orphan_bucket_violations(text: str) -> list[str]:
    v = []
    x12 = block(text, "X12")
    for needed in (
        '[[ "$name" == *"$SUFFIX" ]] || stop S8',
        'grep -qF "absence confirmed: ${name/"$ACCOUNT"/<ACCOUNT>}" "$PROOF_DIR/journal.log"',
        "ON_ALLOWED=S8 expect_error NoSuchTagSet",
        "ON_ALLOWED=S8 expect_error NoSuchBucketPolicy",
        '|| stop S8 "$name holds objects',
    ):
        if needed not in x12:
            v.append(f"X12 lacks: {needed}")
    cmds = commands(x12)
    rec = [i for i, c in enumerate(cmds) if c.name == "record"]
    dele = [i for i, c in enumerate(cmds) if aws_call(c) == ("s3api", "delete-bucket")]
    if not rec or not dele or min(dele) < min(rec):
        v.append("X12 deletes before recording")
    return v


def trap_violations(text: str) -> list[str]:
    v = []
    lib = dict(FILE_BLOCK.findall(text))["lib.sh"]
    code = "\n".join(line for line in lib.splitlines() if not line.lstrip().startswith("#"))
    if re.search(r"^set -[a-zA-Z]*E", code, re.M) or re.search(r"trap .* ERR\b", code):
        v.append("lib.sh inherits an ERR trap into substitutions")
    if "trap _on_exit EXIT" not in code or 'eval "$ON_EXIT"' not in code:
        v.append("lib.sh does not run cleanups on every exit")
    if 'on_exit "kill $ROTATOR 2> /dev/null; wait $ROTATOR 2> /dev/null"' not in block(
        text, "P14-02"
    ):
        v.append("P14-02 does not stop the rotator on every exit")
    return v


def consistency_violations(text: str) -> list[str]:
    """N12: one way to run steps, exports only in P00-01, and the docs agree
    with what the procedure does."""
    v = []
    if any(c.name != "export" for c in commands(block(text, "P00-01")) if not c.nested):
        v.append("P00-01 does more than export variables")
    if "paste it into `bash -s`" in text:
        v.append("the procedure still tells the operator to paste steps into bash -s")
    if (
        "| **S2** | an expected bucket, role, key, trail or instance already exists, or a "
        "just-created bucket is not new | P02, P03-06, P03-07 |" not in text
    ):
        v.append("the stop table does not list where S2 is enforced")
    if "`<SUFFIX>` is empty" in text:
        v.append("A.1 still describes an optional suffix")
    lib = dict(FILE_BLOCK.findall(text))["lib.sh"]
    if "${#AUDIT_BUCKET} <= 63" not in lib or '"$ADMIN_ROLE" != arn:*' not in lib:
        v.append("lib.sh does not check bucket-name length or the ADMIN_ROLE form")
    p0003 = block(text, "P00-03")
    if '[[ "$arn" == "arn:aws:sts::${ACCOUNT}:assumed-role/AWSReservedSSO_${2}_"* ]]' not in p0003:
        v.append("P00-03 does not verify that each identity is an Identity Center session")
    if '[[ "${ADMIN_ROLE##*/}" != nlw-*-dataset-* ]]' not in lib:
        v.append("lib.sh does not refuse a dataset role as ADMIN_ROLE")
    return v


# --- F2: the only AWS changes the procedure may make ---------------------------------------------

ALLOWED_MUTATIONS: dict[str, set[str]] = {
    "iam": {
        "create-role",
        "put-role-policy",
        "create-instance-profile",
        "add-role-to-instance-profile",
        "remove-role-from-instance-profile",
        "delete-instance-profile",
        "delete-role-policy",
        "delete-role",
    },
    "kms": {
        "create-key",
        "create-alias",
        "enable-key-rotation",
        "disable-key",
        "schedule-key-deletion",
    },
    "s3api": {
        "create-bucket",
        "put-public-access-block",
        "put-bucket-tagging",
        "put-bucket-versioning",
        "put-bucket-encryption",
        "put-bucket-lifecycle-configuration",
        "put-bucket-policy",
        "put-object-lock-configuration",
        "put-object",
        "copy-object",
        "create-multipart-upload",
        "upload-part",
        "complete-multipart-upload",
        "abort-multipart-upload",
        "delete-object",
        "delete-bucket",
        "delete-objects",
    },
    "cloudtrail": {
        "create-trail",
        "put-event-selectors",
        "start-logging",
        "stop-logging",
        "delete-trail",
    },
    "ec2": {
        "create-security-group",
        "authorize-security-group-ingress",
        "run-instances",
        "terminate-instances",
        "delete-security-group",
    },
    "ec2-instance-connect": {"send-ssh-public-key"},
    "budgets": {"create-budget"},
    "sso": set(),
    "sts": set(),
}


def mutation_allowlist_violations(text: str) -> list[str]:
    """Every mutating AWS call the procedure can make is one of the reviewed
    operations; inline policies come only from rendered files; every created
    role carries the proof boundary."""
    v = []
    for where, body in all_code(text):
        for c in commands(body):
            call = aws_call(c)
            if not call or is_read(call[1]):
                continue
            service, op = call
            if op not in ALLOWED_MUTATIONS.get(service, set()):
                v.append(f"{where}: aws {service} {op} is not a reviewed change")
            if (service, op) == ("iam", "put-role-policy"):
                doc = (
                    c.words[c.words.index("--policy-document") + 1]
                    if "--policy-document" in c.words
                    else ""
                )
                if not re.fullmatch(r"file://\$PROOF_DIR/policy-[a-z$-]+\.json", doc):
                    v.append(f"{where}: put-role-policy with an unrendered document {doc!r}")
            if (service, op) == ("iam", "create-role") and (
                "--permissions-boundary" not in c.words
                or c.words[c.words.index("--permissions-boundary") + 1] != "$PROOF_BOUNDARY_ARN"
            ):
                v.append(f"{where}: create-role without the proof boundary")
    return v


def gate_violations(text: str) -> list[str]:
    """D6 is blocked: no independent verification record exists, the
    procedure says so, and P00-02 refuses to start without a matching record
    read from the reviewed commit itself (M1) that records a dedicated proof
    account (E14)."""
    v = []
    if (ROOT / "docs" / "evidence" / "o2-d6" / "d6-gate.json").exists():
        v.append(
            "a D6 gate record exists in this change; it must arrive in its own reviewed commit"
        )
    if "**D6 is BLOCKED.**" not in text:
        v.append("the procedure does not say that D6 is blocked")
    p00 = block(text, "P00-02")
    for needed in (
        'git cat-file -e "$REVIEWED_COMMIT:$GATE"',
        'record="$(git show "$REVIEWED_COMMIT:$GATE")"',
        '"$(git rev-parse "$REVIEWED_COMMIT^")" == "$procedure"',
        '[[ "$(git diff --name-only "$procedure" "$REVIEWED_COMMIT")" == "$GATE" ]]',
        "git status --porcelain --ignored -- docs/runbooks docs/evidence",
        '"verified_by": bool(gate.get("verified_by")) and gate.get("verified_by") != '
        'env["OPERATOR_NAME"]',
        '"decision": gate.get("decision") == "approved"',
        '"account_mode": gate.get("account_mode") == "dedicated"',
        '"distinct_account": staging is not None and production is not None',
        '"no_production_resources_verified": gate.get("no_production_resources_verified") is True',
        '"permission_set_policies_verified": gate.get("permission_set_policies_verified") is True',
        '"boundary_attached_verified": gate.get("boundary_attached_verified") is True',
        '"effective_permissions_verified": gate.get("effective_permissions_verified") is True',
        '"identity_center_mfa_required": gate.get("identity_center_mfa_required") is True',
        '"account_administrators_outside_operator": '
        'gate.get("account_administrators_outside_operator") is True',
        "STOP S9: D6 is blocked (decision E15)",
        'git show "$REVIEWED_COMMIT:docs/runbooks/dataset-s3-d6-proof.md"',
    ):
        if needed not in p00.replace("\\\n", " ").replace("\n                        ", " "):
            v.append(f"P00-02 lacks: {needed}")
    if "RUNBOOK_DIR/../evidence" in p00 or "os.path.isfile(path)" in p00:
        v.append("P00-02 reads the gate record from the working tree")
    if "bounded" in p00 or "E14_ACCOUNT_MODE" in text:
        v.append("the shared-account (bounded) mode is still accepted")
    p0102 = block(text, "P01-02")
    for needed in (
        'same "proof boundary"',
        'same "proof deny policy"',
        'verify_permission_set_role "${arn##*/}" "$2"',
        "iam:AttachRolePolicy iam:CreateAccessKey",
        "iam:CreateSAMLProvider",
        "s3:PutObject s3:DeleteObject",
        'check_principal "$ROLE_PREFIX/$ADMIN_ROLE" proof-admin dataset',
        'check_principal "$arn" audit-admin audit',
    ):
        if needed not in p0102.replace("\\\n", " "):
            v.append(f"P01-02 lacks: {needed}")
    lib = dict(FILE_BLOCK.findall(text))["lib.sh"]
    for needed in (
        "$role has managed policies other than the proof deny policy",
        '[[ "$(jq -c \'sort\' <<< "$out")" == \'["AwsSSOInlinePolicy"]\' ]]',
        "account not in lists[0] + lists[1]",
    ):
        if needed not in lib:
            v.append(f"lib.sh lacks: {needed}")
    p0101, p0103 = block(text, "P01-01"), block(text, "P01-03")
    if "verify_dedicated_account" not in p0101 or "verify_dedicated_account" not in p0103:
        v.append("P01 does not check that the proof account is dedicated")
    for needed in (
        "aws organizations describe-organization",
        "the organization differs from the verified gate record",
        "^(alias/)?nlw-production-",
        "Key=nlw-env,Values=production",
        '> "$PROOF_DIR/evidence/p01-account.json"',
    ):
        if needed not in p0103:
            v.append(f"P01-03 lacks: {needed}")
    order = [b["label"]["id"] for b in labelled_blocks(text) if b["label"]]
    if order.index("P01-03") > order.index("P02-01"):
        v.append("the account is not recorded before the first change")
    return v


PERMISSION_SETS = (
    "permission-set-proof-admin",
    "permission-set-operator",
    "permission-set-audit-admin",
    "permission-set-audit-reader",
)
IDENTITY_POLICIES = (*PERMISSION_SETS, *ALL_ROLES)
_PROOF_BUCKETS = {
    "arn:aws:s3:::nlw-<ENV>-datasets-<ACCOUNT>-us-east-1-d6*",
    "arn:aws:s3:::nlw-<ENV>-dataset-audit-<ACCOUNT>-us-east-1-d6*",
}
_KEYS = "arn:aws:kms:us-east-1:<ACCOUNT>:key/*"
SIX_ROLES = {
    role(r) for r in ("bootstrap", "api", "ingest", "operator", "audit-admin", "audit-reader")
}
# The boundary's allow-list, pinned: each Allow's exact resources. Its actions
# must be exactly the union of the identity policies' (checked below).
BOUNDARY_RESOURCES: dict[str, set[str]] = {
    "D6NoResourceScope": {"*"},
    "D6ReadPrincipals": {"arn:aws:iam::<ACCOUNT>:role/*", "arn:aws:iam::<ACCOUNT>:user/*"},
    "D6ReadTheProofPolicies": {
        "<PROOF_BOUNDARY_ARN>",
        "arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-proof-denies",
    },
    "D6TheSixRoles": SIX_ROLES,
    "D6TheBootstrapProfileAndRole": {
        "arn:aws:iam::<ACCOUNT>:instance-profile/nlw-<ENV>-dataset-bootstrap",
        role("bootstrap"),
    },
    "D6TheProofBuckets": _PROOF_BUCKETS,
    "D6TheProofKeys": {
        _KEYS,
        "arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-datasets",
        "arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-dataset-audit",
    },
    "D6TheDataEventTrail": {"<TRAIL_ARN>"},
    "D6TheProofInstance": {"arn:aws:ec2:us-east-1:<ACCOUNT>:*", "arn:aws:ec2:us-east-1::image/*"},
    "D6SshKeyToTheProofInstance": {"arn:aws:ec2:us-east-1:<ACCOUNT>:instance/*"},
    "D6TheAmiParameter": {
        "arn:aws:ssm:us-east-1::parameter/aws/service/ami-amazon-linux-latest/"
        "al2023-ami-kernel-6.1-x86_64"
    },
    "D6TheProofBudget": {"arn:aws:budgets::<ACCOUNT>:budget/nlw-<ENV>-dataset-proof-*"},
}
# Example values for the run-time placeholders, used only to ask whether a
# boundary resource pattern covers an identity policy's resource.
_EXAMPLE = {
    "<BUCKET>": "nlw-<ENV>-datasets-<ACCOUNT>-us-east-1-d6x",
    "<AUDIT_BUCKET>": "nlw-<ENV>-dataset-audit-<ACCOUNT>-us-east-1-d6x",
    "<KEY_ARN>": "arn:aws:kms:us-east-1:<ACCOUNT>:key/k1",
    "<AUDIT_KEY_ARN>": "arn:aws:kms:us-east-1:<ACCOUNT>:key/k2",
}


def _example(resource: str) -> str:
    for k, val in _EXAMPLE.items():
        resource = resource.replace(k, val)
    return resource


_RESOURCE_SERVICE = {
    "<TRAIL_ARN>": "cloudtrail",
    "<KEY_ARN>": "kms",
    "<AUDIT_KEY_ARN>": "kms",
    "<PROOF_BOUNDARY_ARN>": "iam",
}
_ACTION_SERVICE = {"sts": "iam", "ec2-instance-connect": "ec2"}


def _applies(action: str, resource: str) -> bool:
    """Whether an action can apply to a resource: a statement may list several
    services' resources, and each action only acts on its own service's."""
    service = _ACTION_SERVICE.get(action.split(":")[0], action.split(":")[0])
    owner = _RESOURCE_SERVICE.get(resource) or resource.split(":")[2]
    return service == owner


def _covers(pattern: str, resource: str) -> bool:
    regex = "".join(".*" if ch == "*" else re.escape(ch) for ch in pattern)
    return re.fullmatch(regex, _example(resource)) is not None


def boundary_violations(t: Templates) -> list[str]:
    """The boundary is an allow-list: its Allows are the pinned resources and
    exactly the union of the identity policies' actions; every identity
    Allow is covered (action and resource) by a boundary Allow; it names the
    six exact roles, never a dataset-role pattern; created roles must carry
    it. The deny policy and the permission sets carry the mandated denies."""
    v = []
    b = t.get("proof-principal-boundary")
    denies = t.get("proof-principal-denies")
    if b is None or denies is None:
        return ["the proof boundary or deny policy template is missing"]
    bound = {s.get("Sid"): s for s in allows(b)}
    if set(bound) != set(BOUNDARY_RESOURCES):
        v.append(f"boundary Allows {sorted(map(str, bound))} differ from the pinned allow-list")
    for sid, s in bound.items():
        if "NotAction" in s or "NotResource" in s:
            v.append(f"boundary/{sid}: NotAction or NotResource in an Allow")
        if any(a == "*" or a.endswith(":*") for a in actions(s)):
            v.append(f"boundary/{sid}: a wildcard action")
        if set(as_list(s.get("Resource", []))) != BOUNDARY_RESOURCES.get(str(sid)):
            v.append(f"boundary/{sid}: resources differ from the pinned allow-list")
    union = {a for name in IDENTITY_POLICIES for a in allowed_actions(t[name])}
    granted = {a for s in bound.values() for a in actions(s)}
    if granted != union:
        v.append(
            f"boundary allows {sorted(granted - union)} beyond, or lacks {sorted(union - granted)}"
            " of, what the proof identities use"
        )
    for name in IDENTITY_POLICIES:
        for s in allows(t[name]):
            for a in actions(s):
                for r in as_list(s.get("Resource", [])):
                    if r != "*" and not _applies(a, r):
                        continue
                    if r == "*":
                        ok = any(a in actions(x) for x in bound.values())
                    else:
                        ok = any(
                            a in actions(x) and any(_covers(p, r) for p in as_list(x["Resource"]))
                            for x in bound.values()
                        )
                    if not ok:
                        v.append(f"{name}/{s.get('Sid')}: {a} on {r} is outside the boundary")
    text = json.dumps([b, denies, *(t[n] for n in PERMISSION_SETS)])
    if "dataset-*" in text or "dataset-*" in json.dumps(b):
        v.append("a proof policy names roles by a dataset-* pattern instead of the six exact ARNs")
    sids = by_sid(b)
    created = sids.get("CreatedRolesCarryThisBoundary", {})
    if created.get("Effect") != "Deny" or created.get("Condition") != {
        "StringNotEquals": {"iam:PermissionsBoundary": "<PROOF_BOUNDARY_ARN>"}
    }:
        v.append("roles the proof creates need not carry the boundary")
    d = by_sid(denies)
    escalate = actions(d.get("NeverEscalate", {}))
    for a in (
        "iam:AttachRolePolicy",
        "iam:CreateAccessKey",
        "iam:CreatePolicy",
        "iam:CreatePolicyVersion",
        "iam:PutRolePermissionsBoundary",
        "iam:DeleteRolePermissionsBoundary",
        "sso:*",
    ):
        if a not in escalate:
            v.append(f"the deny policy does not refuse {a}")
    if actions(d.get("NeverIdentityProviders", {})) != {
        "iam:*SAMLProvider",
        "iam:*OpenIDConnectProvider*",
    }:
        v.append("the deny policy does not refuse SAML and OIDC provider changes")
    assume = d.get("AssumeOnlyTheProofRoles", {})
    if "sts:AssumeRole" not in actions(assume) or set(as_list(assume.get("NotResource"))) != (
        SIX_ROLES - {role("bootstrap")}
    ):
        v.append("the deny policy does not limit AssumeRole to the five assumed proof roles")
    if d.get("PassOnlyTheBootstrapRole", {}).get("NotResource") != role("bootstrap"):
        v.append("the deny policy does not limit PassRole to the bootstrap role")
    if d.get("PassTheBootstrapRoleOnlyToEc2", {}).get("Condition", {}).get("StringNotEquals") != {
        "iam:PassedToService": "ec2.amazonaws.com"
    }:
        v.append("the bootstrap role may be passed to a service other than EC2")
    indirect = actions(d.get("NeverIndirectExecution", {}))
    for a in ("lambda:*", "codebuild:*", "ssmmessages:*", "ec2-instance-connect:OpenTunnel"):
        if a not in indirect:
            v.append(f"the deny policy does not refuse {a}")
    if "ssm:*" not in actions(d.get("NeverSsmBeyondTheAmiParameter", {})):
        v.append("the deny policy does not refuse SSM beyond the AMI parameter")
    if not {"account:*", "organizations:Leave*", "organizations:Update*"} <= actions(
        d.get("NeverOrganizationOrAccountChanges", {})
    ):
        v.append("the deny policy does not refuse organization or account changes")
    own = d.get("NeverChangeTheProofPrincipalsOrPolicies", {})
    if not (
        {"arn:aws:iam::<ACCOUNT>:role/aws-reserved/*", "<PROOF_BOUNDARY_ARN>"}
        <= set(as_list(own.get("Resource")))
        and {"iam:UpdateAssumeRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePermissionsBoundary"}
        <= actions(own)
    ):
        v.append("a proof principal may change its own trust, permissions or boundary")
    region = d.get("OnlyTheApprovedRegion", {})
    if region.get("Condition") != {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}} or set(
        as_list(region.get("NotAction"))
    ) != {"budgets:*", "iam:*", "organizations:*", "sts:*"}:
        v.append("the deny policy does not confine the proof to us-east-1")
    return v


AUDIT_SIDE = {
    role("audit-admin"),
    role("audit-reader"),
    "arn:aws:s3:::nlw-<ENV>-dataset-audit-<ACCOUNT>-us-east-1-d6*",
    "arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-dataset-audit",
}
DATASET_SIDE = {
    role("bootstrap"),
    role("api"),
    role("ingest"),
    role("operator"),
    "arn:aws:iam::<ACCOUNT>:instance-profile/nlw-<ENV>-dataset-bootstrap",
    "arn:aws:s3:::nlw-<ENV>-datasets-<ACCOUNT>-us-east-1-d6*",
    "arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-datasets",
}
READ_ACTION = re.compile(r"[a-z0-9-]+:(Get|List|Describe|Simulate)")
ROLE_CHANGES = {
    "iam:AttachRolePolicy",
    "iam:CreateRole",
    "iam:DeleteRole",
    "iam:DeleteRolePolicy",
    "iam:PutRolePolicy",
    "iam:UpdateAssumeRolePolicy",
    "iam:PutRolePermissionsBoundary",
    "iam:DeleteRolePermissionsBoundary",
}


def separation_violations(t: Templates) -> list[str]:
    """E9: the operator side (proof administrator, operator) can never change
    the audit roles, the trail, the audit bucket or the audit key; the audit
    side never the dataset roles, bucket or key. Each side's Allows never name
    the other side, and its explicit denies cover the other side."""
    v = []

    def denied(name: str, sid: str, action: str, resources: set[str]) -> bool:
        s = by_sid(t[name]).get(sid, {})
        acts = actions(s)
        hit = action in acts or f"{action.split(':')[0]}:*" in acts
        return s.get("Effect") == "Deny" and hit and resources <= set(as_list(s.get("Resource")))

    for name in ("permission-set-proof-admin", "permission-set-operator"):
        for a in sorted(ROLE_CHANGES | {"sts:AssumeRole", "s3:PutBucketPolicy", "kms:DeleteAlias"}):
            if not denied(name, "NeverTheAuditRolesBucketOrAlias", a, AUDIT_SIDE):
                v.append(f"{name}: {a} on the audit side is not explicitly denied")
        trail = by_sid(t[name]).get("NeverAlterAnyTrail", {})
        if trail.get("Resource") != "*" or not {
            "cloudtrail:StopLogging",
            "cloudtrail:DeleteTrail",
            "cloudtrail:UpdateTrail",
            "cloudtrail:PutEventSelectors",
        } <= actions(trail):
            v.append(f"{name}: may stop, narrow or delete audit recording")
        keys = by_sid(t[name]).get("NeverAuditKeys", {})
        if keys.get("Condition") != {"StringEquals": {"aws:ResourceTag/nlw-purpose": "audit"}}:
            v.append(f"{name}: may administer the audit key")
        for s in allows(t[name]):
            changes = {a for a in actions(s) if not READ_ACTION.match(a)}
            if (set(as_list(s.get("Resource", []))) & AUDIT_SIDE and changes) or any(
                a.startswith("cloudtrail:") and a != "cloudtrail:DescribeTrails" for a in actions(s)
            ):
                v.append(f"{name}/{s.get('Sid')}: an Allow reaches the audit side")
            if actions(s) & {"kms:PutKeyPolicy", "kms:CreateGrant"}:
                v.append(f"{name}/{s.get('Sid')}: may change a key policy or grant")
    for name in ("permission-set-audit-admin", "permission-set-audit-reader"):
        for a in sorted(ROLE_CHANGES | {"sts:AssumeRole", "s3:GetObject", "kms:Decrypt"}):
            if not denied(name, "NeverTheDatasetRolesBucketOrAlias", a, DATASET_SIDE):
                v.append(f"{name}: {a} on the dataset side is not explicitly denied")
        keys = by_sid(t[name]).get("NeverDatasetKeys", {})
        if keys.get("Condition") != {"StringEquals": {"aws:ResourceTag/nlw-purpose": "dataset"}}:
            v.append(f"{name}: may use or administer the dataset key")
        for s in allows(t[name]):
            if set(as_list(s.get("Resource", []))) & DATASET_SIDE:
                v.append(f"{name}/{s.get('Sid')}: an Allow reaches the dataset side")
    admin = by_sid(t["permission-set-proof-admin"])
    if admin.get("AdministerOnlyDatasetKeys", {}).get("Condition") != {
        "StringEquals": {"aws:ResourceTag/nlw-purpose": "dataset"}
    }:
        v.append("the proof administrator may administer keys other than the dataset key")
    for name, sid, target in (
        ("permission-set-operator", "AssumeOnlyTheOperatorRole", "operator"),
        ("permission-set-audit-admin", "AssumeOnlyTheAuditAdminRole", "audit-admin"),
        ("permission-set-audit-reader", "AssumeOnlyTheAuditReaderRole", "audit-reader"),
    ):
        s = by_sid(t[name]).get(sid, {})
        if s.get("Resource") != role(target) or s.get("Condition") != {
            "StringLike": {"sts:RoleSessionName": f"nlw-d6-*-{target}"}
        }:
            v.append(f"{name} may assume more than {target}, or without a run-scoped session")
    return v


EXPECTED_PERMISSION_SET_ALLOWS: dict[
    str, dict[str, tuple[set[str], set[str], dict[str, Any] | None]]
] = {
    "permission-set-proof-admin": {
        "ReadTheAccountInventory": (
            {
                "iam:ListRoles",
                "ec2:DescribeVpcs",
                "organizations:DescribeOrganization",
                "tag:GetResources",
                "cloudtrail:DescribeTrails",
                "ec2:DescribeTags",
                "ec2:DescribeInstances",
                "ec2:DescribeAvailabilityZones",
                "kms:ListAliases",
                "iam:SimulateCustomPolicy",
                "ec2:DescribeInstanceStatus",
                "s3:ListAllMyBuckets",
                "iam:ListAccountAliases",
            },
            {"*"},
            None,
        ),
        "InspectTheProofPrincipals": (
            {
                "iam:GetRolePolicy",
                "iam:ListRolePolicies",
                "iam:ListAttachedRolePolicies",
                "iam:ListRoleTags",
                "iam:GetRole",
            },
            {
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-admin",
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api",
                "arn:aws:iam::<ACCOUNT>:role/aws-reserved/sso.amazonaws.com/*",
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest",
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator",
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap",
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-reader",
            },
            None,
        ),
        "SimulateThisAccountsPrincipals": (
            {"iam:SimulatePrincipalPolicy"},
            {"arn:aws:iam::<ACCOUNT>:role/*", "arn:aws:iam::<ACCOUNT>:user/*"},
            None,
        ),
        "ReadTheProofPolicies": (
            {"iam:GetPolicy", "iam:GetPolicyVersion"},
            {"arn:aws:iam::<ACCOUNT>:policy/nlw-<ENV>-d6-proof-denies", "<PROOF_BOUNDARY_ARN>"},
            None,
        ),
        "CreateDatasetRolesOnlyWithTheBoundary": (
            {"iam:CreateRole"},
            {
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest",
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap",
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api",
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator",
            },
            {"StringEquals": {"iam:PermissionsBoundary": "<PROOF_BOUNDARY_ARN>"}},
        ),
        "ConfigureDatasetRoles": (
            {"iam:DeleteRolePolicy", "iam:TagRole", "iam:PutRolePolicy", "iam:DeleteRole"},
            {
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-ingest",
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap",
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-api",
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator",
            },
            None,
        ),
        "TheBootstrapInstanceProfile": (
            {
                "iam:GetInstanceProfile",
                "iam:RemoveRoleFromInstanceProfile",
                "iam:DeleteInstanceProfile",
                "iam:AddRoleToInstanceProfile",
                "iam:ListInstanceProfileTags",
                "iam:TagInstanceProfile",
                "iam:CreateInstanceProfile",
            },
            {"arn:aws:iam::<ACCOUNT>:instance-profile/nlw-<ENV>-dataset-bootstrap"},
            None,
        ),
        "PassOnlyTheBootstrapRole": (
            {"iam:PassRole"},
            {"arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap"},
            None,
        ),
        "AdministerTheDatasetBucket": (
            {
                "s3:ListBucket",
                "s3:PutBucketTagging",
                "s3:GetBucketVersioning",
                "s3:GetBucketOwnershipControls",
                "s3:DeleteBucket",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketTagging",
                "s3:GetEncryptionConfiguration",
                "s3:GetLifecycleConfiguration",
                "s3:PutBucketOwnershipControls",
                "s3:PutLifecycleConfiguration",
                "s3:PutBucketPolicy",
                "s3:PutBucketVersioning",
                "s3:ListBucketVersions",
                "s3:GetBucketPolicy",
                "s3:PutEncryptionConfiguration",
                "s3:PutBucketPublicAccessBlock",
                "s3:CreateBucket",
            },
            {"arn:aws:s3:::nlw-<ENV>-datasets-<ACCOUNT>-us-east-1-d6*"},
            None,
        ),
        "FindTheOneWriteOutsideVersions": (
            {"s3:GetObject"},
            {"arn:aws:s3:::nlw-<ENV>-datasets-<ACCOUNT>-us-east-1-d6*/outside/*"},
            None,
        ),
        "CreateOnlyDatasetKeys": (
            {"kms:CreateKey"},
            {"*"},
            {
                "StringEquals": {
                    "aws:RequestTag/nlw-env": "<ENV>",
                    "aws:RequestTag/nlw-purpose": "dataset",
                }
            },
        ),
        "TagOnlyNewDatasetKeys": (
            {"kms:TagResource"},
            {"arn:aws:kms:us-east-1:<ACCOUNT>:key/*"},
            {
                "StringEquals": {"aws:RequestTag/nlw-purpose": "dataset"},
                "Null": {"aws:ResourceTag/nlw-purpose": "true"},
            },
        ),
        "AdministerOnlyDatasetKeys": (
            {
                "kms:EnableKeyRotation",
                "kms:CreateAlias",
                "kms:ScheduleKeyDeletion",
                "kms:GetKeyRotationStatus",
                "kms:ListGrants",
                "kms:ListResourceTags",
                "kms:DisableKey",
                "kms:DescribeKey",
                "kms:GetKeyPolicy",
            },
            {"arn:aws:kms:us-east-1:<ACCOUNT>:key/*"},
            {"StringEquals": {"aws:ResourceTag/nlw-purpose": "dataset"}},
        ),
        "TheDatasetKeyAlias": (
            {"kms:CreateAlias"},
            {"arn:aws:kms:us-east-1:<ACCOUNT>:alias/nlw-<ENV>-datasets"},
            None,
        ),
        "LaunchTheProofInstance": (
            {"ec2:CreateSecurityGroup", "ec2:RunInstances"},
            {"arn:aws:ec2:us-east-1:<ACCOUNT>:*", "arn:aws:ec2:us-east-1::image/*"},
            None,
        ),
        "TagOnlyAtLaunch": (
            {"ec2:CreateTags"},
            {
                "arn:aws:ec2:us-east-1:<ACCOUNT>:security-group/*",
                "arn:aws:ec2:us-east-1:<ACCOUNT>:instance/*",
            },
            {"StringEquals": {"ec2:CreateAction": ["RunInstances", "CreateSecurityGroup"]}},
        ),
        "ChangeOnlyTheTaggedProofInstance": (
            {
                "ec2:DeleteSecurityGroup",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:TerminateInstances",
            },
            {
                "arn:aws:ec2:us-east-1:<ACCOUNT>:security-group/*",
                "arn:aws:ec2:us-east-1:<ACCOUNT>:instance/*",
            },
            {"StringEquals": {"aws:ResourceTag/nlw-env": "<ENV>"}},
        ),
        "SshKeyToTheProofInstanceOnly": (
            {"ec2-instance-connect:SendSSHPublicKey"},
            {"arn:aws:ec2:us-east-1:<ACCOUNT>:instance/*"},
            {"StringEquals": {"aws:ResourceTag/nlw-env": "<ENV>", "ec2:osuser": "ec2-user"}},
        ),
        "ReadTheAmiParameter": (
            {"ssm:GetParameters"},
            {
                "arn:aws:ssm:us-east-1::parameter/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64"
            },
            None,
        ),
        "TheProofBudget": (
            {"budgets:ModifyBudget", "budgets:ViewBudget"},
            {"arn:aws:budgets::<ACCOUNT>:budget/nlw-<ENV>-dataset-proof-*"},
            None,
        ),
    },
    "permission-set-operator": {
        "AssumeOnlyTheOperatorRole": (
            {"sts:AssumeRole"},
            {"arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator"},
            {"StringLike": {"sts:RoleSessionName": "nlw-d6-*-operator"}},
        ),
    },
    "permission-set-audit-admin": {
        "AssumeOnlyTheAuditAdminRole": (
            {"sts:AssumeRole"},
            {"arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-admin"},
            {"StringLike": {"sts:RoleSessionName": "nlw-d6-*-audit-admin"}},
        ),
        "CreateAuditRolesOnlyWithTheBoundary": (
            {"iam:CreateRole"},
            {
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-reader",
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-admin",
            },
            {"StringEquals": {"iam:PermissionsBoundary": "<PROOF_BOUNDARY_ARN>"}},
        ),
        "ConfigureAuditRoles": (
            {
                "iam:PutRolePolicy",
                "iam:GetRolePolicy",
                "iam:TagRole",
                "iam:ListRolePolicies",
                "iam:ListAttachedRolePolicies",
                "iam:GetRole",
            },
            {
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-reader",
                "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-admin",
            },
            None,
        ),
        "ConfirmTheAuditResourcesAreAbsent": (
            {"s3:ListBucket", "cloudtrail:GetTrail", "kms:DescribeKey"},
            {
                "arn:aws:kms:us-east-1:<ACCOUNT>:key/*",
                "arn:aws:s3:::nlw-<ENV>-dataset-audit-<ACCOUNT>-us-east-1-d6*",
                "<TRAIL_ARN>",
            },
            None,
        ),
    },
    "permission-set-audit-reader": {
        "AssumeOnlyTheAuditReaderRole": (
            {"sts:AssumeRole"},
            {"arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-audit-reader"},
            {"StringLike": {"sts:RoleSessionName": "nlw-d6-*-audit-reader"}},
        ),
    },
}


def permission_set_statement_violations(t: Templates) -> list[str]:
    """Every permission set's Allow statements are exactly the pinned ones."""
    v = []
    for name, expected in EXPECTED_PERMISSION_SET_ALLOWS.items():
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


# --- H1: every render names a template that exists, and every template is rendered ------------

_RENDER_ARG = re.compile(r"^[a-z0-9$-]+$")


def rendered_templates(text: str) -> tuple[set[str], list[str]]:
    """The template names the procedure renders, with loop variables and
    `make_role`'s template argument resolved, and every invocation that
    cannot be resolved to literal names."""
    names: set[str] = set()
    unresolved: list[str] = []
    for where, body in all_code(text):
        loops: dict[str, list[str]] = {}
        for line in logical_lines(body):
            m = re.match(r"\s*for (\w+) in ([a-z0-9 -]+); do", line)
            if m:
                loops[m.group(1)] = m.group(2).split()
        for c in commands(body):
            if c.name == "render" and len(c.words) > 1:
                arg = c.words[1]
            elif c.name == "make_role" and len(c.words) > 3:
                arg = c.words[3]
            else:
                continue
            if where == "lib.sh" and arg in ("$1", "$3"):
                continue  # the definitions of render and make_role themselves
            var = re.search(r"\$\{?(\w+)\}?", arg)
            if var and var.group(1) in loops and _RENDER_ARG.match(arg):
                names |= {re.sub(r"\$\{?\w+\}?", x, arg) for x in loops[var.group(1)]}
            elif "$" in arg or not _RENDER_ARG.match(arg):
                unresolved.append(f"{where}: render {arg}")
            else:
                names.add(arg)
    return names, unresolved


def render_violations(text: str, t: Templates | None = None) -> list[str]:
    templates = set(t if t is not None else load_templates())
    used, unresolved = rendered_templates(text)
    v = [f"{u} cannot be resolved to a reviewed template" for u in unresolved]
    v += [f"the procedure renders {n}, which is not a template" for n in sorted(used - templates)]
    v += [f"the template {n} is never rendered by the procedure" for n in sorted(templates - used)]
    return v


# --- H2: one source of session names, matching the generated profiles -------------------------


def session_violations(text: str) -> list[str]:
    v = []
    files = dict(FILE_BLOCK.findall(text))
    lib, config = files["lib.sh"], files["aws-config.workstation"]
    if 'session_name() { printf \'nlw-d6-%s-%s\' "$PROOF_ID" "$1"; }' not in lib:
        v.append("lib.sh does not define the one session-name helper")
    profiles = dict(re.findall(r"^\[profile ([a-z0-9-]+)\]\n(.*?)(?=^\[|\Z)", config, re.M | re.S))
    sessions = set(re.findall(r"^\[sso-session nlw-d6-<PROOF_ID>-([a-z-]+)\]$", config, re.M))
    chained: dict[str, tuple[str, str]] = {}
    for name, body in profiles.items():
        rsn = re.search(r"^role_session_name = (\S+)$", body, re.M)
        arn = re.search(r"^role_arn = \S+:role/(\S+)$", body, re.M)
        if rsn and arn:
            m = re.fullmatch(r"nlw-d6-<PROOF_ID>-([a-z-]+)", rsn.group(1))
            if not m:
                v.append(f"profile {name} has a session name that is not proof-scoped")
                continue
            chained[name] = (arn.group(1), m.group(1))
    for where, body in all_code(text):
        for c in commands(body):
            for opt, allowed in (
                ("--sso-session", sessions),
                ("--role-session-name", {"operator"}),
            ):
                if opt in c.words:
                    value = c.words[c.words.index(opt) + 1]
                    m = re.fullmatch(r"\$\(session_name ([a-z-]+)\)", value)
                    if not m or m.group(1) not in allowed:
                        v.append(f"{where}: {opt} {value} does not come from session_name")
        for line in logical_lines(body):
            for role, who in re.findall(
                r"assumed-role/(nlw-staging-dataset-[a-z-]+)/\$\(session_name ([a-z-]+)\)", line
            ):
                profile = re.search(r"--profile (\S+)", line)
                if not profile or chained.get(profile.group(1)) != (role, who):
                    v.append(
                        f"{where}: {role}/{who} does not match the profile "
                        f"{profile.group(1) if profile else '?'}"
                    )
            if re.search(
                r"assumed-role/nlw-staging-dataset-(operator|audit-[a-z]+)/(?!\$\(session_name)",
                line,
            ):
                v.append(f"{where}: a role-session check that does not use session_name")
        if where not in ("lib.sh", "X08") and re.search(r"nlw-d6-[$<]", body):
            v.append(f"{where}: a session name built outside session_name")
    if "nlw-staging-operator" in text:
        v.append("the old operator session name is still used")
    return v


# --- F2: static scanning, defence in depth only -----------------------------------------------

FORBIDDEN_PYTHON = re.compile(
    r"\bboto3\b|\bbotocore\b|SigV4|\bsubprocess\b|os\.system|os\.popen|os\.exec|\bsocket\b"
    r"|amazonaws\.com/"
)


def _python_bodies(text: str) -> list[tuple[str, str]]:
    out = [(n, b) for n, b in FILE_BLOCK.findall(text) if n.endswith(".py")]
    for where, body in all_code(text):
        out += [(where, m) for m in re.findall(r"<<'PY'\n(.*?)\nPY\n", body, re.S)]
        out += [(where, m) for m in re.findall(r"python3? -c '(.*?)'", body, re.S)]
    return out


def static_call_violations(text: str) -> list[str]:
    """No AWS call through a shell variable or an absolute path, no network
    tool, and no SDK, SigV4 or subprocess use in any embedded Python. This is
    a scan of the reviewed text; it is not exhaustive."""
    v = []
    for where, body in all_code(text):
        aws_like = {
            name
            for name, value in assignments(body)
            if value.strip("'\"") == "aws" or value.strip("'\"").endswith("/aws")
        }
        for c in commands(body):
            var = re.fullmatch(r"\$\{?(\w+)\}?", c.name)
            if var and (var.group(1) in aws_like or any(w.startswith("--") for w in c.words[1:])):
                v.append(f"{where}: a command run through a variable ({c.name})")
            if "/" in c.name and c.name.rsplit("/", 1)[-1] == "aws":
                v.append(f"{where}: aws run by absolute path ({c.name})")
            if c.name in ("curl", "wget", "nc", "ncat") or (
                c.name == "openssl" and "s_client" in c.words
            ):
                v.append(f"{where}: a network client ({c.name})")
    for where, code in _python_bodies(text):
        if where == "probe.py":
            continue  # runs the application's own client inside the proven image
        found = FORBIDDEN_PYTHON.search(code)
        if found:
            v.append(f"{where}: embedded Python uses {found.group(0)}")
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


def test_human_roles_admit_only_identity_center_sessions() -> None:
    assert sso_trust_violations(load_templates()) == []


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
    assert [r[0] for r in rows] == [f"E{n}" for n in range(1, 16)]
    for _, _, options, recommendation in rows:
        assert options.strip() and recommendation.strip()
    assert "every decision below is open" in text
    assert "E11 to E15 are **required before D6**" in text
    decisions = {r[0]: r for r in rows}
    assert "**Identity Center only; required before D6.**" in decisions["E11"][3]
    assert "No long-term access key may be created or used" in decisions["E11"][3]
    assert "aws:MultiFactorAuthPresent" in decisions["E11"][3] and "attests" in decisions["E11"][3]
    assert "**no IAM policy here enforces MFA**" in decisions["E11"][3]
    assert "**Decided: a dedicated proof account is required.**" in decisions["E14"][3]
    assert "The shared-account mode is removed." in decisions["E14"][3]
    assert "bounded" not in decisions["E14"][3]
    assert "**Required; D6 is blocked until then.**" in decisions["E15"][3]
    assert "`git show`" in decisions["E15"][3]
    assert "rests on the reviewed pull request" in decisions["E15"][3]
    assert "**That separation holds only when different approved people" in decisions["E9"][3]
    assert "**The dedicated proof account only.**" in decisions["E5"][3]
    assert "explicitly approved the dedicated account" in text
    assert "and refuses any `nlw-*-dataset-*` role" in decisions["E8"][3]
    assert '[[ "$E11_IDENTITY" == identity-center ]]' in block(proof_text(), "P00-02")


def test_overclaims_are_corrected() -> None:
    review, prov, proof = REVIEW.read_text(), PROVISIONING.read_text(), proof_text()
    assert "audit key cannot be scheduled for deletion" not in review
    assert "Nobody may schedule this key's deletion" not in prov
    assert "cannot be scheduled\n  for deletion **without first changing its key policy**" in prov
    assert "no IMDS fallback even when IMDS is reachable" not in proof
    assert "it does **not** show what happens when a running" in proof
    assert "mid-run expiry with IMDS reachable is untested until P14-05 runs" in review
    # Round-2 overclaims: the round-1 rows now say what round 2 found and fixed.
    for marker in (
        "Round 2 (N1, N2) found",
        "Round 2 (N3) found",
        "Round 2 (N4) found",
        "**What the stub execution does not show.**",
        "**No AWS command was run.**",
    ):
        assert marker in review, marker
    assert "the provisioned state equals the templates" not in proof
    # Round 3: isolation is the AWS-side boundary; the stub run is defence in depth only.
    assert "pin every Allow and every Deny" not in review
    assert "**The stub run does not observe\n  every possible AWS call:**" in review
    assert "**Production isolation during D6 is an AWS-side control" not in review
    assert "**Production isolation during D6 is the dedicated proof account (E14).**" in review
    assert "**No policy in this package enforces MFA.**" in review
    assert "test_human_roles_require_mfa" not in review
    for marker in ("| **R13** |", "| **I5** |", "| **I6** |", "| **I7** |", "| **H1** P03-01"):
        assert marker in review, marker
    for row in ("| **F3** |", "| **M3** Identity Center", "| **N9** human lists"):
        line = next(x for x in review.splitlines() if x.startswith(row))
        assert "Superseded in round 3" in line, row
    # Round 4: the dedicated account is the blast-radius boundary; the policies
    # are additional controls; the stub is regression evidence only.
    assert "**What protects production.** AWS does" not in proof
    assert "This is the blast-radius boundary." in proof
    assert "**The shell and its tests are regression evidence only.**" in proof
    assert "It is not a security boundary and not an\n  exhaustive observation" in proof
    assert "**The\naccount is the blast-radius boundary:**" in prov
    assert "every IAM escalation path" not in prov + review + proof
    assert "an IAM escalation path, or this boundary itself is\n  refused by AWS" not in prov
    assert "MFA is enforced by Identity Center" not in prov + proof
    assert "Identity Center enforces MFA" not in proof
    assert "MFA operator" not in proof and "Operator MFA" not in proof
    assert "owner's existing" not in proof and "owner's account administration" not in proof
    assert "P01-02 re-checks effective permissions" not in review
    assert "exists in the reviewed commit" not in review
    assert "What it does **not** check:" in proof
    assert "**D6 is BLOCKED.**" in proof
    for marker in (
        "| **F1** the stub run can be evaded |",
        "| **F13** a dataset role as `ADMIN_ROLE` |",
        "| **R11** |",
        "| **R12** |",
    ):
        assert marker in review, marker
    assert "deployed policies and settings equal the rendered templates" in proof


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
ADMIN_ROLE_NAME = "aws-reserved/sso.amazonaws.com/AWSReservedSSO_NlwD6ProofAdmin_0123456789abcdef"


def sso_role(account: str, permission_set: str) -> str:
    return (
        f"arn:aws:iam::{account}:role/aws-reserved/sso.amazonaws.com/"
        f"AWSReservedSSO_{permission_set}_0123456789abcdef"
    )


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
        "ADMIN_ROLE": ADMIN_ROLE_NAME,
        "REC_KEY_ARN": f"{kms}/{'1' * 8}-1111-1111-1111-{'1' * 12}",
        "REC_AUDIT_KEY_ARN": f"{kms}/{'2' * 8}-2222-2222-2222-{'2' * 12}",
        "HUMANS": json.dumps([sso_role(DUMMY_ACCOUNT, f"Human{x}") for x in "AB"]),
        "PROOF_BOUNDARY_ARN": f"arn:aws:iam::{DUMMY_ACCOUNT}:policy/nlw-staging-d6-proof-boundary",
        "AUDIT_RETENTION_DAYS": "90",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    env.update(overrides)
    if overrides.get("DIRTY"):
        (repo / "docs" / "runbooks" / PROVISIONING.name).write_text("tampered")
    bash = overrides.pop("BASH_BIN", "bash")
    return subprocess.run(
        [bash, "-c", f'source "{lib}" && {script}'],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


# AWS's documented size limits, counted without whitespace.
SIZE_LIMITS = {"trust": 2048, "role": 10240, "managed": 6144, "bucket": 20480, "key": 32768}


def _limit_for(name: str) -> int | None:
    if name.startswith("trust-"):
        return SIZE_LIMITS["trust"]
    if name.startswith(("role-", "permission-set-")):
        return SIZE_LIMITS["role"]
    if name.startswith("proof-principal-"):
        return SIZE_LIMITS["managed"]
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


# --- N1/N2 --------------------------------------------------------------------------------------


def test_every_statement_has_a_canonical_effect_and_known_keys() -> None:
    assert effect_violations(load_templates()) == []


def test_every_deny_and_every_sid_is_pinned() -> None:
    assert deny_pin_violations(load_templates()) == []


def _insert_statement(text: str, template: str, statement: str) -> str:
    start = text.index(f"<!-- template: {template} -->")
    body = text.index("```json\n", start) + len("```json\n")
    anchor = text.index('{"Sid"', body)
    return text[:anchor] + statement + ",\n  " + text[anchor:]


TEXT_TEMPLATE_MUTATIONS = [
    (
        "lowercase allow grants kms:Decrypt to everyone",
        lambda t: _insert_statement(
            t,
            "dataset-kms-key-statements",
            '{"Sid": "X", "Effect": "allow", "Principal": {"AWS": "*"}, "Action": '
            '"kms:Decrypt", "Resource": "*"}',
        ),
    ),
    (
        "lowercase allow grants audit-bucket GetObject to everyone",
        lambda t: _insert_statement(
            t,
            "audit-bucket-policy",
            '{"Sid": "X", "Effect": "allow", "Principal": "*", "Action": "s3:GetObject", '
            '"Resource": "arn:aws:s3:::<AUDIT_BUCKET>/*"}',
        ),
    ),
    (
        "duplicate Effect keys hide an Allow",
        lambda t: _insert_statement(
            t,
            "dataset-kms-key-statements",
            '{"Sid": "X", "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "kms:Decrypt", '
            '"Resource": "*", "Effect": "Deny"}',
        ),
    ),
    (
        "duplicate Action key widens the API role",
        lambda t: t.replace(
            '{"Sid": "Encrypt", "Effect": "Allow",\n',
            '{"Sid": "Encrypt", "Effect": "Allow", "Action": "*", "Resource": "*",\n',
            1,
        ),
    ),
    (
        "missing Effect",
        lambda t: _insert_statement(
            t, "role-api", '{"Sid": "X", "Action": "s3:*", "Resource": "*"}'
        ),
    ),
]


@pytest.mark.parametrize(
    ("mutation",),
    [(m[1],) for m in TEXT_TEMPLATE_MUTATIONS],
    ids=[m[0] for m in TEXT_TEMPLATE_MUTATIONS],
)
def test_negative_control_noncanonical_statements_are_refused(
    mutation: Callable[[str], str],
) -> None:
    original = PROVISIONING.read_text()
    weakened = mutation(original)
    assert weakened != original
    try:
        t = load_templates(weakened)
    except ValueError:
        return  # refused while parsing
    found = (
        effect_violations(t)
        + deny_pin_violations(t)
        + principal_violations(t)
        + role_statement_violations(t)
    )
    assert found, "a non-canonical statement passed every check"


_FALSE = {"Bool": {"aws:SecureTransport": "maybe"}}
DENY_MUTATIONS = [
    (
        "NeverTouchAudit made inert",
        lambda t: _sid(t, "role-api", "NeverTouchAudit").update(Condition=_FALSE),
    ),
    (
        "NeverAssumeAnyOtherRole made inert",
        lambda t: _sid(t, "role-bootstrap", "NeverAssumeAnyOtherRole").update(Condition=_FALSE),
    ),
    (
        "NeverAlterAnyTrail made inert",
        lambda t: _sid(t, "role-operator", "NeverAlterAnyTrail").update(Condition=_FALSE),
    ),
    (
        "DenyMachineRoles made inert",
        lambda t: _sid(t, "trust-human", "DenyMachineRoles").update(Condition=_FALSE),
    ),
    (
        "DenyDeleteExceptOperator narrowed",
        lambda t: _sid(t, "dataset-bucket-policy", "DenyDeleteExceptOperator").update(
            Resource="arn:aws:s3:::<BUCKET>/nothing/*"
        ),
    ),
    (
        "DenyDeleteExceptOperator made inert",
        lambda t: _sid(t, "dataset-bucket-policy", "DenyDeleteExceptOperator").update(
            Condition=_FALSE
        ),
    ),
    (
        "DenyDatasetRoles made inert",
        lambda t: _sid(t, "audit-bucket-policy", "DenyDatasetRoles").update(Condition=_FALSE),
    ),
    (
        "DenyRecordDeletionExceptAuditAdmin exempts every role",
        lambda t: _sid(t, "audit-bucket-policy", "DenyRecordDeletionExceptAuditAdmin").update(
            Condition={"ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/*"}}
        ),
    ),
    (
        "DenyBucketConfigExceptAuditAdmin exempts every role",
        lambda t: _sid(t, "audit-bucket-policy", "DenyBucketConfigExceptAuditAdmin").update(
            Condition={"ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/*"}}
        ),
    ),
    (
        "DenyBucketConfigExceptAdmin exempts every role",
        lambda t: _sid(t, "dataset-bucket-policy", "DenyBucketConfigExceptAdmin").update(
            Condition={"ArnNotEquals": {"aws:PrincipalArn": ["arn:aws:iam::<ACCOUNT>:role/*"]}}
        ),
    ),
    (
        "DenyOutsideAccount removed",
        lambda t: _drop_sid(t, "dataset-bucket-policy", "DenyOutsideAccount"),
    ),
    (
        "NeverDataPlane principal changed",
        lambda t: _sid(t, "role-bootstrap", "NeverDataPlane").update(Resource="arn:aws:s3:::none"),
    ),
    (
        "a Deny turned into an Allow",
        lambda t: _sid(t, "role-ingest", "NeverOtherEnvironment").update(Effect="Allow"),
    ),
]


@pytest.mark.parametrize(
    ("mutation",), [(m[1],) for m in DENY_MUTATIONS], ids=[m[0] for m in DENY_MUTATIONS]
)
def test_negative_control_a_weakened_deny_is_detected(
    mutation: Callable[[Templates], None],
) -> None:
    weakened = copy.deepcopy(load_templates())
    mutation(weakened)
    assert deny_pin_violations(weakened)


# --- N3/N4: executing the procedure against the stub `aws` --------------------------------------


@needs_harness
@pytest.mark.parametrize("bash", AVAILABLE_BASHES)
def test_executing_every_step_reaches_only_staging_and_every_call(
    tmp_path: Path, bash: str
) -> None:
    run = run_with_stub(tmp_path, proof_text(), bash)
    assert len(run.calls) > 250
    assert stub_violations(run, proof_text()) == []
    assert not any(
        kind == "sudo-skipped" and not detail.startswith("python3") for kind, detail in run.other
    )


def _after_source(text: str, step: str, line: str) -> str:
    start, _ = _block_containing(text, step)
    first = text.index("\n", start) + 1
    return text[:first] + line + "\n" + text[first:]


HARNESS_MUTATIONS = [
    (
        "command substitution",
        lambda t: _after_source(
            t,
            "P03-06",
            "aws s3api put-object --profile nlw-proof-admin "
            '--bucket "nlw-$(echo prod)uction-datasets-x" --key k --body f',
        ),
    ),
    (
        "indirect variable",
        lambda t: _after_source(
            t,
            "P03-06",
            "T=OTHER_BUCKET; aws s3api put-object --profile nlw-proof-admin "
            '--bucket "${!T}" --key k --body f',
        ),
    ),
    (
        "case conversion",
        lambda t: _after_source(
            t,
            "P03-06",
            "E=PRODUCTION; aws s3api put-object --profile nlw-proof-admin "
            '--bucket "nlw-${E,,}-datasets-x" --key k --body f',
        ),
    ),
    (
        "ledger value",
        lambda t: _after_source(
            _after_source(t, "P02-01", 'record REC_TARGET "nlw-production-datasets-x"'),
            "P03-06",
            'aws s3api delete-bucket --profile nlw-proof-admin --bucket "$REC_TARGET"',
        ),
    ),
    (
        "helper function",
        lambda t: _after_source(
            t.replace(
                "note() { printf",
                'tidy() { aws s3api delete-bucket --bucket "$OTHER_BUCKET"; }\nnote() { printf',
                1,
            ),
            "P03-06",
            "tidy",
        ),
    ),
    (
        "timeout wrapper",
        lambda t: _after_source(
            t, "P02-01", 'timeout 60 aws s3api delete-bucket --bucket "$OTHER_BUCKET"'
        ),
    ),
    (
        "xargs wrapper",
        lambda t: _after_source(
            t, "P02-01", 'echo "$OTHER_BUCKET" | xargs -I{} aws s3api delete-bucket --bucket {}'
        ),
    ),
    (
        "bash -c string",
        lambda t: _after_source(
            t, "P02-01", "bash -c 'aws s3api delete-bucket --bucket nlw-production-x'"
        ),
    ),
    (
        "nohup wrapper",
        lambda t: _after_source(
            t, "P02-01", 'nohup aws s3api delete-bucket --bucket "$OTHER_BUCKET"'
        ),
    ),
    (
        "sudo -u wrapper",
        lambda t: _after_source(
            t, "P02-01", 'sudo -u nobody aws s3api delete-bucket --bucket "$OTHER_BUCKET"'
        ),
    ),
    (
        "high-level aws s3 cp",
        lambda t: _after_source(
            t, "P05-01", 'expect_denied aws s3 cp f "s3://$BUCKET/elsewhere/x"'
        ),
    ),
]


@needs_harness
@pytest.mark.parametrize(
    ("mutation",), [(m[1],) for m in HARNESS_MUTATIONS], ids=[m[0] for m in HARNESS_MUTATIONS]
)
def test_negative_control_executed_production_or_wrapped_calls_are_detected(
    tmp_path: Path, mutation: Callable[[str], str]
) -> None:
    text = proof_text()
    weakened = mutation(text)
    assert weakened != text
    run = run_with_stub(tmp_path, weakened, AVAILABLE_BASHES[0])
    assert stub_violations(run, weakened), "the executed procedure reached production unnoticed"


def test_no_aws_call_hides_behind_a_wrapper() -> None:
    assert wrapper_violations(proof_text()) == []


WRAPPER_TEXT_MUTATIONS = [
    ("timeout", "timeout 60 aws s3api delete-bucket --bucket b"),
    ("xargs", "echo b | xargs aws s3api delete-bucket --bucket"),
    ("nohup", "nohup aws s3api delete-bucket --bucket b"),
    ("sudo -u", "sudo -u nobody aws s3api delete-bucket --bucket b"),
    ("bash -c", "bash -c 'aws s3api delete-bucket --bucket b'"),
    ("env", "env X=1 aws s3api delete-bucket --bucket b"),
]


@pytest.mark.parametrize(
    ("line",), [(m[1],) for m in WRAPPER_TEXT_MUTATIONS], ids=[m[0] for m in WRAPPER_TEXT_MUTATIONS]
)
def test_negative_control_wrapped_aws_is_detected_statically(line: str) -> None:
    assert wrapper_violations(_after_source(proof_text(), "P02-01", line))


# --- N5 ------------------------------------------------------------------------------------------


def test_human_credentials_have_a_defined_source_lifecycle_and_cleanup() -> None:
    assert credential_source_violations(proof_text()) == []


CREDENTIAL_MUTATIONS = [
    (
        "a key in the workstation config",
        lambda t: t.replace(
            "[profile nlw-proof-human-audit-admin]\n",
            "[profile nlw-proof-human-audit-admin]\naws_secret_access_key = x\n",
            1,
        ),
    ),
    (
        "a credential_process in the workstation config",
        lambda t: t.replace(
            "[profile nlw-proof-human-audit-admin]\n",
            "[profile nlw-proof-human-audit-admin]\ncredential_process = /bin/cat k\n",
            1,
        ),
    ),
    (
        "a chained profile without a run-scoped session name",
        lambda t: t.replace(
            "role_session_name = nlw-d6-<PROOF_ID>-audit-reader", "role_session_name = reader", 1
        ),
    ),
    (
        "a step creates an access key",
        lambda t: _after_source(
            t, "P01-01", "aws iam create-access-key --profile nlw-proof-admin --user-name x"
        ),
    ),
    (
        "P00-02 accepts IAM users",
        lambda t: t.replace(
            '[[ "$E11_IDENTITY" == identity-center ]]', '[[ -n "$E11_IDENTITY" ]]', 1
        ),
    ),
    (
        "X08 deletes cached sessions by age",
        lambda t: t.replace(
            'python3 - "$HOME/.aws" "$ACCOUNT" "$PROOF_ID" <<\'PY\'',
            'find "$HOME/.aws/cli/cache" -newer "$PROOF_DIR/started" -delete\npython3 - '
            '"$HOME/.aws" "$ACCOUNT" "$PROOF_ID" <<\'PY\'',
            1,
        ),
    ),
    (
        "X08 logs out every SSO session",
        lambda t: t.replace(
            'rm -f "$PROOF_DIR/proof-key"', 'aws sso logout\nrm -f "$PROOF_DIR/proof-key"', 1
        ),
    ),
    (
        "recovery no longer requires X08",
        lambda t: t.replace(
            "4. **Always, whatever else happens:** run X08", "4. Optionally run X08", 1
        ),
    ),
]


@pytest.mark.parametrize(
    ("mutation",), [(m[1],) for m in CREDENTIAL_MUTATIONS], ids=[m[0] for m in CREDENTIAL_MUTATIONS]
)
def test_negative_control_credential_handling_weakening_is_detected(
    mutation: Callable[[str], str],
) -> None:
    text = proof_text()
    weakened = mutation(text)
    assert weakened != text
    assert credential_source_violations(weakened)


def _heredoc_python(body: str) -> str:
    return body.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]


def test_x08_removes_only_this_runs_cached_tokens_and_sessions(tmp_path: Path) -> None:
    aws = tmp_path / "aws"
    cli, sso = aws / "cli" / "cache", aws / "sso" / "cache"
    cli.mkdir(parents=True)
    sso.mkdir(parents=True)
    run, other_run = "d6-20261011-a1b2c3", "d6-20261010-ffffff"

    def session(name: str, arn: str) -> None:
        (cli / name).write_text(
            json.dumps({"Credentials": {"SecretAccessKey": "s"}, "AssumedRoleUser": {"Arn": arn}})
        )

    base = f"arn:aws:sts::{DUMMY_ACCOUNT}:assumed-role"
    session("ours-op.json", f"{base}/nlw-staging-dataset-operator/nlw-d6-{run}-operator")
    session(
        "ours-reader.json", f"{base}/nlw-staging-dataset-audit-reader/nlw-d6-{run}-audit-reader"
    )
    session("other-run.json", f"{base}/nlw-staging-dataset-operator/nlw-d6-{other_run}-operator")
    session("other-session.json", f"{base}/Admin/alice")
    session("other-account.json", f"arn:aws:sts::999999999999:assumed-role/x/nlw-d6-{run}-operator")
    session("suffix-trick.json", f"{base}/nlw-staging-dataset-operator/nlw-d6-{run}-operator-extra")
    (cli / "junk.json").write_text("not json")
    import hashlib

    for who, run_id in (("operator", run), ("audit", run), ("operator", other_run)):
        name = hashlib.sha1(f"nlw-d6-{run_id}-{who}".encode()).hexdigest() + ".json"
        (sso / name).write_text(json.dumps({"accessToken": "t"}))
    (sso / "unrelated.json").write_text(json.dumps({"accessToken": "t"}))
    script = tmp_path / "x08.py"
    script.write_text(_heredoc_python(block(proof_text(), "X08")))
    subprocess.run(
        [sys.executable, str(script), str(aws), DUMMY_ACCOUNT, run], check=True, capture_output=True
    )
    assert sorted(p.name for p in cli.iterdir()) == [
        "junk.json",
        "other-account.json",
        "other-run.json",
        "other-session.json",
        "suffix-trick.json",
    ]
    other_token = hashlib.sha1(f"nlw-d6-{other_run}-operator".encode()).hexdigest() + ".json"
    assert sorted(p.name for p in sso.iterdir()) == sorted([other_token, "unrelated.json"])


def test_negative_control_cross_run_cache_deletion_is_detected(tmp_path: Path) -> None:
    """X08 widened to every run's sessions must be caught statically and,
    executed, would delete another run's cache."""
    text = proof_text()
    widened = text.replace("re.escape(proof)", "r'[^-]+-[^-]+-[^-]+'", 1)
    assert widened != text and credential_source_violations(widened)


# --- N6/N7/N8/N10 --------------------------------------------------------------------------------


def test_nothing_touches_a_new_bucket_before_it_is_proven_new() -> None:
    assert bucket_creation_strict_violations(proof_text()) == []


def test_expected_denied_writes_use_parsed_keys_inside_the_prefixes() -> None:
    assert denied_write_strict_violations(proof_text()) == []


def test_open_uploads_are_recovered_and_aborted_by_exact_ids() -> None:
    assert multipart_recovery_violations(proof_text()) == []


def test_an_unrecorded_bucket_of_this_run_is_recovered_safely() -> None:
    assert orphan_bucket_violations(proof_text()) == []


STATIC_MUTATIONS = [
    (
        "N6 configuration before the pristine checks",
        lambda t: t.replace(
            'aws s3api create-bucket --profile nlw-proof-admin --bucket "$BUCKET" '
            "--object-ownership BucketOwnerEnforced\n",
            'aws s3api create-bucket --profile nlw-proof-admin --bucket "$BUCKET" '
            "--object-ownership BucketOwnerEnforced\n"
            'aws s3api delete-bucket-policy --profile nlw-proof-admin --bucket "$BUCKET"\n',
            1,
        ),
        bucket_creation_strict_violations,
    ),
    (
        "N7 --key= form outside the prefixes",
        lambda t: _after_source(
            t,
            "P05-01",
            'expect_denied aws s3api put-object --profile proof-api --bucket "$BUCKET" '
            "--key=elsewhere/x --body f",
        ),
        denied_write_strict_violations,
    ),
    (
        "N7 high-level aws s3 cp",
        lambda t: _after_source(
            t, "P05-01", 'expect_denied aws s3 cp f "s3://$BUCKET/elsewhere/x"'
        ),
        denied_write_strict_violations,
    ),
    (
        "N7 delete-objects outside the prefixes",
        lambda t: _after_source(
            t,
            "P05-01",
            'expect_denied aws s3api delete-objects --profile proof-api --bucket "$BUCKET" '
            "--delete 'Objects=[{Key=elsewhere/x}]'",
        ),
        denied_write_strict_violations,
    ),
    (
        "N8 open uploads not listed",
        lambda t: t.replace(
            "aws s3api list-multipart-uploads --profile nlw-proof-operator --bucket "
            '"${REC_BUCKET}" \\\n    --prefix "versions/$ws/"',
            'true \\\n    --prefix "versions/$ws/"',
            1,
        ),
        multipart_recovery_violations,
    ),
    (
        "N8 old uploads accepted",
        lambda t: t.replace('[[ "$initiated" > "$started" ]] || stop S8', "true", 1),
        multipart_recovery_violations,
    ),
    (
        "N8 recovered uploads not aborted",
        lambda t: t.replace(
            '--key "${!v}" --upload-id "${!up}"', '--key "${!up}" --upload-id "${!up}"', 1
        ),
        multipart_recovery_violations,
    ),
    (
        "N10 orphan without the suffix check",
        lambda t: t.replace('[[ "$name" == *"$SUFFIX" ]] || stop S8', "true", 1),
        orphan_bucket_violations,
    ),
    (
        "N10 absence no longer journalled",
        lambda t: t.replace('note "absence confirmed: ${BUCKET/"$ACCOUNT"/<ACCOUNT>}"\n', "", 1),
        bucket_creation_strict_violations,
    ),
    (
        "N9 human lists not validated",
        lambda t: t.replace(
            'validate_principals sso "$AUDIT_READER_HUMANS_JSON" '
            '"$OPERATOR_HUMANS_JSON"\nmake_role',
            "make_role",
            1,
        ),
        human_and_drift_violations,
    ),
    (
        "N9 key policies no longer compared",
        lambda t: t.replace('same "dataset key policy"', 'true "dataset key policy"', 1),
        human_and_drift_violations,
    ),
    (
        "N11 ERR trap inherited again",
        lambda t: t.replace(
            "(seen on bash 3.2).\nset -euo pipefail\n",
            "(seen on bash 3.2).\nset -Eeuo pipefail\n",
            1,
        ),
        trap_violations,
    ),
    (
        "N11 rotator not stopped",
        lambda t: t.replace(
            'on_exit "kill $ROTATOR 2> /dev/null; wait $ROTATOR 2> /dev/null"', "true", 1
        ),
        trap_violations,
    ),
    (
        "N12 P00-01 runs a check",
        lambda t: t.replace(
            'export REVIEWED_COMMIT="<the full commit id the owner approved for this run>"\n',
            'export REVIEWED_COMMIT="<the full commit id the owner approved for this '
            'run>"\ngit status\n',
            1,
        ),
        consistency_violations,
    ),
    (
        "N12 stop table forgets P03-06",
        lambda t: t.replace("| P02, P03-06, P03-07 |", "| P02 |", 1),
        consistency_violations,
    ),
    (
        "N12 ADMIN_ROLE form not checked",
        lambda t: t.replace('"$ADMIN_ROLE" != arn:*', '"$ADMIN_ROLE" != none', 1),
        consistency_violations,
    ),
    (
        "N12 identity type not verified",
        lambda t: t.replace(
            '[[ "$arn" == "arn:aws:sts::${ACCOUNT}:assumed-role/AWSReservedSSO_${2}_"* ]]',
            "true",
            1,
        ),
        consistency_violations,
    ),
]


@pytest.mark.parametrize(
    ("mutation", "check"),
    [(m[1], m[2]) for m in STATIC_MUTATIONS],
    ids=[m[0] for m in STATIC_MUTATIONS],
)
def test_negative_control_n_findings_are_detected(
    mutation: Callable[[str], str], check: Callable[[str], list[str]]
) -> None:
    text = proof_text()
    weakened = mutation(text)
    assert weakened != text, "the mutation did not apply"
    assert check(weakened)


# --- N9: human principal validation, rendering and drift comparison -----------------------------


def test_human_lists_and_drift_comparison_are_in_place() -> None:
    assert human_and_drift_violations(proof_text()) == []


@needs_bash_and_git
@pytest.mark.parametrize(
    ("kind", "people", "excluded", "ok"),
    [
        ("sso", ["SSO:Operator"], [], True),
        ("sso", ["SSO:Operator", "SSO:Second"], [], True),
        (
            "sso",
            [
                f"arn:aws:iam::{DUMMY_ACCOUNT}:role/aws-reserved/sso.amazonaws.com/us-east-1/"
                "AWSReservedSSO_Operator_0123456789abcdef"
            ],
            [],
            True,
        ),
        ("sso", ["*"], [], False),
        ("sso", [f"arn:aws:iam::{DUMMY_ACCOUNT}:root"], [], False),
        ("sso", [f"arn:aws:iam::{DUMMY_ACCOUNT}:user/alice"], [], False),
        (
            "sso",
            [
                "arn:aws:iam::999999999999:role/aws-reserved/sso.amazonaws.com/"
                "AWSReservedSSO_Operator_0123456789abcdef"
            ],
            [],
            False,
        ),
        ("sso", ["SSO:Operator\n"], [], False),
        (
            "sso",
            [f"arn:aws:iam::{DUMMY_ACCOUNT}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_*"],
            [],
            False,
        ),
        ("sso", ["SSO:Operator", "SSO:Operator"], [], False),
        ("sso", ["SSO:Operator"], ["SSO:Operator"], False),
        ("sso", [], [], False),
        ("sso", "not-a-list", [], False),
        ("iam", [f"arn:aws:iam::{DUMMY_ACCOUNT}:user/team/alice"], [], True),
        ("iam", [f"arn:aws:iam::{DUMMY_ACCOUNT}:role/Admin"], [], True),
        ("iam", [f"arn:aws:iam::{DUMMY_ACCOUNT}:user/alice\n"], [], False),
        ("iam", [], [], False),
        ("iam", ["*"], [], False),
    ],
    ids=[
        "sso role",
        "two sso roles",
        "sso role with region path",
        "wildcard",
        "root",
        "IAM user",
        "other account",
        "trailing newline",
        "wildcard role",
        "duplicate",
        "shared with the operator",
        "empty",
        "not a list",
        "iam user with path",
        "iam role",
        "iam trailing newline",
        "iam empty (E12 must name principals)",
        "iam wildcard",
    ],
)
def test_negative_control_principal_lists_are_validated(
    tmp_path: Path, kind: str, people: Any, excluded: list[str], ok: bool
) -> None:
    def expand(x: Any) -> Any:
        if isinstance(x, list):
            return [expand(i) for i in x]
        if isinstance(x, str) and x.startswith("SSO:"):
            name = x[4:].rstrip("\n")
            return sso_role(DUMMY_ACCOUNT, name) + ("\n" if x.endswith("\n") else "")
        return x

    raw = people if isinstance(people, str) else json.dumps(expand(people))
    script = (
        f"validate_principals {kind} {shlex.quote(raw)} {shlex.quote(json.dumps(expand(excluded)))}"
    )
    result = _lib_run(tmp_path, script)
    assert (result.returncode == 0) is ok, result.stderr
    if not ok:
        assert "STOP S9: a principal list is invalid" in result.stderr


@needs_bash_and_git
@pytest.mark.parametrize(
    "humans",
    [
        '["*"]',
        f'["arn:aws:iam::{DUMMY_ACCOUNT}:root"]',
        f'["arn:aws:iam::{DUMMY_ACCOUNT}:user/a\\"]}}, {{\\"Sid\\": \\"x"]',
        json.dumps([sso_role(DUMMY_ACCOUNT, "Operator") + "\n"]),
        json.dumps([f"arn:aws:iam::{DUMMY_ACCOUNT}:user/alice"]),
        "[1]",
    ],
    ids=["wildcard", "root", "injection", "not strings", "trailing newline", "IAM user"],
)
def test_negative_control_render_refuses_unsafe_human_principals(
    tmp_path: Path, humans: str
) -> None:
    result = _lib_run(tmp_path, "render trust-human", HUMANS=humans)
    assert result.returncode != 0 and result.stdout == ""


def test_normalized_policies_compare_equal_across_aws_representations(tmp_path: Path) -> None:
    script = tmp_path / "normalize.py"
    script.write_text(dict(FILE_BLOCK.findall(proof_text()))["normalize-policy.py"])

    def canon(payload: str) -> str:
        return subprocess.run(
            [sys.executable, str(script)], input=payload, capture_output=True, text=True, check=True
        ).stdout

    rendered = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "B", "Effect": "Deny", "Action": ["s3:*"], "Resource": "*"},
            {
                "Sid": "A",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": ["x"],
            },
        ],
    }
    deployed = {
        "Statement": [
            {
                "Resource": "x",
                "Action": ["s3:PutObject", "s3:GetObject"],
                "Effect": "Allow",
                "Sid": "A",
            },
            {"Sid": "B", "Effect": "Deny", "Action": "s3:*", "Resource": ["*"]},
        ],
        "Version": "2012-10-17",
    }
    assert canon(json.dumps(rendered)) == canon(json.dumps(deployed))
    assert canon(json.dumps(json.dumps(deployed))) == canon(
        json.dumps(rendered)
    )  # KMS returns a string
    drifted: dict[str, Any] = copy.deepcopy(deployed)
    drifted["Statement"][1]["Effect"] = "Allow"
    assert canon(json.dumps(rendered)) != canon(json.dumps(drifted))


# --- N11/N12: traps, background processes and step binding on every available bash -------------


@needs_bash_and_git
@pytest.mark.parametrize("bash", AVAILABLE_BASHES)
def test_a_guarded_failing_substitution_does_not_record_s10(tmp_path: Path, bash: str) -> None:
    result = _lib_run(
        tmp_path, '[[ "$(printf x | grep -c ok)" == 1 ]] || stop S9 "guarded"', BASH_BIN=bash
    )
    assert "STOP S9: guarded" in result.stderr and "S10" not in result.stderr
    assert "S10" not in (tmp_path / "proof" / "journal.log").read_text()


@needs_bash_and_git
@pytest.mark.parametrize("bash", AVAILABLE_BASHES)
def test_a_failure_inside_a_function_records_s10_with_the_command(
    tmp_path: Path, bash: str
) -> None:
    result = _lib_run(tmp_path, 'f() { python3 -c "import sys; sys.exit(3)"; }; f', BASH_BIN=bash)
    assert result.returncode != 0 and "STOP S10: command failed: python3" in result.stderr


@needs_bash_and_git
@pytest.mark.parametrize("bash", AVAILABLE_BASHES)
def test_background_processes_are_stopped_on_every_exit(tmp_path: Path, bash: str) -> None:
    pid_file = tmp_path / "pid"
    script = (
        f"{{ ( while true; do sleep 1; done ) & }} ; R=$!; echo $R > {shlex.quote(str(pid_file))}; "
        'on_exit "kill $R 2> /dev/null; wait $R 2> /dev/null"; stop S9 "early stop"'
    )
    result = _lib_run(tmp_path, script, BASH_BIN=bash)
    assert "STOP S9: early stop" in result.stderr
    pid = int(pid_file.read_text())
    alive = subprocess.run(["kill", "-0", str(pid)], capture_output=True).returncode == 0
    assert not alive, "the background process outlived the step"


@needs_bash_and_git
def test_negative_control_admin_role_must_be_a_name_not_an_arn(tmp_path: Path) -> None:
    result = _lib_run(tmp_path, "true", ADMIN_ROLE=f"arn:aws:iam::{DUMMY_ACCOUNT}:role/Admin")
    assert result.returncode != 0 and "STOP S1: ADMIN_ROLE must be the role name" in result.stderr


@needs_harness
def test_negative_control_run_step_refuses_a_modified_step(tmp_path: Path) -> None:
    proof_dir = tmp_path / "p"
    (proof_dir / "steps").mkdir(parents=True)
    files = dict(FILE_BLOCK.findall(proof_text()))
    (proof_dir / "run-step").write_text(files["run-step"])
    (proof_dir / "steps" / "P01-01.sh").write_text("echo reviewed\n")
    digest = __import__("hashlib").sha256(b"echo reviewed\n").hexdigest()
    (proof_dir / "manifest.json").write_text(json.dumps({"steps/P01-01.sh": digest}))
    env = {"PATH": os.environ["PATH"], "PROOF_DIR": str(proof_dir)}
    ok = subprocess.run(
        ["bash", str(proof_dir / "run-step"), "P01-01"], capture_output=True, text=True, env=env
    )
    assert ok.returncode == 0 and ok.stdout == "reviewed\n"
    (proof_dir / "steps" / "P01-01.sh").write_text("echo tampered\n")
    bad = subprocess.run(
        ["bash", str(proof_dir / "run-step"), "P01-01"], capture_output=True, text=True, env=env
    )
    assert (
        bad.returncode != 0
        and "differs from the reviewed commit" in bad.stderr
        and "tampered" not in bad.stdout
    )


def test_trap_model_and_execution_instructions_are_consistent() -> None:
    assert trap_violations(proof_text()) == []
    assert consistency_violations(proof_text()) == []


# --- round 3: the AWS-side boundary, the gate, and fail-closed verification -------------------


def test_d6_is_blocked_until_an_independent_verification_record_exists() -> None:
    assert gate_violations(proof_text()) == []


def test_every_aws_change_is_a_reviewed_operation() -> None:
    assert mutation_allowlist_violations(proof_text()) == []


def test_the_proof_principal_boundary_narrows_only() -> None:
    assert boundary_violations(load_templates()) == []


ROUND3_PROOF_MUTATIONS = [
    (
        "attach AdministratorAccess",
        lambda t: _after_source(
            t,
            "P03-09",
            "aws iam attach-role-policy --profile nlw-proof-admin --role-name "
            "nlw-staging-dataset-api --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        ),
        mutation_allowlist_violations,
    ),
    (
        "set an unexpected permissions boundary",
        lambda t: _after_source(
            t,
            "P03-09",
            "aws iam put-role-permissions-boundary --profile nlw-proof-admin "
            "--role-name nlw-staging-dataset-api --permissions-boundary arn:aws:iam::aws:policy/x",
        ),
        mutation_allowlist_violations,
    ),
    (
        "create a KMS grant",
        lambda t: _after_source(
            t,
            "P03-09",
            'aws kms create-grant --profile nlw-proof-admin --key-id "$REC_KEY_ARN" '
            "--grantee-principal x --operations Decrypt",
        ),
        mutation_allowlist_violations,
    ),
    (
        "create a role without the boundary",
        lambda t: t.replace('    --permissions-boundary "$PROOF_BOUNDARY_ARN" \\\n', "", 1),
        mutation_allowlist_violations,
    ),
    (
        "an inline policy from a hand-written document",
        lambda t: _after_source(
            t,
            "P03-09",
            "aws iam put-role-policy --profile nlw-proof-admin --role-name "
            "nlw-staging-dataset-api --policy-name x --policy-document file:///tmp/x.json",
        ),
        mutation_allowlist_violations,
    ),
    (
        "P03-11 stops checking attached policies",
        lambda t: t.replace(
            '  verify_role_shape "nlw-staging-dataset-$r" "nlw-dataset-$r"\n', "", 1
        ),
        human_and_drift_violations,
    ),
    (
        "P03-11 stops checking KMS grants",
        lambda t: t.replace('verify_no_grants "$REC_KEY_ARN" nlw-proof-admin\n', "", 1),
        human_and_drift_violations,
    ),
    (
        "P03-11 stops checking the audit bucket's controls",
        lambda t: t.replace(
            'verify_bucket_controls "$AUDIT_BUCKET" nlw-proof-audit-admin\n', "", 1
        ),
        human_and_drift_violations,
    ),
    (
        "E12 simulation accepts an empty result again",
        lambda t: t.replace('validate_principals iam "$E12_MUST_NOT_PASS_JSON"\n', "", 1),
        human_and_drift_violations,
    ),
    (
        "an expected-denied write to the audit bucket",
        lambda t: _after_source(
            t,
            "P05-01",
            "expect_denied aws s3api put-object --profile proof-api "
            '--bucket "$AUDIT_BUCKET" --key "versions/$REC_PROOF_WS/x" --body f',
        ),
        denied_write_strict_violations,
    ),
    (
        "the D6-blocked notice removed",
        lambda t: t.replace("**D6 is BLOCKED.**", "D6 may start.", 1),
        gate_violations,
    ),
    (
        "the gate accepts the operator as verifier",
        lambda t: t.replace(' and gate.get("verified_by") != env["OPERATOR_NAME"]', "", 1),
        gate_violations,
    ),
    (
        "P01-02 stops checking the boundary document",
        lambda t: t.replace('same "proof boundary"', 'true "proof boundary"', 1),
        gate_violations,
    ),
    (
        "lib.sh accepts a dataset role as ADMIN_ROLE",
        lambda t: t.replace('[[ "${ADMIN_ROLE##*/}" != nlw-*-dataset-* ]]', "true", 1),
        consistency_violations,
    ),
]


@pytest.mark.parametrize(
    ("mutation", "check"),
    [(m[1], m[2]) for m in ROUND3_PROOF_MUTATIONS],
    ids=[m[0] for m in ROUND3_PROOF_MUTATIONS],
)
def test_negative_control_round3_procedure_weakening_is_detected(
    mutation: Callable[[str], str], check: Callable[[str], list[str]]
) -> None:
    text = proof_text()
    weakened = mutation(text)
    assert weakened != text, "the mutation did not apply"
    assert check(weakened)


ROUND3_TEMPLATE_MUTATIONS = [
    (
        "dataset lifecycle expires versions",
        lambda t: t["dataset-bucket-lifecycle"]["Rules"][0].update(
            Expiration={"Days": 1}, NoncurrentVersionExpiration={"NoncurrentDays": 1}
        ),
        deny_pin_violations,
    ),
    (
        "dataset lifecycle scope widened",
        lambda t: t["dataset-bucket-lifecycle"]["Rules"][0].update(Filter={"Prefix": ""}),
        deny_pin_violations,
    ),
    (
        "audit lifecycle shortened",
        lambda t: t["audit-bucket-lifecycle"]["Rules"][0].update(
            NoncurrentVersionExpiration={"NoncurrentDays": 0}
        ),
        deny_pin_violations,
    ),
    (
        "event selectors narrowed",
        lambda t: t["trail-advanced-event-selectors"][0]["FieldSelectors"].append(
            {"Field": "readOnly", "Equals": ["false"]}
        ),
        deny_pin_violations,
    ),
    (
        "deny policy allows escalation",
        lambda t: _sid(t, "proof-principal-denies", "NeverEscalate")["Action"].remove(
            "iam:AttachRolePolicy"
        ),
        boundary_violations,
    ),
    (
        "boundary no longer forced onto created roles",
        lambda t: _drop_sid(t, "proof-principal-boundary", "CreatedRolesCarryThisBoundary"),
        boundary_violations,
    ),
    (
        "deny policy production deny narrowed",
        lambda t: _sid(t, "proof-principal-denies", "NeverOtherEnvironmentNames").update(
            Resource=["arn:aws:s3:::nlw-<OTHER_ENV>-*"]
        ),
        deny_pin_violations,
    ),
    (
        "human trust admits IAM users again",
        lambda t: _drop_sid(t, "trust-human", "DenyAnythingButIdentityCenter"),
        sso_trust_violations,
    ),
]


@pytest.mark.parametrize(
    ("mutation", "check"),
    [(m[1], m[2]) for m in ROUND3_TEMPLATE_MUTATIONS],
    ids=[m[0] for m in ROUND3_TEMPLATE_MUTATIONS],
)
def test_negative_control_round3_template_weakening_is_detected(
    mutation: Callable[[Templates], None], check: Callable[[Templates], list[str]]
) -> None:
    weakened = copy.deepcopy(load_templates())
    mutation(weakened)
    assert check(weakened)


# A fake `aws` for exercising lib.sh's verification helpers: the answer to an
# operation comes from FAKE_<OPERATION> (and its exit code from
# FAKE_<OPERATION>_RC), so each test states exactly what AWS "returned".
FAKE_AWS = r"""#!/bin/bash
op=""; svc=""
for a in "$@"; do
  case "$a" in --*) continue ;; esac
  if [[ -z "$svc" ]]; then svc="$a"; elif [[ -z "$op" ]]; then op="$a"; break; fi
done
var="FAKE_$(printf '%s' "$op" | tr 'a-z-' 'A-Z_')"
rc_var="${var}_RC"
[[ -n "${!var+x}" ]] && printf '%s\n' "${!var}"
exit "${!rc_var:-0}"
"""


def _fake_run(tmp_path: Path, script: str, **answers: str) -> subprocess.CompletedProcess[str]:
    fake = tmp_path / "fake"
    fake.mkdir(exist_ok=True)
    (fake / "aws").write_text(FAKE_AWS)
    (fake / "aws").chmod(0o755)
    (tmp_path / "proof").mkdir(exist_ok=True)
    (tmp_path / "proof" / "normalize-policy.py").write_text(
        dict(FILE_BLOCK.findall(proof_text()))["normalize-policy.py"]
    )
    return _lib_run(tmp_path, script, PATH=f"{fake}:{os.environ['PATH']}", **answers)


BOUNDARY = f"arn:aws:iam::{DUMMY_ACCOUNT}:policy/nlw-staging-d6-proof-boundary"
GOOD_ROLE = {
    "FAKE_LIST_ROLE_POLICIES": '["nlw-dataset-api"]',
    "FAKE_LIST_ATTACHED_ROLE_POLICIES": "[]",
    "FAKE_GET_ROLE": BOUNDARY,
}


@needs_bash_and_git
@pytest.mark.parametrize(
    ("answers", "expected"),
    [
        ({}, None),
        (
            {"FAKE_LIST_ATTACHED_ROLE_POLICIES": '["arn:aws:iam::aws:policy/AdministratorAccess"]'},
            "has attached managed policies",
        ),
        (
            {"FAKE_GET_ROLE": "arn:aws:iam::aws:policy/PowerUserAccess"},
            "does not carry exactly the proof boundary",
        ),
        ({"FAKE_GET_ROLE": "None"}, "does not carry exactly the proof boundary"),
        (
            {"FAKE_LIST_ROLE_POLICIES": '["nlw-dataset-api", "extra"]'},
            "has inline policies other than",
        ),
        ({"FAKE_LIST_ATTACHED_ROLE_POLICIES_RC": "254"}, "cannot list the managed policies"),
    ],
    ids=[
        "clean role",
        "AdministratorAccess attached",
        "unexpected boundary",
        "no boundary",
        "extra inline policy",
        "listing failed",
    ],
)
def test_negative_control_role_shape_is_verified(
    tmp_path: Path, answers: dict[str, str], expected: str | None
) -> None:
    result = _fake_run(
        tmp_path,
        "verify_role_shape nlw-staging-dataset-api nlw-dataset-api",
        **{**GOOD_ROLE, **answers},
        PROOF_BOUNDARY_ARN=BOUNDARY,
    )
    if expected is None:
        assert result.returncode == 0, result.stderr
    else:
        assert (
            result.returncode != 0
            and f"STOP S9: nlw-staging-dataset-api {expected}" in result.stderr
            or ("STOP S9: cannot list" in result.stderr and expected.startswith("cannot list"))
        ), result.stderr


@needs_bash_and_git
@pytest.mark.parametrize(
    ("answers", "ok"),
    [
        ({"FAKE_LIST_GRANTS": "0"}, True),
        ({"FAKE_LIST_GRANTS": "1"}, False),
        ({"FAKE_LIST_GRANTS_RC": "255"}, False),
    ],
    ids=["no grant", "an unexpected grant", "listing failed"],
)
def test_negative_control_kms_grants_are_verified(
    tmp_path: Path, answers: dict[str, str], ok: bool
) -> None:
    result = _fake_run(
        tmp_path,
        "verify_no_grants arn:aws:kms:us-east-1:111122223333:key/x nlw-proof-admin",
        **answers,
    )
    assert (result.returncode == 0) is ok, result.stderr
    if not ok:
        assert "STOP S9:" in result.stderr


@needs_bash_and_git
@pytest.mark.parametrize(
    ("answers", "expected"),
    [
        (
            {
                "FAKE_GET_PUBLIC_ACCESS_BLOCK": "True\tTrue\tTrue\tTrue",
                "FAKE_GET_BUCKET_OWNERSHIP_CONTROLS": "BucketOwnerEnforced",
            },
            True,
        ),
        (
            {
                "FAKE_GET_PUBLIC_ACCESS_BLOCK": "True\tTrue\tFalse\tTrue",
                "FAKE_GET_BUCKET_OWNERSHIP_CONTROLS": "BucketOwnerEnforced",
            },
            "public access is not fully blocked on",
        ),
        (
            {
                "FAKE_GET_PUBLIC_ACCESS_BLOCK_RC": "254",
                "FAKE_GET_BUCKET_OWNERSHIP_CONTROLS": "BucketOwnerEnforced",
            },
            "no public access block on",
        ),
        (
            {
                "FAKE_GET_PUBLIC_ACCESS_BLOCK": "True\tTrue\tTrue\tTrue",
                "FAKE_GET_BUCKET_OWNERSHIP_CONTROLS": "ObjectWriter",
            },
            "ACLs are not disabled on",
        ),
        (
            {
                "FAKE_GET_PUBLIC_ACCESS_BLOCK": "True\tTrue\tTrue\tTrue",
                "FAKE_GET_BUCKET_OWNERSHIP_CONTROLS_RC": "254",
            },
            "no ownership controls on",
        ),
    ],
    ids=[
        "controls in place",
        "one public-access block off",
        "public-access block missing",
        "ACLs enabled",
        "ownership controls missing",
    ],
)
def test_negative_control_bucket_controls_are_verified(
    tmp_path: Path, answers: dict[str, str], expected: bool | str
) -> None:
    """Each control is checked on its own: the stop names the exact reason."""
    result = _fake_run(
        tmp_path, "verify_bucket_controls nlw-staging-datasets-x nlw-proof-admin", **answers
    )
    if expected is True:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0
        assert f"STOP S9: {expected} nlw-staging-datasets-x" in result.stderr, result.stderr


@needs_bash_and_git
@pytest.mark.parametrize(
    ("answers", "expected"),
    [
        ({"FAKE_SIMULATE_PRINCIPAL_POLICY": "implicitDeny\texplicitDeny"}, None),
        (
            {"FAKE_SIMULATE_PRINCIPAL_POLICY": ""},
            "STOP S9: the simulation for arn:aws:iam::111122223333:user/x returned no decision",
        ),
        (
            {"FAKE_SIMULATE_PRINCIPAL_POLICY_RC": "255"},
            "STOP S9: the simulation for arn:aws:iam::111122223333:user/x failed",
        ),
        (
            {"FAKE_SIMULATE_PRINCIPAL_POLICY": "implicitDeny\tallowed"},
            "STOP S4: arn:aws:iam::111122223333:user/x is allowed",
        ),
    ],
    ids=["all denied", "empty result", "simulation error", "one allowed"],
)
def test_negative_control_simulations_fail_closed(
    tmp_path: Path, answers: dict[str, str], expected: str | None
) -> None:
    result = _fake_run(
        tmp_path,
        "sim_denied arn:aws:iam::111122223333:user/x arn:aws:iam::111122223333:role/r iam:PassRole",
        **answers,
    )
    if expected is None:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0 and expected in result.stderr, result.stderr


@needs_bash_and_git
def test_negative_control_an_empty_expected_simulation_is_refused(tmp_path: Path) -> None:
    result = _lib_run(tmp_path, "expect_simulated explicitDeny ''")
    assert result.returncode != 0 and "STOP S9: the simulator returned no decision" in result.stderr


@needs_bash_and_git
@pytest.mark.parametrize("template", ["dataset-bucket-lifecycle", "audit-bucket-lifecycle"])
def test_negative_control_a_drifted_lifecycle_rule_stops_the_proof(
    tmp_path: Path, template: str
) -> None:
    render = _lib_run(tmp_path / "a", f'render {template} > "$PROOF_DIR/rendered.json"')
    assert render.returncode == 0, render.stderr
    rendered = json.loads((tmp_path / "a" / "proof" / "rendered.json").read_text())
    drifted = copy.deepcopy(rendered)
    drifted["Rules"][0]["Expiration"] = {"Days": 1}
    normalizer = dict(FILE_BLOCK.findall(proof_text()))["normalize-policy.py"]
    results = {}
    for sub, deployed in (("b", rendered), ("c", drifted)):
        (tmp_path / sub / "proof").mkdir(parents=True)
        (tmp_path / sub / "proof" / "normalize-policy.py").write_text(normalizer)
        (tmp_path / sub / "proof" / "rendered.json").write_text(json.dumps(rendered))
        results[sub] = _lib_run(
            tmp_path / sub,
            f'same lifecycle {shlex.quote(json.dumps(deployed))} "$PROOF_DIR/rendered.json"',
        )
    assert results["b"].returncode == 0, results["b"].stderr
    assert results["c"].returncode != 0
    assert "STOP S9: lifecycle differs from the rendered template" in results["c"].stderr


@needs_bash_and_git
@pytest.mark.parametrize(
    "role", ["nlw-staging-dataset-operator", "team/nlw-production-dataset-api"]
)
def test_negative_control_a_dataset_role_cannot_be_admin_role(tmp_path: Path, role: str) -> None:
    result = _lib_run(tmp_path, "true", ADMIN_ROLE=role)
    assert (
        result.returncode != 0 and "STOP S1: ADMIN_ROLE must not be a dataset role" in result.stderr
    )


# --- P00-02 executed: reviewed-tree binding and the D6 gate --------------------------------------


GATE_PATH = Path("docs") / "evidence" / "o2-d6" / "d6-gate.json"
PROD_ACCOUNT = "444455556666"
STAGING_ACCOUNT = "777788889999"


def _git(repo: Path, env: dict[str, str], *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True, env=env
    ).stdout.strip()


def _p00_02(
    tmp_path: Path,
    *,
    gate: dict[str, Any] | None,
    runbook_dir: Path | None = None,
    overrides: dict[str, str] | None = None,
    layout: str = "committed",
) -> subprocess.CompletedProcess[str]:
    """Run the reviewed P00-02 block in a throwaway repository: commit 1 is
    the procedure; with layout "committed" commit 2 adds only the gate record,
    naming commit 1 (``procedure_commit: "<PARENT>"``), and is the reviewed
    commit. Other layouts are the M1 negative controls."""
    repo = tmp_path / "repo"
    (repo / "docs" / "runbooks").mkdir(parents=True)
    for doc in (PROVISIONING, PROOF):
        shutil.copy(doc, repo / "docs" / "runbooks" / doc.name)
    git_env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    _git(repo, git_env, "init", "-q")
    _git(repo, git_env, "add", "-A")
    _git(repo, git_env, "commit", "-q", "--no-gpg-sign", "-m", "procedure")
    procedure = _git(repo, git_env, "rev-parse", "HEAD")
    if gate is not None:
        body = json.dumps(
            {k: procedure if v == "<PARENT>" else v for k, v in gate.items()}, indent=1
        )
        (repo / GATE_PATH).parent.mkdir(parents=True)
        (repo / GATE_PATH).write_text(body)
        if layout == "excluded":  # hidden from status by .git/info/exclude, never committed
            (repo / ".git" / "info" / "exclude").write_text("docs/evidence/\n")
        elif layout == "untracked":  # present in the working tree, never committed
            pass
        elif layout != "with-procedure-change":
            _git(repo, git_env, "add", "-A")
            _git(repo, git_env, "commit", "-q", "--no-gpg-sign", "-m", "gate")
            if layout == "replaced":  # tracked, then edited in the working tree
                (repo / GATE_PATH).write_text(body.replace("independent verifier", "operator"))
            if layout == "later-commit":  # the gate was recorded for an earlier commit
                (repo / "docs" / "runbooks" / "extra.md").write_text("x")
                _git(repo, git_env, "add", "-A")
                _git(repo, git_env, "commit", "-q", "--no-gpg-sign", "-m", "later")
        if layout == "with-procedure-change":  # the gate commit also changes the procedure
            (repo / "docs" / "runbooks" / "extra.md").write_text("x")
            _git(repo, git_env, "add", "-A")
            _git(repo, git_env, "commit", "-q", "--no-gpg-sign", "-m", "gate and more")
    head = _git(repo, git_env, "rev-parse", "HEAD")
    humans = {
        "OPERATOR_HUMANS_JSON": json.dumps([sso_role(DUMMY_ACCOUNT, "NlwD6Operator")]),
        "AUDIT_ADMIN_HUMANS_JSON": json.dumps([sso_role(DUMMY_ACCOUNT, "NlwD6AuditAdmin")]),
        "AUDIT_READER_HUMANS_JSON": json.dumps([sso_role(DUMMY_ACCOUNT, "NlwD6AuditReader")]),
    }
    env = {
        **git_env,
        "REVIEWED_COMMIT": head,
        "PROOF_ID": "d6-20261011-a1b2c3",
        "BUCKET_SUFFIX": GOOD_SUFFIX,
        "PROOF_DIR": str(tmp_path / "proof"),
        "RUNBOOK_DIR": str(runbook_dir or repo / "docs" / "runbooks"),
        "APPROVED_ACCOUNT": DUMMY_ACCOUNT,
        "STAGING_ACCOUNT_IDS_JSON": json.dumps([STAGING_ACCOUNT]),
        "PRODUCTION_ACCOUNT_IDS_JSON": json.dumps([PROD_ACCOUNT]),
        "E11_IDENTITY": "identity-center",
        "ADMIN_ROLE": ADMIN_ROLE_NAME,
        "PROOF_BOUNDARY_ARN": BOUNDARY,
        "OPERATOR_NAME": "operator",
        "SSO_START_URL": "https://d-0000000000.awsapps.com/start/#/",
        "SSO_REGION": "us-east-1",
        "PROOF_ADMIN_PERMISSION_SET": "NlwD6ProofAdmin",
        "OPERATOR_PERMISSION_SET": "NlwD6Operator",
        "AUDIT_ADMIN_PERMISSION_SET": "NlwD6AuditAdmin",
        "AUDIT_READER_PERMISSION_SET": "NlwD6AuditReader",
        **humans,
    }
    env.update(overrides or {})
    script = tmp_path / "p00-02.sh"
    script.write_text(
        [
            b["raw"]
            for b in labelled_blocks(proof_text())
            if b["label"] and b["label"]["id"] == "P00-02"
        ][0]
    )
    return subprocess.run(
        ["bash", str(script)], cwd=repo, env=env, capture_output=True, text=True, timeout=60
    )


def _good_gate() -> dict[str, Any]:
    return {
        "decision": "approved",
        "procedure_commit": "<PARENT>",
        "account": DUMMY_ACCOUNT,
        "account_mode": "dedicated",
        "staging_account_ids": [STAGING_ACCOUNT],
        "production_account_ids": [PROD_ACCOUNT],
        "no_production_resources_verified": True,
        "organization_id": "o-exampleorg1",
        "management_account_id": "none-recorded",
        "proof_boundary_arn": BOUNDARY,
        "proof_admin_role_arn": f"arn:aws:iam::{DUMMY_ACCOUNT}:role/{ADMIN_ROLE_NAME}",
        "permission_sets": {
            "proof_admin": "NlwD6ProofAdmin",
            "operator": "NlwD6Operator",
            "audit_admin": "NlwD6AuditAdmin",
            "audit_reader": "NlwD6AuditReader",
        },
        "operator_role_arns": [sso_role(DUMMY_ACCOUNT, "NlwD6Operator")],
        "audit_admin_role_arns": [sso_role(DUMMY_ACCOUNT, "NlwD6AuditAdmin")],
        "audit_reader_role_arns": [sso_role(DUMMY_ACCOUNT, "NlwD6AuditReader")],
        "permission_set_policies_verified": True,
        "boundary_attached_verified": True,
        "effective_permissions_verified": True,
        "identity_center_mfa_required": True,
        "account_administrators_outside_operator": True,
        "verified_by": "independent verifier",
        "verified_at": "2026-10-12",
    }


@needs_bash_and_git
def test_p00_02_extracts_only_with_a_matching_gate_record(tmp_path: Path) -> None:
    result = _p00_02(tmp_path, gate=_good_gate())
    assert result.returncode == 0, result.stderr
    proof = tmp_path / "proof"
    manifest = json.loads((proof / "manifest.json").read_text())
    for rel in ("aws-config", "gate.json", "steps/P03-11.sh", "lib.sh", "render-config.py"):
        assert rel in manifest, rel
    # L1: the start URL holds '#' and '/', and arrives byte for byte.
    config = (proof / "aws-config").read_text()
    assert "sso_start_url = https://d-0000000000.awsapps.com/start/#/\n" in config
    assert not re.search(r"<[A-Z_]+>", config)
    assert json.loads((proof / "gate.json").read_text())["account_mode"] == "dedicated"


@needs_bash_and_git
@pytest.mark.parametrize(
    ("gate_change", "overrides", "expected"),
    [
        (None, {}, "STOP S9: D6 is blocked (decision E15): no verification record is tracked"),
        ({"verified_by": "operator"}, {}, "does not match this run: verified_by"),
        ({"decision": "rejected"}, {}, "does not match this run: decision"),
        ({"verified_by": ""}, {}, "does not match this run: verified_by"),
        ({"effective_permissions_verified": False}, {}, "effective_permissions_verified"),
        ({"permission_set_policies_verified": False}, {}, "permission_set_policies_verified"),
        ({"identity_center_mfa_required": False}, {}, "identity_center_mfa_required"),
        ({"account_mode": "bounded"}, {}, "does not match this run: account_mode"),
        ({"no_production_resources_verified": False}, {}, "no_production_resources_verified"),
        (
            {"account_administrators_outside_operator": False},
            {},
            "account_administrators_outside_operator",
        ),
        (
            {"proof_boundary_arn": "arn:aws:iam::111122223333:policy/other"},
            {},
            "proof_boundary_arn",
        ),
        ({"account": "999999999999"}, {}, "does not match this run: account"),
        (
            {"production_account_ids": [DUMMY_ACCOUNT]},
            {"PRODUCTION_ACCOUNT_IDS_JSON": json.dumps([DUMMY_ACCOUNT])},
            "distinct_account",
        ),
        (
            {"staging_account_ids": [DUMMY_ACCOUNT]},
            {"STAGING_ACCOUNT_IDS_JSON": json.dumps([DUMMY_ACCOUNT])},
            "distinct_account",
        ),
        ({}, {"PRODUCTION_ACCOUNT_IDS_JSON": "[]"}, "production_account_ids"),
        ({"permission_sets": {"proof_admin": "NlwD6ProofAdmin"}}, {}, "permission_sets"),
        ({"procedure_commit": "0" * 40}, {}, "does not name the reviewed commit's parent"),
        (
            {},
            {"E11_IDENTITY": "iam-user-mfa"},
            "STOP S9: only short-lived Identity Center credentials",
        ),
        ({}, {"REVIEWED_COMMIT": "0" * 40}, "STOP S9: not the reviewed commit"),
        ({}, {"SSO_START_URL": "https://x/\n[profile evil]"}, "STOP S7: aws-config"),
    ],
    ids=[
        "no gate record",
        "operator verified their own run",
        "decision not approved",
        "no verifier",
        "effective permissions unverified",
        "permission-set policies unverified",
        "MFA not attested",
        "shared-account mode",
        "production resources not checked",
        "account administrator is the operator",
        "different boundary",
        "different account",
        "proof account is a production account",
        "proof account is a staging account",
        "no production account list",
        "permission sets differ",
        "mismatched commit inside the gate",
        "long-term credentials",
        "unreviewed commit",
        "newline injected into aws-config",
    ],
)
def test_negative_control_p00_02_refuses_to_start(
    tmp_path: Path, gate_change: dict[str, Any] | None, overrides: dict[str, str], expected: str
) -> None:
    gate = None if gate_change is None else {**_good_gate(), **gate_change}
    result = _p00_02(tmp_path, gate=gate, overrides=overrides)
    assert result.returncode != 0 and expected in result.stderr, result.stderr
    if "aws-config" not in expected:
        assert not (tmp_path / "proof" / "manifest.json").exists()


@needs_bash_and_git
@pytest.mark.parametrize(
    ("layout", "expected"),
    [
        ("excluded", "untracked or ignored files under docs/runbooks or docs/evidence"),
        ("untracked", "STOP S9: the checkout has local changes"),
        ("replaced", "STOP S9: the checkout has local changes"),
        ("later-commit", "the record does not name the reviewed commit's parent"),
        (
            "with-procedure-change",
            "the reviewed commit changes more than the verification record",
        ),
    ],
    ids=[
        "gate hidden by .git/info/exclude",
        "untracked replacement gate",
        "tracked gate edited in the working tree",
        "gate from another commit",
        "gate commit also changes the procedure",
    ],
)
def test_negative_control_the_gate_is_read_only_from_the_reviewed_commit(
    tmp_path: Path, layout: str, expected: str
) -> None:
    result = _p00_02(tmp_path, gate=_good_gate(), layout=layout)
    assert result.returncode != 0 and expected in result.stderr, result.stderr
    assert not (tmp_path / "proof" / "manifest.json").exists()


@needs_bash_and_git
def test_negative_control_an_excluded_file_under_the_runbooks_is_refused(tmp_path: Path) -> None:
    """`git status --porcelain` hides ignored files; P00-02 also refuses an
    ignored file under docs/runbooks or docs/evidence (M1)."""
    result = _p00_02(tmp_path, gate=_good_gate())
    assert result.returncode == 0, result.stderr
    repo = tmp_path / "repo"
    (repo / ".git" / "info" / "exclude").write_text("docs/runbooks/shadow.md\n")
    (repo / "docs" / "runbooks" / "shadow.md").write_text("x")
    shutil.rmtree(tmp_path / "proof")
    script = tmp_path / "p00-02.sh"
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1"}
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, env=env
    ).stdout.strip()
    again = _p00_02_rerun(tmp_path, repo, script, head)
    assert again.returncode != 0
    assert "untracked or ignored files under docs/runbooks or docs/evidence" in again.stderr


def _p00_02_rerun(
    tmp_path: Path, repo: Path, script: Path, head: str
) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "GIT_CONFIG_NOSYSTEM": "1",
        "REVIEWED_COMMIT": head,
        "PROOF_DIR": str(tmp_path / "proof"),
        "RUNBOOK_DIR": str(repo / "docs" / "runbooks"),
        "E11_IDENTITY": "identity-center",
    }
    return subprocess.run(
        ["bash", str(script)], cwd=repo, env=env, capture_output=True, text=True, timeout=60
    )


@needs_bash_and_git
def test_negative_control_p00_02_refuses_a_runbook_tree_outside_the_reviewed_checkout(
    tmp_path: Path,
) -> None:
    other = tmp_path / "other" / "docs" / "runbooks"
    other.mkdir(parents=True)
    for doc in (PROVISIONING, PROOF):
        shutil.copy(doc, other / doc.name)
    result = _p00_02(tmp_path, gate=_good_gate(), runbook_dir=other)
    assert result.returncode != 0
    assert "STOP S9: RUNBOOK_DIR is not this reviewed checkout's runbook directory" in result.stderr


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
        lambda t: _sid(t, "trust-human", "NamedSsoPermissionSetRolesOnly").update(
            Principal={"AWS": ["<HUMAN_PRINCIPAL_ARNS>", role("bootstrap")]}
        ),
        instance_role_violations,
    ),
    (
        "human trust stops denying machine roles",
        lambda t: _drop_sid(t, "trust-human", "DenyMachineRoles"),
        instance_role_violations,
    ),
    (
        "api trust drops the session-name condition",
        lambda t: _sid(t, "trust-api", "BootstrapWithApiSessionName").pop("Condition"),
        instance_role_violations,
    ),
    (
        "human trust without run-scoped session names",
        lambda t: _sid(t, "trust-human", "NamedSsoPermissionSetRolesOnly").pop("Condition"),
        sso_trust_violations,
    ),
    (
        "human trust admits non-Identity-Center principals",
        lambda t: _drop_sid(t, "trust-human", "DenyAnythingButIdentityCenter"),
        sso_trust_violations,
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


# --- round 4: proof executability, executed calls, the dedicated account and E9 -----------


def test_every_render_names_an_existing_template_and_every_template_is_rendered() -> None:
    assert render_violations(proof_text()) == []


@pytest.mark.parametrize(
    "mutation",
    [
        lambda t: t.replace(
            "make_role nlw-proof-admin operator trust-human REC_ROLE_OPERATOR",
            "make_role nlw-proof-admin operator trust-human-mfa REC_ROLE_OPERATOR",
            1,
        ),
        lambda t: t.replace(
            "render dataset-bucket-policy >", "render dataset-bucket-policies >", 1
        ),
        lambda t: t.replace(
            "for ps in proof-admin operator audit-admin audit-reader; do",
            "for ps in proof-admin operator audit-admin; do",
            1,
        ),
        lambda t: t.replace('render "permission-set-$ps"', 'render "$template"', 1),
    ],
    ids=[
        "H1 trust-human-mfa again",
        "a renamed template",
        "a required template never rendered",
        "an unresolvable render",
    ],
)
def test_negative_control_render_mismatches_are_detected(mutation: Callable[[str], str]) -> None:
    text = proof_text()
    weakened = mutation(text)
    assert weakened != text
    assert render_violations(weakened)


def test_negative_control_an_unused_template_is_detected() -> None:
    extra = (
        PROVISIONING.read_text()
        + "\n<!-- template: unused-policy -->\n```json\n"
        + '{"Version": "2012-10-17", "Statement": []}\n```\n'
    )
    assert render_violations(proof_text(), load_templates(extra)) == [
        "the template unused-policy is never rendered by the procedure"
    ]


def test_every_session_name_is_proof_scoped_and_matches_its_profile() -> None:
    assert session_violations(proof_text()) == []


@pytest.mark.parametrize(
    "mutation",
    [
        lambda t: t.replace(
            '/$(session_name operator)" \\\n  || stop S9 "operator identity"',
            '/nlw-staging-operator" \\\n  || stop S9 "operator identity"',
            1,
        ),
        lambda t: t.replace(
            '"$(session_name operator)" \\\n  --query AssumedRoleUser.Arn',
            "nlw-staging-operator \\\n  --query AssumedRoleUser.Arn",
            1,
        ),
        lambda t: t.replace(
            'aws sso login --sso-session "$(session_name operator)"',
            'aws sso login --sso-session "nlw-d6-$PROOF_ID-operator"',
            1,
        ),
        lambda t: t.replace(
            "role_session_name = nlw-d6-<PROOF_ID>-operator\n"
            "source_profile = nlw-proof-human-operator",
            "role_session_name = nlw-d6-<PROOF_ID>-op\nsource_profile = nlw-proof-human-operator",
            1,
        ),
        lambda t: t.replace(
            "session_name() { printf 'nlw-d6-%s-%s'", "session_name() { printf 'nlw-%s-%s'", 1
        ),
    ],
    ids=[
        "H2 P12-03 expects the old session name",
        "P12-02 uses a literal session name",
        "an SSO session built by hand",
        "the profile's session name differs",
        "the helper is changed",
    ],
)
def test_negative_control_session_name_mismatches_are_detected(
    mutation: Callable[[str], str],
) -> None:
    text = proof_text()
    weakened = mutation(text)
    assert weakened != text
    assert session_violations(weakened)


@needs_harness
@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda t: t.replace(
                "make_role nlw-proof-admin operator trust-human REC_ROLE_OPERATOR",
                "make_role nlw-proof-admin operator trust-human-mfa REC_ROLE_OPERATOR",
                1,
            ),
            "P03-01 failed",
        ),
        (
            lambda t: t.replace(
                '/$(session_name operator)" \\\n  || stop S9 "operator identity"',
                '/nlw-staging-operator" \\\n  || stop S9 "operator identity"',
                1,
            ),
            "P12-03: STOP S9 operator identity",
        ),
        (
            lambda t: _after_source(
                t, "P03-11", 'jq -e .missing "$PROOF_DIR/gate.json" > /dev/null'
            ),
            "P03-11 failed",
        ),
        (
            lambda t: t.replace(
                "source_profile = nlw-proof-human-audit-reader\n",
                "source_profile = nlw-proof-human-audit-nobody\n",
                1,
            ),
            "P00-02 failed",
        ),
        (
            lambda t: t.replace(
                'record REC_TRAIL_ARN "$(aws cloudtrail create-trail',
                'record REC_TRAIL_ARN "$(true || aws cloudtrail create-trail',
                1,
            ),
            "STOP S10 a create returned no identifier",
        ),
    ],
    ids=[
        "missing template",
        "incorrect session name",
        "unexpected command failure",
        "malformed generated configuration",
        "a create that returns nothing",
    ],
)
def test_negative_control_the_stub_run_fails_on_a_genuinely_broken_step(
    tmp_path: Path, mutation: Callable[[str], str], expected: str
) -> None:
    """Fake AWS answers never turn a genuine proof error into noise: the run
    stops at the first one and reports it."""
    text = proof_text()
    weakened = mutation(text)
    assert weakened != text
    run = run_with_stub(tmp_path, weakened, AVAILABLE_BASHES[0])
    assert any(expected in f for f in run.fatal), run.fatal
    assert stub_violations(run, weakened)


EXECUTED_CALL_MUTATIONS = [
    (
        'cli=aws; "$cli" ssm send-command',
        lambda t: _after_source(
            t,
            "P03-11",
            'cli=aws; "$cli" ssm send-command --profile nlw-proof-admin '
            '--instance-ids "$REC_INSTANCE_ID" --document-name AWS-RunShellScript',
        ),
        "aws ssm send-command is not a reviewed operation",
    ),
    (
        "unexpected STS operation",
        lambda t: _after_source(t, "P01-01", "aws sts get-session-token --profile nlw-proof-admin"),
        "aws sts get-session-token is not a reviewed operation",
    ),
    (
        "unexpected IAM operation",
        lambda t: _after_source(
            t,
            "P03-09",
            "aws iam attach-role-policy --profile nlw-proof-admin --role-name "
            "nlw-staging-dataset-api --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        ),
        "aws iam attach-role-policy is not a reviewed operation",
    ),
    (
        "unexpected KMS operation",
        lambda t: _after_source(
            t,
            "P03-11",
            'aws kms create-grant --profile nlw-proof-admin --key-id "$REC_KEY_ARN" '
            "--grantee-principal x --operations Decrypt",
        ),
        "aws kms create-grant is not a reviewed operation",
    ),
    (
        "unexpected S3 operation",
        lambda t: _after_source(
            t,
            "P03-06",
            "aws s3api put-bucket-acl --profile nlw-proof-admin "
            '--bucket "$BUCKET" --acl public-read',
        ),
        "aws s3api put-bucket-acl is not a reviewed operation",
    ),
    (
        "unexpected CloudTrail operation",
        lambda t: _after_source(
            t,
            "P03-08",
            'aws cloudtrail update-trail --profile nlw-proof-audit-admin --name "$TRAIL_ARN" '
            "--no-enable-log-file-validation",
        ),
        "aws cloudtrail update-trail is not a reviewed operation",
    ),
    (
        "an allowed operation from the wrong step",
        lambda t: _after_source(
            t,
            "P03-11",
            'aws kms schedule-key-deletion --profile nlw-proof-admin --key-id "$REC_KEY_ARN" '
            "--pending-window-in-days 7",
        ),
        "P03-11: aws kms schedule-key-deletion runs outside its reviewed steps",
    ),
    (
        "an allowed operation on an unexpected resource",
        lambda t: _after_source(
            t,
            "P03-06",
            'aws s3api put-bucket-policy --profile nlw-proof-admin --bucket "nlw-staging-other" '
            '--policy "file://$PROOF_DIR/bucket-policy.json"',
        ),
        "--bucket 'nlw-staging-other' is not a reviewed resource",
    ),
    (
        "an allowed operation as an unexpected identity",
        lambda t: _after_source(
            t,
            "P03-06",
            'aws s3api put-bucket-policy --profile nlw-proof-human-audit-admin --bucket "$BUCKET" '
            '--policy "file://$PROOF_DIR/bucket-policy.json"',
        ),
        "runs as nlw-proof-human-audit-admin, not a reviewed identity",
    ),
]


@needs_harness
@pytest.mark.parametrize(
    ("mutation", "expected"),
    [(m[1], m[2]) for m in EXECUTED_CALL_MUTATIONS],
    ids=[m[0] for m in EXECUTED_CALL_MUTATIONS],
)
def test_negative_control_executed_calls_outside_the_allow_list_are_detected(
    tmp_path: Path, mutation: Callable[[str], str], expected: str
) -> None:
    text = proof_text()
    weakened = mutation(text)
    assert weakened != text
    run = run_with_stub(tmp_path, weakened, AVAILABLE_BASHES[0])
    found = executed_call_violations(run)
    assert any(expected in f for f in found), found


@needs_harness
def test_negative_control_a_malformed_stub_record_fails_closed(tmp_path: Path) -> None:
    """A record left without its suffix, or without its terminator, is an
    incomplete write and fails the run."""
    extra = (
        '\nprintf "aws\\037P00-03\\037sts" > "$STUB_LOG/rec.partial"'
        '\nprintf "aws\\037P00-03\\037sts" > "$STUB_LOG/rec.cut.rec"\n'
    )
    text = proof_text()
    run = run_with_stub(tmp_path, text, AVAILABLE_BASHES[0], lib_extra=extra)
    bad = [f for f in run.fatal if "malformed or incomplete stub record" in f]
    assert len(bad) >= 2, run.fatal


def test_no_aws_call_is_hidden_from_the_static_scan() -> None:
    assert static_call_violations(proof_text()) == []


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('cli=aws; "$cli" ssm send-command --instance-ids i-1', "through a variable ($cli)"),
        ("/usr/local/bin/aws s3api delete-bucket --bucket b", "aws run by absolute path"),
        ("curl -s https://s3.amazonaws.com/b", "a network client (curl)"),
        ("python3 - <<'PY'\nimport boto3\nPY", "embedded Python uses boto3"),
        ("python3 - <<'PY'\nimport subprocess\nPY", "embedded Python uses subprocess"),
        ("python3 -c 'from botocore.auth import SigV4Auth'", "embedded Python uses"),
    ],
    ids=["shell variable", "absolute path", "curl", "boto3", "subprocess", "SigV4"],
)
def test_negative_control_static_scan_detects_hidden_calls(line: str, expected: str) -> None:
    weakened = _after_source(proof_text(), "P03-11", line)
    assert any(expected in x for x in static_call_violations(weakened))


def test_operator_and_audit_sides_are_separated() -> None:
    assert separation_violations(load_templates()) == []
    assert permission_set_statement_violations(load_templates()) == []


SEPARATION_MUTATIONS = [
    (
        "operator side may change the audit roles",
        lambda t: _drop_sid(t, "permission-set-proof-admin", "NeverTheAuditRolesBucketOrAlias"),
    ),
    (
        "operator may stop the trail",
        lambda t: _sid(t, "permission-set-operator", "NeverAlterAnyTrail")["Action"].remove(
            "cloudtrail:StopLogging"
        ),
    ),
    (
        "proof administrator may administer the audit key",
        lambda t: _drop_sid(t, "permission-set-proof-admin", "NeverAuditKeys"),
    ),
    (
        "proof administrator granted the audit bucket",
        lambda t: _sid(t, "permission-set-proof-admin", "AdministerTheDatasetBucket").update(
            Resource="arn:aws:s3:::nlw-<ENV>-dataset-audit-<ACCOUNT>-us-east-1-d6*"
        ),
    ),
    (
        "audit side may assume the operator role",
        lambda t: _sid(t, "permission-set-audit-admin", "NeverTheDatasetRolesBucketOrAlias")[
            "Resource"
        ].remove("arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-operator"),
    ),
    (
        "audit reader may use the dataset key",
        lambda t: _drop_sid(t, "permission-set-audit-reader", "NeverDatasetKeys"),
    ),
    (
        "operator permission set assumes any dataset role",
        lambda t: _sid(t, "permission-set-operator", "AssumeOnlyTheOperatorRole").update(
            Resource="arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-*"
        ),
    ),
    (
        "proof administrator may change a key policy",
        lambda t: _sid(t, "permission-set-proof-admin", "AdministerOnlyDatasetKeys")[
            "Action"
        ].append("kms:PutKeyPolicy"),
    ),
]


@pytest.mark.parametrize(
    ("mutation",), [(m[1],) for m in SEPARATION_MUTATIONS], ids=[m[0] for m in SEPARATION_MUTATIONS]
)
def test_negative_control_separation_weakening_is_detected(
    mutation: Callable[[Templates], None],
) -> None:
    weakened = copy.deepcopy(load_templates())
    mutation(weakened)
    assert separation_violations(weakened) or permission_set_statement_violations(weakened)


BOUNDARY_MUTATIONS = [
    (
        "a dataset-* role pattern",
        lambda t: _sid(t, "proof-principal-boundary", "D6TheSixRoles").update(
            Resource="arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-*"
        ),
    ),
    (
        "an action no proof identity uses",
        lambda t: _sid(t, "proof-principal-boundary", "D6NoResourceScope")["Action"].append(
            "lambda:InvokeFunction"
        ),
    ),
    (
        "an action a proof identity needs is missing",
        lambda t: _sid(t, "proof-principal-boundary", "D6TheProofKeys")["Action"].remove(
            "kms:ListGrants"
        ),
    ),
    (
        "an identity policy granted beyond the boundary",
        lambda t: _sid(t, "permission-set-proof-admin", "ReadTheAccountInventory")["Action"].append(
            "iam:CreateUser"
        ),
    ),
    (
        "a wildcard Allow",
        lambda t: _sid(t, "proof-principal-boundary", "D6TheProofBuckets")["Action"].append("s3:*"),
    ),
    (
        "a bucket outside the proof pattern",
        lambda t: _sid(t, "proof-principal-boundary", "D6TheProofBuckets").update(Resource="*"),
    ),
    (
        "SAML and OIDC providers allowed",
        lambda t: _drop_sid(t, "proof-principal-denies", "NeverIdentityProviders"),
    ),
    (
        "AssumeRole into the bootstrap role",
        lambda t: _sid(t, "proof-principal-denies", "AssumeOnlyTheProofRoles")[
            "NotResource"
        ].append("arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-bootstrap"),
    ),
    (
        "the bootstrap role passed to any service",
        lambda t: _drop_sid(t, "proof-principal-denies", "PassTheBootstrapRoleOnlyToEc2"),
    ),
    (
        "Lambda allowed",
        lambda t: _sid(t, "proof-principal-denies", "NeverIndirectExecution")["Action"].remove(
            "lambda:*"
        ),
    ),
    (
        "organizations changes allowed",
        lambda t: _sid(t, "proof-principal-denies", "NeverOrganizationOrAccountChanges")[
            "Action"
        ].remove("organizations:Leave*"),
    ),
    (
        "own trust may be changed",
        lambda t: _sid(t, "proof-principal-denies", "NeverChangeTheProofPrincipalsOrPolicies")[
            "Action"
        ].remove("iam:UpdateAssumeRolePolicy"),
    ),
    (
        "boundary removal allowed",
        lambda t: _sid(t, "proof-principal-denies", "NeverEscalate")["Action"].remove(
            "iam:DeleteRolePermissionsBoundary"
        ),
    ),
    (
        "any region",
        lambda t: _drop_sid(t, "proof-principal-denies", "OnlyTheApprovedRegion"),
    ),
    (
        "created roles need not carry the boundary",
        lambda t: _drop_sid(t, "proof-principal-boundary", "CreatedRolesCarryThisBoundary"),
    ),
]


@pytest.mark.parametrize(
    ("mutation",), [(m[1],) for m in BOUNDARY_MUTATIONS], ids=[m[0] for m in BOUNDARY_MUTATIONS]
)
def test_negative_control_boundary_and_deny_policy_weakening_is_detected(
    mutation: Callable[[Templates], None],
) -> None:
    weakened = copy.deepcopy(load_templates())
    mutation(weakened)
    assert boundary_violations(weakened)


def _render_config(
    tmp_path: Path, template: str, **values: str
) -> subprocess.CompletedProcess[str]:
    script = tmp_path / "render-config.py"
    script.write_text(dict(FILE_BLOCK.findall(proof_text()))["render-config.py"])
    (tmp_path / "in").write_text(template)
    env = {
        "PATH": os.environ["PATH"],
        "APPROVED_ACCOUNT": DUMMY_ACCOUNT,
        "PROOF_ID": STUB_PROOF_ID,
        "SSO_START_URL": "https://d-0000000000.awsapps.com/start/#/",
        "SSO_REGION": "eu-west-1",
        "PROOF_ADMIN_PERMISSION_SET": "NlwD6ProofAdmin",
        "OPERATOR_PERMISSION_SET": "NlwD6Operator",
        "AUDIT_ADMIN_PERMISSION_SET": "NlwD6AuditAdmin",
        "AUDIT_READER_PERMISSION_SET": "NlwD6AuditReader",
        **values,
    }
    return subprocess.run(
        [sys.executable, "-I", str(script), str(tmp_path / "in"), str(tmp_path / "out")],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


def test_render_config_fills_urls_with_hash_and_slash_literally(tmp_path: Path) -> None:
    """L1: '#', '/' and '&' are legal in an Identity Center start URL and must
    arrive unchanged; sed with '#' as its delimiter broke on them."""
    url = "https://d-0000000000.awsapps.com/start/#/?a=1&b=2"
    template = dict(FILE_BLOCK.findall(proof_text()))["aws-config.workstation"]
    result = _render_config(tmp_path, template, SSO_START_URL=url)
    assert result.returncode == 0, result.stderr
    out = (tmp_path / "out").read_text()
    assert f"sso_start_url = {url}\n" in out
    assert not re.search(r"<[A-Z_]+>", out)
    assert stat.S_IMODE((tmp_path / "out").stat().st_mode) == 0o600
    parsed = configparser.RawConfigParser()
    parsed.read_string(out)
    assert parsed.get(f"sso-session nlw-d6-{STUB_PROOF_ID}-operator", "sso_start_url") == url


@pytest.mark.parametrize(
    ("template", "values", "expected"),
    [
        (
            "[profile a]\nsso_start_url = <SSO_START_URL>\n",
            {"SSO_START_URL": "https://x\n[profile b]"},
            "not a valid value",
        ),
        (
            "[profile a]\nsso_start_url = <SSO_START_URL>\n",
            {"SSO_START_URL": "https://x y"},
            "not a valid value",
        ),
        ("[profile a]\nregion = <SURPRISE>\n", {}, "unknown placeholder"),
        (
            "[profile a]\nsso_role_name = <OPERATOR_PERMISSION_SET>\n",
            {"OPERATOR_PERMISSION_SET": "a_b"},
            "not a valid value",
        ),
        ("[profile a]\ncredential_process = /bin/cat k\n", {}, "credential process"),
        ("[profile a]\naws_secret_access_key = x\n", {}, "a key"),
        ("[profile a]\nregion = x\n[profile a]\nregion = y\n", {}, "does not parse"),
        ("[profile a]\nsource_profile = nobody\n", {}, "unknown source profile"),
        ("[profile a]\nsso_session = nobody\n", {}, "unknown sso-session"),
        ("[default]\nregion = x\n", {}, "neither a profile nor an sso-session"),
    ],
    ids=[
        "newline injection",
        "whitespace",
        "unknown placeholder",
        "permission set with underscore",
        "credential process",
        "a key",
        "duplicate section",
        "unknown source profile",
        "unknown sso-session",
        "default section",
    ],
)
def test_negative_control_render_config_refuses_unsafe_input(
    tmp_path: Path, template: str, values: dict[str, str], expected: str
) -> None:
    result = _render_config(tmp_path, template, **values)
    assert result.returncode != 0 and expected in result.stderr, result.stderr
    assert not (tmp_path / "out").exists()


@needs_bash_and_git
@pytest.mark.parametrize(
    ("staging", "production", "ok"),
    [
        (f'["{STAGING_ACCOUNT}"]', f'["{PROD_ACCOUNT}"]', True),
        (f'["{DUMMY_ACCOUNT}"]', f'["{PROD_ACCOUNT}"]', False),
        (f'["{STAGING_ACCOUNT}"]', f'["{PROD_ACCOUNT}", "{DUMMY_ACCOUNT}"]', False),
        ("", f'["{PROD_ACCOUNT}"]', False),
        (f'["{STAGING_ACCOUNT}"]', "[]", False),
        (f'["{STAGING_ACCOUNT}"]', '["1234"]', False),
        (f'["{STAGING_ACCOUNT}"]', f'["{PROD_ACCOUNT}\\n"]', False),
    ],
    ids=[
        "dedicated",
        "the staging account",
        "a production account",
        "no staging list",
        "empty production list",
        "malformed id",
        "trailing newline",
    ],
)
def test_negative_control_the_proof_account_must_be_dedicated(
    tmp_path: Path, staging: str, production: str, ok: bool
) -> None:
    result = _lib_run(
        tmp_path,
        "verify_dedicated_account",
        STAGING_ACCOUNT_IDS_JSON=staging,
        PRODUCTION_ACCOUNT_IDS_JSON=production,
    )
    assert (result.returncode == 0) is ok, result.stderr
    if not ok:
        assert "STOP S1: the proof account is not a dedicated account" in result.stderr


PS_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "A", "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "r"}],
    }
)
DENIES = f"arn:aws:iam::{DUMMY_ACCOUNT}:policy/nlw-staging-d6-proof-denies"
GOOD_PS_ROLE = {
    "FAKE_LIST_ROLE_POLICIES": '["AwsSSOInlinePolicy"]',
    "FAKE_GET_ROLE_POLICY": PS_DOC,
    "FAKE_LIST_ATTACHED_ROLE_POLICIES": json.dumps([DENIES]),
    "FAKE_GET_ROLE": BOUNDARY,
}


@needs_bash_and_git
@pytest.mark.parametrize(
    ("answers", "expected"),
    [
        ({}, None),
        (
            {"FAKE_LIST_ROLE_POLICIES": '["AwsSSOInlinePolicy", "Extra"]'},
            "has inline policies other than",
        ),
        (
            {"FAKE_GET_ROLE_POLICY": PS_DOC.replace("sts:AssumeRole", "sts:*")},
            "differs from the rendered template",
        ),
        (
            {
                "FAKE_LIST_ATTACHED_ROLE_POLICIES": json.dumps(
                    [DENIES, "arn:aws:iam::aws:policy/AdministratorAccess"]
                )
            },
            "has managed policies other than the proof deny policy",
        ),
        (
            {"FAKE_LIST_ATTACHED_ROLE_POLICIES": "[]"},
            "has managed policies other than the proof deny policy",
        ),
        (
            {"FAKE_GET_ROLE": "arn:aws:iam::aws:policy/PowerUserAccess"},
            "does not carry exactly the proof boundary",
        ),
        ({"FAKE_GET_ROLE_POLICY_RC": "254"}, "cannot read the inline policy of"),
    ],
    ids=[
        "exactly the reviewed configuration",
        "an extra inline policy",
        "a widened inline policy",
        "AdministratorAccess attached",
        "deny policy detached",
        "another boundary",
        "inline policy unreadable",
    ],
)
def test_negative_control_permission_set_roles_are_verified(
    tmp_path: Path, answers: dict[str, str], expected: str | None
) -> None:
    (tmp_path / "proof").mkdir()
    (tmp_path / "proof" / "permission-set-operator.json").write_text(PS_DOC)
    result = _fake_run(
        tmp_path,
        "verify_permission_set_role AWSReservedSSO_NlwD6Operator_0123456789abcdef operator",
        **{**GOOD_PS_ROLE, **answers},
        PROOF_BOUNDARY_ARN=BOUNDARY,
    )
    if expected is None:
        assert result.returncode == 0, result.stderr
    else:
        assert (
            result.returncode != 0 and "STOP S9: " in result.stderr and expected in result.stderr
        ), result.stderr


def test_x01_no_longer_accepts_access_key_ids() -> None:
    assert "AKIA" not in block(proof_text(), "X01")
    assert cleanup_identity_violations(
        proof_text().replace(
            '    REC_PROOF_ID) [[ "$value" == "$PROOF_ID" ]] ;;\n',
            '    REC_PROOF_ID) [[ "$value" == "$PROOF_ID" ]] ;;\n'
            '    REC_HUMAN_*_KEY_ID) [[ "$value" =~ ^AKIA[0-9A-Z]{16}$ ]] ;;\n',
            1,
        )
    )
