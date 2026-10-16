"""The O-4 object-backup templates (ADR-036): parsed, pinned and checked against
the invariants `restore-objects` and the retention policy rely on. NOT RUN
against AWS."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from nlw.core import retention

ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = ROOT / "docs/runbooks/dataset-object-backup-provisioning.md"
PROVISIONING = ROOT / "docs/runbooks/dataset-s3-provisioning.md"
RECEIPTS = ROOT / "docs/runbooks/deletion-receipt-log-provisioning.md"
TEMPLATE = re.compile(r"<!-- template: ([a-z0-9-]+) -->\n```json\n(.*?)```", re.S)

BUCKET = "arn:aws:s3:::<BUCKET>"
RESTORE = "arn:aws:s3:::<RESTORE_BUCKET>"
BACKUP_ROLE = "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-backup-service"
RESTORE_ROLE = "arn:aws:iam::<ACCOUNT>:role/nlw-<ENV>-dataset-restore"
ADMIN_ROLE = "arn:aws:iam::<ACCOUNT>:role/<ADMIN_ROLE>"
VIA_S3 = {"kms:ViaService": "s3.us-east-1.amazonaws.com"}


def _strict(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    assert len(keys) == len(set(keys)), f"duplicate JSON keys {keys}"
    return dict(pairs)


def templates(path: Path = RUNBOOK) -> dict[str, Any]:
    found = TEMPLATE.findall(path.read_text())
    names = [n for n, _ in found]
    assert len(names) == len(set(names)), names
    return {n: json.loads(raw, object_pairs_hook=_strict) for n, raw in found}


def sids(doc: dict[str, Any] | list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    statements = doc if isinstance(doc, list) else doc["Statement"]
    return {s["Sid"]: s for s in statements}


def as_set(v: str | list[str]) -> set[str]:
    return {v} if isinstance(v, str) else set(v)


def allows(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for s in doc["Statement"] if s["Effect"] == "Allow"]


def test_the_runbook_holds_exactly_the_reviewed_templates() -> None:
    assert sorted(templates()) == [
        "backup-plan",
        "backup-selection",
        "backup-vault-access-policy",
        "backup-vault-lock",
        "dataset-kms-key-o4-statements",
        "restore-bucket-lifecycle",
        "restore-bucket-policy",
        "restore-kms-key-statements",
        "role-backup-service",
        "role-dataset-restore",
        "trust-backup-service",
        "vault-kms-key-statements",
    ]
    # The reviewed D6 and receipt packages are not redefined or extended here.
    assert not set(templates()) & set(templates(PROVISIONING))
    assert not set(templates()) & set(templates(RECEIPTS))


def test_the_d6_key_policy_names_no_o4_role() -> None:
    """KMS refuses a policy naming a role that does not exist, so the D6 proof
    keeps the base key policy and O-4 only appends its own fragment."""
    text = json.dumps(templates(PROVISIONING))
    assert "dataset-backup-service" not in text and "dataset-restore" not in text


def test_recovery_points_are_kept_exactly_the_policy_period() -> None:
    days = retention.OBJECT_BACKUP_RETENTION_DAYS
    t = templates()
    (rule,) = t["backup-plan"]["Rules"]
    assert rule["EnableContinuousBackup"] is True
    assert rule["Lifecycle"] == {"DeleteAfterDays": days}
    assert t["backup-vault-lock"] == {
        "BackupVaultName": "<VAULT>",
        "MinRetentionDays": days,
        "MaxRetentionDays": days,
    }
    # GOVERNANCE for the pilot: no ChangeableForDays (that would be COMPLIANCE).
    assert "ChangeableForDays" not in t["backup-vault-lock"]


def test_only_the_dataset_bucket_is_backed_up_by_the_backup_role() -> None:
    sel = templates()["backup-selection"]
    assert sel["Resources"] == [BUCKET]
    assert sel["IamRoleArn"] == BACKUP_ROLE
    trust = sids(templates()["trust-backup-service"])["AwsBackupThisAccountOnly"]
    assert trust["Principal"] == {"Service": "backup.amazonaws.com"}
    assert trust["Condition"] == {"StringEquals": {"aws:SourceAccount": "<ACCOUNT>"}}


def test_no_one_but_the_administrator_changes_recovery_points() -> None:
    s = sids(templates()["backup-vault-access-policy"])["DenyRecoveryPointChangesExceptAdmin"]
    assert s["Effect"] == "Deny" and s["Principal"] == "*"
    assert {"backup:DeleteRecoveryPoint", "backup:UpdateRecoveryPointLifecycle"} <= as_set(
        s["Action"]
    )
    assert {"backup:DeleteBackupVaultLockConfiguration", "backup:PutBackupVaultAccessPolicy"} <= (
        as_set(s["Action"])
    )
    assert s["Condition"] == {"ArnNotEquals": {"aws:PrincipalArn": ADMIN_ROLE}}


def test_the_backup_role_can_never_change_the_dataset_bucket() -> None:
    doc = templates()["role-backup-service"]
    for s in allows(doc):
        for r in as_set(s["Resource"]):
            if r.startswith(BUCKET):
                assert all(a.startswith(("s3:Get", "s3:List")) for a in as_set(s["Action"])), s
        # Writes only ever target the restore bucket.
        if any(a.startswith(("s3:Put", "s3:Delete")) for a in as_set(s["Action"])):
            assert all(r.startswith(RESTORE) for r in as_set(s["Resource"])), s
        assert not any(a.startswith("s3:Delete") for a in as_set(s["Action"])), s
    deny = sids(doc)["NeverChangeTheDatasetBucket"]
    assert deny["Effect"] == "Deny"
    assert {"s3:PutObject*", "s3:DeleteObject*", "s3:PutBucket*"} <= as_set(deny["Action"])
    assert as_set(deny["Resource"]) == {BUCKET, f"{BUCKET}/*"}


def test_the_restore_role_writes_once_and_never_deletes() -> None:
    doc = templates()["role-dataset-restore"]
    for s in allows(doc):
        assert not any(a.startswith(("s3:Delete", "backup:")) for a in as_set(s["Action"])), s
        assert "s3:*" not in as_set(s["Action"]), s
    write = sids(doc)["WriteOnceIntoTheDatasetBucket"]
    assert as_set(write["Resource"]) == {f"{BUCKET}/versions/*"}
    # Receipts: read and listed only, so restore-objects can confirm every
    # deletion was re-applied; never written.
    s = sids(doc)
    assert s["ReadDeletionReceipts"]["Action"] == "s3:GetObject"
    assert s["ReadDeletionReceipts"]["Resource"] == "arn:aws:s3:::<RECEIPT_BUCKET>/receipts/*"
    assert s["ListDeletionReceipts"]["Condition"] == {"StringLike": {"s3:prefix": ["receipts/*"]}}
    for st in allows(doc):
        if any("<RECEIPT_BUCKET>" in r for r in as_set(st["Resource"])):
            assert as_set(st["Action"]) <= {"s3:GetObject", "s3:ListBucket"}, st
    deny = sids(doc)["NeverDeleteOrReconfigure"]
    assert deny["Effect"] == "Deny" and deny["Resource"] == "*"
    assert {"s3:DeleteObject*", "s3:BypassGovernanceRetention", "backup:*"} <= as_set(
        deny["Action"]
    )


@pytest.mark.parametrize("name", ["role-backup-service", "role-dataset-restore"])
def test_every_key_grant_is_via_s3_and_other_environments_are_denied(name: str) -> None:
    doc = templates()[name]
    for s in allows(doc):
        if any(a.startswith("kms:") for a in as_set(s["Action"])):
            assert s["Condition"] == {"StringEquals": VIA_S3}, s
    other = sids(doc)["NeverOtherEnvironment"]
    assert other["Effect"] == "Deny"
    assert as_set(other["Resource"]) == {
        "arn:aws:s3:::nlw-<OTHER_ENV>-*",
        "arn:aws:s3:::nlw-<OTHER_ENV>-*/*",
    }


def test_the_key_fragment_admits_exactly_the_two_o4_roles() -> None:
    frag = sids(templates()["dataset-kms-key-o4-statements"])
    assert {k: v["Principal"] for k, v in frag.items()} == {
        "BackupDecryptsViaS3ForThisBucketOnly": {"AWS": BACKUP_ROLE},
        "RestorerWritesViaS3ForThisBucketOnly": {"AWS": RESTORE_ROLE},
    }
    assert frag["BackupDecryptsViaS3ForThisBucketOnly"]["Action"] == "kms:Decrypt"
    assert as_set(frag["RestorerWritesViaS3ForThisBucketOnly"]["Action"]) == {
        "kms:GenerateDataKey",
        "kms:Decrypt",
    }
    for s in frag.values():
        assert s["Effect"] == "Allow"
        assert s["Condition"] == {
            "StringEquals": {**VIA_S3, "kms:EncryptionContext:aws:s3:arn": BUCKET}
        }


def test_only_the_backup_service_writes_and_only_the_restorer_reads_restored_copies() -> None:
    s = sids(templates()["restore-bucket-policy"])
    assert list(s) == [
        "DenyNonTLS",
        "DenyOutsideAccount",
        "DenyOtherEnvironmentRoles",
        "DenyWritesExceptBackupService",
        "DenyReadsExceptRestorer",
        "DenyBucketConfigExceptAdmin",
    ]
    assert all(v["Effect"] == "Deny" and v["Principal"] == "*" for v in s.values())
    assert s["DenyWritesExceptBackupService"]["Condition"] == {
        "ArnNotEquals": {"aws:PrincipalArn": BACKUP_ROLE}
    }
    assert s["DenyReadsExceptRestorer"]["Condition"] == {
        "ArnNotEquals": {"aws:PrincipalArn": RESTORE_ROLE}
    }
    assert s["DenyBucketConfigExceptAdmin"]["Condition"] == {
        "ArnNotEquals": {"aws:PrincipalArn": ADMIN_ROLE}
    }


def test_restored_copies_expire_after_the_policy_period() -> None:
    (rule,) = templates()["restore-bucket-lifecycle"]["Rules"]
    assert rule["Status"] == "Enabled" and rule["Filter"] == {"Prefix": ""}
    assert rule["Expiration"] == {"Days": retention.RESTORE_COPY_EXPIRY_DAYS}
    assert rule["NoncurrentVersionExpiration"] == {"NoncurrentDays": 1}
    assert rule["AbortIncompleteMultipartUpload"] == {"DaysAfterInitiation": 1}


def test_every_role_is_at_path_root() -> None:
    for arn in re.findall(r"arn:aws:iam::<ACCOUNT>:role/([^\"]+)", json.dumps(templates())):
        assert "/" not in arn, arn
    for flag in re.findall(r"--path\s+([^\s`'\"),;]+)", RUNBOOK.read_text()):
        assert flag == "/", flag


@pytest.mark.parametrize(
    "value",
    [r"\b\d{12}\b", r"arn:aws:iam::\d", r"nlw-(staging|production)-datasets-restore-\d"],
)
def test_no_real_identifier_is_written_down(value: str) -> None:
    assert re.search(value, RUNBOOK.read_text()) is None


# --- F2 (review of PR #68): the vault and restore keys are pinned in full ---------

ADMIN_PRINCIPALS = {"AWS": ["arn:aws:iam::<ACCOUNT>:root", ADMIN_ROLE]}
USE = {"kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:ReEncryptFrom",
       "kms:ReEncryptTo", "kms:CreateGrant", "kms:GenerateDataKeyWithoutPlaintext"}  # fmt: skip


@pytest.mark.parametrize("name", ["vault-kms-key-statements", "restore-kms-key-statements"])
def test_the_administrator_administers_and_never_uses_the_o4_keys(name: str) -> None:
    statements = sids(templates()[name])
    admin = statements["AdministerNeverUse"]
    assert admin["Principal"] == ADMIN_PRINCIPALS
    assert not as_set(admin["Action"]) & USE
    # The administration statement is the dataset key's, byte for byte.
    (d6,) = [
        s
        for s in templates(PROVISIONING)["dataset-kms-key-statements"]
        if s["Sid"] == "AdministerNeverUse"
    ]
    assert admin == d6
    for sid, s in statements.items():
        assert s["Effect"] == "Allow", sid
        if sid != "AdministerNeverUse":
            assert s["Principal"]["AWS"] in (BACKUP_ROLE, RESTORE_ROLE), sid
            assert "kms:ViaService" in json.dumps(s["Condition"]), sid


def test_only_aws_backup_can_use_the_vault_key() -> None:
    s = sids(templates()["vault-kms-key-statements"])
    assert list(s) == [
        "AdministerNeverUse",
        "BackupServiceUsesViaBackupOnly",
        "BackupServiceGrantsForBackupResourcesOnly",
    ]
    via = {"kms:ViaService": "backup.us-east-1.amazonaws.com"}
    assert s["BackupServiceUsesViaBackupOnly"]["Condition"] == {"StringEquals": via}
    assert s["BackupServiceGrantsForBackupResourcesOnly"]["Condition"] == {
        "Bool": {"kms:GrantIsForAWSResource": "true"}, "StringEquals": via,
    }  # fmt: skip
    assert "dataset-restore" not in json.dumps(s)


def test_the_restore_key_serves_the_restore_bucket_only() -> None:
    s = sids(templates()["restore-kms-key-statements"])
    assert list(s) == [
        "AdministerNeverUse",
        "BackupServiceWritesViaS3ForTheRestoreBucketOnly",
        "RestorerReadsViaS3ForTheRestoreBucketOnly",
    ]
    context = {**VIA_S3, "kms:EncryptionContext:aws:s3:arn": RESTORE}
    write = s["BackupServiceWritesViaS3ForTheRestoreBucketOnly"]
    read = s["RestorerReadsViaS3ForTheRestoreBucketOnly"]
    assert (write["Principal"], as_set(write["Action"])) == (
        {"AWS": BACKUP_ROLE}, {"kms:GenerateDataKey", "kms:Decrypt"},
    )  # fmt: skip
    assert (read["Principal"], read["Action"]) == ({"AWS": RESTORE_ROLE}, "kms:Decrypt")
    assert write["Condition"] == read["Condition"] == {"StringEquals": context}


# --- F4: restore-objects relies on the restore bucket's single writer -------------


def test_the_restore_bucket_has_exactly_one_writer_for_restore_objects() -> None:
    s = sids(templates()["restore-bucket-policy"])["DenyWritesExceptBackupService"]
    assert s == {
        "Sid": "DenyWritesExceptBackupService", "Effect": "Deny", "Principal": "*",
        "Action": "s3:PutObject", "Resource": f"{RESTORE}/*",
        "Condition": {"ArnNotEquals": {"aws:PrincipalArn": BACKUP_ROLE}},
    }  # fmt: skip
    restorer = templates()["role-dataset-restore"]
    for st in allows(restorer):
        if any(r.startswith(RESTORE) for r in as_set(st["Resource"])):
            assert not any(a.startswith(("s3:Put", "s3:Delete")) for a in as_set(st["Action"]))


# --- F1: the residual risk is recorded, not hidden ----------------------------------


def test_the_resurrection_risk_and_its_controls_are_documented() -> None:
    text = RUNBOOK.read_text()
    risks = text[text.index("## 9. Residual risks") :]
    for phrase in ("recreate a purged key", "declared recovery", "CloudTrail data event",
                   "MaxSessionDuration"):  # fmt: skip
        assert phrase in risks, phrase
    checklist = (ROOT / "docs/runbooks/dataset-uploads-staging-checklist.md").read_text()
    assert "object-backup vault lock (O-4) use COMPLIANCE" in checklist
