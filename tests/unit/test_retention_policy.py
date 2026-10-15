"""The O-5 retention policy (ADR-035) is pinned: every value, every lifecycle
document, the Object Lock mode, the backup retention, the alert thresholds,
and the deadline arithmetic at each boundary."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from nlw.backup.config import BackupSettings
from nlw.backup.restic import Restic
from nlw.core import retention as r

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = re.compile(r"<!-- template: ([a-z0-9-]+) -->\n```json\n(.*?)```", re.S)
PROVISIONING = ROOT / "docs/runbooks/dataset-s3-provisioning.md"
RECEIPTS = ROOT / "docs/runbooks/deletion-receipt-log-provisioning.md"
ADR = ROOT / "docs/adr/ADR-035-phase2-retention-policy.md"
RULES = ROOT / "docker/prometheus/alerts/datasets.rules.yml"


def _templates(path: Path) -> dict[str, Any]:
    return {n: json.loads(b) for n, b in TEMPLATE.findall(path.read_text())}


def test_every_policy_value_is_the_owner_decision() -> None:
    assert (r.REJECTED_PURGE_DAYS, r.INACTIVE_RETENTION_DAYS, r.DELETED_PURGE_DAYS) == (7, 30, 7)
    assert (r.MULTIPART_ABORT_DAYS, r.NONCURRENT_RETENTION_DAYS) == (1, 30)
    assert (r.RECEIPT_RETENTION_DAYS, r.AUDIT_RETENTION_DAYS) == (365, 365)
    assert (r.RECEIPT_EXPIRY_DAYS, r.AUDIT_EXPIRY_DAYS) == (366, 366)
    assert (r.DB_BACKUP_DAILY, r.DB_BACKUP_WEEKLY, r.DB_BACKUP_MONTHLY) == (30, 0, 12)
    assert r.OBJECT_BACKUP_RETENTION_DAYS == 30
    assert r.PILOT_OBJECT_LOCK_MODE == "GOVERNANCE"
    assert r.CUSTOMER_DATA_OBJECT_LOCK_MODE == "COMPLIANCE"
    assert r.RECEIPT_EXPIRY_WARNING_DAYS == 30 and r.SWEEP_STALE_AFTER_S == 36 * 3600
    kinds = {rule.subject: rule.kind for rule in r.POLICY}
    assert kinds["REJECTED object"] == kinds["logically deleted bytes"] == "target"
    assert kinds["ACTIVE published source"] == kinds["deletion receipt"] == "guarantee"
    assert len(r.POLICY) == 11


# --- deadline arithmetic at every boundary ------------------------------------------

BASE = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
SECOND = timedelta(seconds=1)
RETENTIONS = [
    r.INACTIVE_RETENTION_DAYS,
    r.NONCURRENT_RETENTION_DAYS,
    r.RECEIPT_RETENTION_DAYS,
    r.AUDIT_RETENTION_DAYS,
    r.OBJECT_BACKUP_RETENTION_DAYS,
    r.MULTIPART_ABORT_DAYS,
]
DEADLINES = [r.REJECTED_PURGE_DAYS, r.DELETED_PURGE_DAYS]


@pytest.mark.parametrize("days", RETENTIONS)
def test_a_retention_period_ends_exactly_at_its_length(days: int) -> None:
    end = BASE + timedelta(days=days)
    assert not r.eligible(BASE, end - SECOND, days)
    assert r.eligible(BASE, end, days)
    assert r.eligible(BASE, end + SECOND, days)


@pytest.mark.parametrize("days", DEADLINES)
def test_a_deadline_is_overdue_only_after_it(days: int) -> None:
    end = BASE + timedelta(days=days)
    assert not r.overdue(BASE, end - SECOND, days)
    assert not r.overdue(BASE, end, days)
    assert r.overdue(BASE, end + SECOND, days)


def test_offsets_do_not_change_a_deadline() -> None:
    tokyo = timezone(timedelta(hours=9))
    end = (BASE + timedelta(days=30)).astimezone(tokyo)
    assert r.eligible(BASE, end, 30) and not r.eligible(BASE, end - SECOND, 30)


@pytest.mark.parametrize("naive", ["since", "now"])
def test_timezone_naive_timestamps_are_refused(naive: str) -> None:
    since, now = BASE, BASE + timedelta(days=40)
    if naive == "since":
        since = since.replace(tzinfo=None)
    else:
        now = now.replace(tzinfo=None)
    with pytest.raises(ValueError, match="timezone-aware"):
        r.eligible(since, now, 30)
    with pytest.raises(ValueError, match="timezone-aware"):
        r.overdue(since, now, 7)


# --- lifecycle documents and Object Lock ----------------------------------------------


def test_the_dataset_lifecycle_never_touches_a_current_object() -> None:
    doc = _templates(PROVISIONING)["dataset-bucket-lifecycle"]
    assert doc == {
        "Rules": [
            {
                "ID": "abort-incomplete-multipart",
                "Status": "Enabled",
                "Filter": {"Prefix": "versions/"},
                "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": r.MULTIPART_ABORT_DAYS},
            },
            {
                "ID": "expire-noncurrent-versions",
                "Status": "Enabled",
                "Filter": {"Prefix": "versions/"},
                "NoncurrentVersionExpiration": {"NoncurrentDays": r.NONCURRENT_RETENTION_DAYS},
            },
        ]
    }
    text = json.dumps(doc)
    for forbidden in ('"Expiration"', "Transition", "ExpiredObjectDeleteMarker"):
        assert forbidden not in text, forbidden


def test_receipts_and_audit_events_outlive_their_lock() -> None:
    receipt = _templates(RECEIPTS)["receipt-bucket-lifecycle"]["Rules"]
    assert [x["Expiration"]["Days"] for x in receipt] == [r.RECEIPT_EXPIRY_DAYS]
    assert r.RECEIPT_EXPIRY_DAYS > r.RECEIPT_RETENTION_DAYS
    assert "default retention **GOVERNANCE for 365\n  days**" in RECEIPTS.read_text()
    audit = _templates(PROVISIONING)["audit-bucket-lifecycle"]["Rules"]
    assert [x["Expiration"]["Days"] for x in audit] == ["<AUDIT_EXPIRY_DAYS>"]
    text = PROVISIONING.read_text()
    assert "| `<AUDIT_EXPIRY_DAYS>` | `<AUDIT_RETENTION_DAYS>` + 1," in text
    assert "audit-log retention: **365 days** for the staging and production audit" in text
    assert "with default retention **GOVERNANCE**" in text


def test_customer_data_needs_compliance_and_a_separate_go() -> None:
    for path in (ADR, RECEIPTS, PROVISIONING):
        text = " ".join(path.read_text().split())
        assert "COMPLIANCE" in text and "GO decision" in text, path.name


# --- backups --------------------------------------------------------------------------


def test_backup_retention_defaults_are_the_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("NLW_BACKUP_RETENTION_DAILY", "NLW_BACKUP_RETENTION_WEEKLY",
                "NLW_BACKUP_RETENTION_MONTHLY"):  # fmt: skip
        monkeypatch.delenv(var, raising=False)
    s = BackupSettings(_env_file=None)  # type: ignore[call-arg]
    assert (s.retention_daily, s.retention_weekly, s.retention_monthly) == (30, 0, 12)
    compose = yaml.safe_load((ROOT / "docker-compose.prod.yml").read_text())
    env = next(
        svc["environment"]
        for svc in compose["services"].values()
        if "NLW_BACKUP_RETENTION_DAILY" in (svc.get("environment") or {})
    )
    assert env["NLW_BACKUP_RETENTION_DAILY"] == "${NLW_BACKUP_RETENTION_DAILY:-30}"
    assert env["NLW_BACKUP_RETENTION_WEEKLY"] == "${NLW_BACKUP_RETENTION_WEEKLY:-0}"
    assert env["NLW_BACKUP_RETENTION_MONTHLY"] == "${NLW_BACKUP_RETENTION_MONTHLY:-12}"
    example = (ROOT / ".env.backup.example").read_text()
    for line in ("NLW_BACKUP_RETENTION_DAILY=30", "NLW_BACKUP_RETENTION_WEEKLY=0",
                 "NLW_BACKUP_RETENTION_MONTHLY=12"):  # fmt: skip
        assert line in example.splitlines()


@pytest.mark.parametrize(
    "var, value",
    [
        ("NLW_BACKUP_RETENTION_DAILY", "13"),  # shorter
        ("NLW_BACKUP_RETENTION_DAILY", "731"),  # longer: kept beyond the policy
        ("NLW_BACKUP_RETENTION_WEEKLY", "8"),
        ("NLW_BACKUP_RETENTION_MONTHLY", "6"),
    ],
)
def test_any_other_backup_retention_is_refused_by_name_never_by_value(
    monkeypatch: pytest.MonkeyPatch, var: str, value: str
) -> None:
    monkeypatch.setenv(var, value)
    with pytest.raises(ValidationError) as exc:
        BackupSettings(_env_file=None)  # type: ignore[call-arg]
    messages = " ".join(str(e["msg"]) for e in exc.value.errors())
    assert var in messages and value not in messages


class _Recorder(Restic):
    def __init__(self) -> None:
        self.argv: list[str] = []

    def _restic_checked(self, *args: str, what: str) -> None:  # type: ignore[override]
        self.argv = list(args)


def test_restic_keeps_30_daily_and_12_monthly_with_no_weekly_tier() -> None:
    rec = _Recorder()
    rec.forget_prune(daily=r.DB_BACKUP_DAILY, weekly=r.DB_BACKUP_WEEKLY,
                     monthly=r.DB_BACKUP_MONTHLY)  # fmt: skip
    assert rec.argv == ["forget", "--keep-daily", "30", "--keep-monthly", "12", "--prune"]
    with pytest.raises(ValueError, match="no retention tier"):
        rec.forget_prune(daily=0, weekly=0, monthly=0)
    with pytest.raises(ValueError, match="negative"):
        rec.forget_prune(daily=-1, weekly=0, monthly=12)


# --- alerts and the ADR ----------------------------------------------------------------


def test_alert_thresholds_are_the_policy() -> None:
    rules = {x["alert"]: x for g in yaml.safe_load(RULES.read_text())["groups"] for x in g["rules"]}
    assert rules["NlwDatasetRejectedRetainedTooLong"]["expr"].strip() == (
        f"nlw_dataset_rejected_oldest_age_seconds > {r.REJECTED_PURGE_DAYS * r.DAY_S}"
    )
    assert rules["NlwDatasetInactiveRetainedTooLong"]["expr"].strip() == (
        f"nlw_dataset_inactive_oldest_age_seconds > {r.INACTIVE_RETENTION_DAYS * r.DAY_S}"
    )
    assert rules["NlwDatasetDeletedNotPurged"]["expr"].strip() == (
        f"nlw_dataset_deleting_oldest_unpurged_age_seconds > {r.DELETED_PURGE_DAYS * r.DAY_S}"
    )
    stale = " ".join(rules["NlwDatasetRetentionSweepStale"]["expr"].split())
    assert stale == (
        "(time() - nlw_dataset_retention_sweep_last_success_timestamp_seconds > "
        f"{r.SWEEP_STALE_AFTER_S}) "
        "or absent(nlw_dataset_retention_sweep_last_success_timestamp_seconds)"
    )
    for name in ("NlwDatasetReceiptsUnverified", "NlwDatasetReceiptsExpiringBeforeTombstone",
                 "NlwDatasetRetentionSweepFailed"):  # fmt: skip
        assert name in rules
    # Dormant until O-6.
    prom = yaml.safe_load((ROOT / "docker/prometheus/prometheus.yml").read_text())
    assert "alerts/datasets.rules.yml" not in prom["rule_files"]


def test_the_adr_states_every_period() -> None:
    text = ADR.read_text()
    for needle in ("purge within 7 days", "30 days (from `superseded_at`, else `created_at`)",
                   "| 1 day |", "30 days after it became noncurrent", "| 365 days |",
                   "30 daily, 12 monthly recovery points", "30/0/12",
                   "until deletion is requested"):  # fmt: skip
        assert needle in text, needle
    for rule in r.POLICY:
        assert rule.subject.split(" (")[0].lower() in text.lower(), rule.subject
