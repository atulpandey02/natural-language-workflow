"""Alertmanager null-receiver boundary (M12A-Prep §E)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from nlw.ops.rollout import alerting
from nlw.ops.rollout.gates import GateError

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
NULL_CFG = (ROOT / "docker/alertmanager/alertmanager.yml").read_text()
REAL_CFG = """
route:
  receiver: ops-pager
receivers:
  - name: "null"
  - name: ops-pager
    pagerduty_configs:
      - routing_key_file: /etc/alertmanager/secrets/pagerduty.key
"""
GROUPS = ("nlw-backup", "nlw-signed-context")


def _status(
    cfg: str,
    *,
    present: set[str] | None = None,
    record: dict[str, object] | None = None,
    groups: tuple[str, ...] = GROUPS,
    reachable: bool = True,
) -> alerting.AlertingStatus:
    default, receivers = alerting.parse_alertmanager_config(cfg)
    return alerting.build_status(
        rule_groups=groups,
        alertmanager_reachable=reachable,
        default_receiver=default,
        receivers=receivers,
        present_files=present or set(),
        delivery_record=record,
        now=NOW,
    )


def test_committed_config_is_null_receiver_and_never_delivery_evidence() -> None:
    st = _status(NULL_CFG)
    assert st.receiver_is_null and not st.delivery_verified and st.rules_loaded
    # Connectivity is fine; delivery is not: the two are distinct facts.
    alerting.check_rules_and_connectivity(st)
    ev = st.evidence()
    assert ev["alertmanager_reachable"] is True and ev["delivery_verified"] is False


def test_local_rehearsal_may_finish_on_null_receiver_but_the_gate_stays_recorded() -> None:
    # The rehearsal mirrors a staging manifest: it completes (reopen never raises on
    # delivery), yet the very same open gate is recorded — the executor being local
    # changes nothing about what the null receiver proves.
    st = _status(NULL_CFG)
    assert alerting.launch_gates_for(st, environment="staging") == [
        alerting.LAUNCH_GATE_ALERT_DELIVERY
    ]
    alerting.check_rules_and_connectivity(st)  # rehearsal may proceed to reopen


def test_staging_reopen_records_open_gate_and_go_rejects_null() -> None:
    st = _status(NULL_CFG)
    assert alerting.launch_gates_for(st, environment="staging") == [
        alerting.LAUNCH_GATE_ALERT_DELIVERY
    ]
    with pytest.raises(GateError, match="null receiver"):
        alerting.check_go(st, environment="staging")
    with pytest.raises(GateError, match="null receiver"):
        alerting.check_go(st, environment="production")


def test_absent_receiver_credentials_fail_the_delivery_gate() -> None:
    st = _status(REAL_CFG, present=set())
    assert not st.credential_files_present and not st.delivery_verified
    with pytest.raises(GateError, match="credential file"):
        alerting.check_go(st, environment="staging")


def test_synthetic_alert_to_null_receiver_does_not_verify_delivery() -> None:
    record: dict[str, object] = {
        "receiver": "null",
        "delivered_at": NOW.isoformat(),
        "confirmed_by": "ops",
    }
    st = _status(NULL_CFG, record=record)
    assert not st.delivery_verified
    with pytest.raises(GateError):
        alerting.check_go(st, environment="staging")


def test_real_receiver_with_credentials_and_confirmed_test_passes_go() -> None:
    record: dict[str, object] = {
        "receiver": "ops-pager",
        "delivered_at": (NOW - timedelta(hours=1)).isoformat(),
        "confirmed_by": "ops-lead",
    }
    st = _status(REAL_CFG, present={"/etc/alertmanager/secrets/pagerduty.key"}, record=record)
    assert st.delivery_verified and not st.receiver_is_null
    alerting.check_go(st, environment="production")
    assert alerting.launch_gates_for(st, environment="production") == []
    # A stale confirmation (8 days) or the wrong receiver does not count.
    stale = dict(record, delivered_at=(NOW - timedelta(days=8)).isoformat())
    assert not _status(
        REAL_CFG, present={"/etc/alertmanager/secrets/pagerduty.key"}, record=stale
    ).delivery_verified
    wrong = dict(record, receiver="null")
    assert not _status(
        REAL_CFG, present={"/etc/alertmanager/secrets/pagerduty.key"}, record=wrong
    ).delivery_verified


def test_inline_credentials_are_refused_and_rules_connectivity_gate() -> None:
    with pytest.raises(GateError, match="inline credential"):
        alerting.parse_alertmanager_config(
            "route:\n  receiver: s\nreceivers:\n  - name: s\n    slack_configs:\n      - api_url: https://hooks.example/x\n"
        )
    with pytest.raises(GateError, match="rule groups"):
        alerting.check_rules_and_connectivity(_status(NULL_CFG, groups=("nlw-backup",)))
    with pytest.raises(GateError, match="not reachable"):
        alerting.check_rules_and_connectivity(_status(NULL_CFG, reachable=False))
