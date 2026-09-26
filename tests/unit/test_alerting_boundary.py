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


# --- post-rollout hotfix: operator authority + effective (running) configuration -------
from nlw.ops.rollout.keyfiles import parse_stat_line  # noqa: E402

OPERATOR_CFG = """
route:
  receiver: ops-slack
receivers:
  - name: "null"
  - name: ops-slack
    slack_configs:
      - api_url_file: /etc/alertmanager/secrets/slack.url
"""
EXAMPLE_OVERRIDE = ROOT / "deploy/staging/docker-compose.operator.example.yml"
EXAMPLE_CFG = ROOT / "deploy/staging/alertmanager.operator.example.yml"


def test_operator_config_refuses_null_inline_and_foreign_credential_paths() -> None:
    default, receivers = alerting.check_operator_config(OPERATOR_CFG)
    assert default == "ops-slack"
    assert alerting.credential_host_paths(receivers, default, "/opt/nlw/alertmanager.secrets") == {
        "/etc/alertmanager/secrets/slack.url": "/opt/nlw/alertmanager.secrets/slack.url"
    }
    with pytest.raises(GateError, match="null receiver"):
        alerting.check_operator_config(NULL_CFG)
    with pytest.raises(GateError, match="inline credential"):
        alerting.check_operator_config(
            OPERATOR_CFG.replace(
                "api_url_file: /etc/alertmanager/secrets/slack.url",
                "api_url: https://hooks.example.invalid/x",
            )
        )
    for bad in (
        "/etc/alertmanager/alertmanager.yml",
        "/etc/alertmanager/secrets/../alertmanager.yml",
        "/run/secrets/x",
    ):
        with pytest.raises(GateError, match="secrets mount"):
            alerting.check_operator_config(
                OPERATOR_CFG.replace("/etc/alertmanager/secrets/slack.url", bad)
            )
    with pytest.raises(GateError, match="no credential file"):
        alerting.check_operator_config(
            "route:\n  receiver: w\nreceivers:\n  - name: w\n    webhook_configs:\n      - url: http://x.invalid/\n"
        )
    # The committed example is a valid operator config (never committed as authority).
    assert alerting.check_operator_config(EXAMPLE_CFG.read_text())[0] == "ops-slack"


def test_override_may_only_add_the_two_alertmanager_mounts() -> None:
    doc = yaml_load(EXAMPLE_OVERRIDE.read_text())
    mounts = alerting.override_alertmanager_mounts(doc)
    alerting.check_override_mounts(
        mounts,
        config_path="/opt/nlw/alertmanager/alertmanager.yml",
        secrets_dir="/opt/nlw/alertmanager.secrets",
        what="override",
    )
    with pytest.raises(GateError, match="mount disagreement"):
        alerting.check_override_mounts(
            mounts,
            config_path="/opt/nlw/releases/x/docker/alertmanager/alertmanager.yml",
            secrets_dir="/opt/nlw/alertmanager.secrets",
            what="override",
        )
    rw = {
        "/etc/alertmanager/alertmanager.yml": ("/opt/nlw/alertmanager/alertmanager.yml", False),
        "/etc/alertmanager/secrets": ("/opt/nlw/alertmanager.secrets", True),
    }
    with pytest.raises(GateError, match="read-only"):
        alerting.check_override_mounts(
            rw,
            config_path="/opt/nlw/alertmanager/alertmanager.yml",
            secrets_dir="/opt/nlw/alertmanager.secrets",
            what="override",
        )
    with pytest.raises(GateError, match="does not mount"):
        alerting.check_override_mounts({}, config_path="/a", secrets_dir="/b", what="override")
    # Not a general hook: other services or other keys are refused.
    with pytest.raises(GateError, match="ONLY the alertmanager service"):
        alerting.override_alertmanager_mounts(
            {
                "services": {
                    "alertmanager": {"volumes": []},
                    "api": {"volumes": ["/x:/run/nlw/keys/api.key"]},
                }
            }
        )
    with pytest.raises(GateError, match="only add alertmanager volumes"):
        alerting.override_alertmanager_mounts(
            {"services": {"alertmanager": {"image": "evil", "volumes": []}}}
        )
    with pytest.raises(GateError, match="must define services.alertmanager"):
        alerting.override_alertmanager_mounts({"services": {}})
    # Long syntax is understood too.
    long = {
        "services": {
            "alertmanager": {
                "volumes": [
                    {
                        "type": "bind",
                        "source": "/a",
                        "target": "/etc/alertmanager/alertmanager.yml",
                        "read_only": True,
                    }
                ]
            }
        }
    }
    assert alerting.override_alertmanager_mounts(long) == {
        "/etc/alertmanager/alertmanager.yml": ("/a", True)
    }


def test_loaded_configuration_must_match_the_mounted_file() -> None:
    default, receivers = alerting.parse_alertmanager_config(OPERATOR_CFG)
    alerting.check_loaded_matches_mounted(OPERATOR_CFG, default=default, receivers=receivers)
    with pytest.raises(GateError, match="does not match"):
        alerting.check_loaded_matches_mounted(NULL_CFG, default=default, receivers=receivers)
    other = OPERATOR_CFG.replace("slack.url", "other.url")
    with pytest.raises(GateError, match="does not match"):
        alerting.check_loaded_matches_mounted(other, default=default, receivers=receivers)
    with pytest.raises(GateError, match="rejected|unparseable"):
        alerting.check_loaded_matches_mounted("not: [valid", default=default, receivers=receivers)


def test_delivery_record_classification_and_status_words() -> None:
    assert alerting.classify_delivery_record("__ABSENT__") == (None, None)
    assert alerting.classify_delivery_record("__UNREADABLE__") == (None, "unreadable")
    assert alerting.classify_delivery_record('__OK__\n{"receiver": "ops"}') == (
        {"receiver": "ops"},
        None,
    )
    assert alerting.classify_delivery_record("__OK__\n[1]") == (None, "malformed")
    assert alerting.classify_delivery_record("__OK__\n{oops") == (None, "malformed")
    assert alerting.classify_delivery_record("garbage") == (None, "malformed")
    good: dict[str, object] = {
        "receiver": "ops-pager",
        "delivered_at": (NOW - timedelta(hours=1)).isoformat(),
        "confirmed_by": "ops",
    }
    st = _status(REAL_CFG, present={"/etc/alertmanager/secrets/pagerduty.key"}, record=good)
    assert st.delivery_status == "verified" and st.delivery_verified
    for over, word in (
        ({"receiver": "null"}, "receiver-mismatch"),
        ({"confirmed_by": " "}, "unconfirmed"),
        ({"delivered_at": (NOW - timedelta(days=8)).isoformat()}, "stale"),
        ({"delivered_at": (NOW + timedelta(days=1)).isoformat()}, "stale"),  # from the future
        ({"delivered_at": "yesterday"}, "stale"),
    ):
        st = _status(
            REAL_CFG, present={"/etc/alertmanager/secrets/pagerduty.key"}, record={**good, **over}
        )
        assert st.delivery_status == word and not st.delivery_verified, over
        with pytest.raises(GateError, match=word):
            alerting.check_go(st, environment="staging")
    assert _status(REAL_CFG, present=set(), record=good).delivery_status == "credentials-missing"
    assert _status(NULL_CFG, record=good).delivery_status == "null-receiver"
    # A present-but-unusable record stops reopen/go-check outright.
    default, receivers = alerting.parse_alertmanager_config(REAL_CFG)
    for problem, msg in (("unreadable", "not readable"), ("malformed", "malformed")):
        st = alerting.build_status(
            rule_groups=GROUPS,
            alertmanager_reachable=True,
            default_receiver=default,
            receivers=receivers,
            present_files={"/etc/alertmanager/secrets/pagerduty.key"},
            delivery_record=None,
            now=NOW,
            record_problem=problem,
        )
        with pytest.raises(GateError, match=msg):
            alerting.check_delivery_record_usable(st)
        with pytest.raises(GateError, match=msg):
            alerting.check_go(st, environment="production")


@pytest.mark.parametrize(
    "line, check, msg",
    [
        ("slack.url|regular file|640|0|65534|80", "cred", None),
        ("slack.url|regular file|644|0|65534|80", "cred", "world-readable"),
        (
            "slack.url|regular file|660|0|65534|80",
            "cred",
            None,
        ),  # not world-readable; readability proven as 65534 elsewhere
        ("slack.url|regular file|640|0|65534|0", "cred", "empty"),
        ("slack.url|symbolic link|777|0|0|10", "cred", "regular file"),
        (".|directory|750|0|65534|4096", "dir", None),
        (".|directory|755|0|65534|4096", "dir", "world"),
        (
            ".|directory|700|0|0|4096",
            "dir",
            None,
        ),  # not world-accessible; 65534 readability decides
        ("f|regular file|644|0|0|100", "cfg", None),
        ("f|regular file|664|0|0|100", "cfg", "writable"),
        ("f|regular file|646|0|0|100", "cfg", "writable"),
        ("f|regular file|644|1000|0|100", "cfg", "owned by root"),
        ("f|directory|755|0|0|100", "cfg", "regular file"),
    ],
)
def test_permission_matrix(line: str, check: str, msg: str | None) -> None:
    st = parse_stat_line(line)
    fn = {
        "cred": alerting.check_credential_file_stat,
        "dir": alerting.check_secrets_dir_stat,
        "cfg": alerting.check_config_file_stat,
    }[check]
    if msg is None:
        fn(st, "/x")
    else:
        with pytest.raises(GateError, match=msg):
            fn(st, "/x")


def yaml_load(text: str) -> object:
    import yaml

    return yaml.safe_load(text)
