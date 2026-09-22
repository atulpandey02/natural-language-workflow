"""Alerting evidence and the null-receiver boundary (M12A-Prep §E).

Three things are deliberately kept apart:

* **rules loaded** — Prometheus reports the expected rule groups;
* **Alertmanager reachable** — the internal Alertmanager answers health checks
  and Prometheus lists it as an active alertmanager;
* **delivery verified** — a real (non-null) receiver with a mounted credential
  delivered a controlled test alert, confirmed by an operator record.

A healthy Alertmanager container proves nothing about delivery. The committed
config ships a ``null`` receiver: fine for the local rehearsal, never evidence
for staging/production. ``reopen`` may still complete a staging TECHNICAL
deployment with the null receiver, but only while recording the launch gate
"alert delivery unverified"; an M12 GO check rejects it outright.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import yaml

from nlw.ops.rollout.gates import GateError

NULL_RECEIVER = "null"
EXPECTED_RULE_GROUPS = frozenset({"nlw-backup", "nlw-signed-context"})
LAUNCH_GATE_ALERT_DELIVERY = "alert delivery unverified"
_CRED_FILE_KEYS = (
    "api_url_file",
    "routing_key_file",
    "service_key_file",
    "auth_password_file",
    "auth_secret_file",
    "url_file",
    "bot_token_file",
)


@dataclass(frozen=True)
class ReceiverConfig:
    name: str
    integrations: int
    credential_files: tuple[str, ...]


def parse_alertmanager_config(text: str) -> tuple[str, dict[str, ReceiverConfig]]:
    """(default receiver name, receivers) from an alertmanager.yml. Inline
    secrets are refused outright — credentials must be ``*_file`` references."""
    doc = yaml.safe_load(text) or {}
    receivers: dict[str, ReceiverConfig] = {}
    for r in doc.get("receivers") or []:
        name = str(r.get("name"))
        integrations = 0
        files: list[str] = []
        for key, value in r.items():
            if key == "name" or not isinstance(value, list):
                continue
            integrations += len(value)
            for cfg in value:
                if not isinstance(cfg, dict):
                    continue
                for k, v in cfg.items():
                    if k in _CRED_FILE_KEYS and isinstance(v, str):
                        files.append(v)
                    if k in ("api_url", "routing_key", "service_key", "auth_password", "bot_token"):
                        raise GateError(f"receiver {name!r} carries an inline credential ({k})")
        receivers[name] = ReceiverConfig(name, integrations, tuple(files))
    default = str((doc.get("route") or {}).get("receiver", ""))
    if not default or default not in receivers:
        raise GateError("alertmanager route.receiver must name a configured receiver")
    return default, receivers


@dataclass(frozen=True)
class AlertingStatus:
    rules_loaded: bool
    rule_groups: tuple[str, ...]
    alertmanager_reachable: bool
    receiver: str
    receiver_is_null: bool
    credential_files_present: bool
    delivery_verified: bool
    delivery_record: dict[str, Any] = field(default_factory=dict)

    def evidence(self) -> dict[str, Any]:
        return {
            "rules_loaded": self.rules_loaded,
            "rule_groups": list(self.rule_groups),
            "alertmanager_reachable": self.alertmanager_reachable,
            "receiver": self.receiver,
            "receiver_is_null": self.receiver_is_null,
            "credential_files_present": self.credential_files_present,
            "delivery_verified": self.delivery_verified,
        }


def parse_rule_groups(rules_json: dict[str, Any]) -> tuple[str, ...]:
    groups = (rules_json.get("data") or {}).get("groups") or []
    return tuple(sorted(str(g.get("name")) for g in groups if isinstance(g, dict)))


def build_status(
    *,
    rule_groups: tuple[str, ...],
    alertmanager_reachable: bool,
    default_receiver: str,
    receivers: dict[str, ReceiverConfig],
    present_files: set[str],
    delivery_record: dict[str, Any] | None,
    now: datetime,
) -> AlertingStatus:
    """Derive the three-way status. ``delivery_record`` is an operator-written
    confirmation of a controlled test alert; it only counts when it names the
    configured non-null receiver, is recent, and that receiver has all of its
    credential files present."""
    recv = receivers[default_receiver]
    is_null = recv.integrations == 0 or default_receiver == NULL_RECEIVER
    creds_ok = bool(recv.credential_files) and all(
        f in present_files for f in recv.credential_files
    )
    verified = False
    if delivery_record and not is_null and creds_ok:
        try:
            at = datetime.fromisoformat(
                str(delivery_record.get("delivered_at", "")).replace("Z", "+00:00")
            )
        except ValueError:
            at = None
        verified = (
            delivery_record.get("receiver") == default_receiver
            and bool(delivery_record.get("confirmed_by"))
            and at is not None
            and at.tzinfo is not None
            and now - at.astimezone(UTC) <= timedelta(days=7)
        )
    return AlertingStatus(
        rules_loaded=set(rule_groups) >= EXPECTED_RULE_GROUPS,
        rule_groups=rule_groups,
        alertmanager_reachable=alertmanager_reachable,
        receiver=default_receiver,
        receiver_is_null=is_null,
        credential_files_present=creds_ok,
        delivery_verified=verified,
        delivery_record=dict(delivery_record or {}),
    )


def check_rules_and_connectivity(status: AlertingStatus) -> None:
    """Required for EVERY environment before reopen (rules + connectivity only)."""
    if not status.rules_loaded:
        raise GateError(
            f"prometheus rule groups loaded: {list(status.rule_groups)}, "
            f"want {sorted(EXPECTED_RULE_GROUPS)}"
        )
    if not status.alertmanager_reachable:
        raise GateError("Alertmanager is not reachable from Prometheus")


def launch_gates_for(status: AlertingStatus, *, environment: str) -> list[str]:
    """Open launch gates a technical deployment must RECORD (never hide).

    The null receiver is acceptable for FINISHING a local rehearsal, and a
    staging technical deployment may reopen traffic with it — but in both cases
    this gate stays open and recorded (``environment`` comes from the release
    manifest, never from the executor), so no report can present a null or
    unverified pipeline as "alert delivery configured". Only a verified real
    delivery (``delivery_verified``) closes it."""
    if environment in ("staging", "production") and not status.delivery_verified:
        return [LAUNCH_GATE_ALERT_DELIVERY]
    return []


def check_go(status: AlertingStatus, *, environment: str) -> None:
    """The M12 GO decision: staging/production require a real, credentialed
    receiver whose delivery was verified. A healthy null pipeline is a NO-GO."""
    check_rules_and_connectivity(status)
    if environment in ("staging", "production"):
        if status.receiver_is_null:
            raise GateError("alert delivery: the null receiver is configured — NO-GO")
        if not status.credential_files_present:
            raise GateError("alert delivery: receiver credential file(s) missing — NO-GO")
        if not status.delivery_verified:
            raise GateError("alert delivery: no verified controlled test alert on record — NO-GO")


def receiver_from_config(config_text: str) -> tuple[str, dict[str, ReceiverConfig]]:
    return parse_alertmanager_config(config_text)


_CONFIG_RE = re.compile(r"receivers:", re.M)


def looks_like_alertmanager_config(text: str) -> bool:
    return bool(_CONFIG_RE.search(text))
