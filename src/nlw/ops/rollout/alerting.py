"""Alerting evidence and the null-receiver boundary (M12A-Prep §E).

Three things are deliberately kept apart:

* **rules loaded** — Prometheus reports the expected rule groups;
* **Alertmanager reachable** — the internal Alertmanager answers health checks
  and Prometheus lists it as an active alertmanager;
* **delivery verified** — a real (non-null) receiver with a mounted credential
  delivered a controlled test alert, confirmed by an operator record.

A healthy Alertmanager container proves nothing about delivery. The committed
config ships a ``null`` receiver: fine for the local rehearsal, never evidence
for staging/production. For those environments the receiver configuration is
OPERATOR authority (``remote.OperatorAlerting``): a host-side config file and
credential files mounted through a reviewed Compose override, evaluated from
the RUNNING container (mount sources, mounted bytes, loaded config) — never from
the committed file in a release checkout. ``reopen`` may complete a TECHNICAL
deployment without a verified delivery, but only while recording the launch gate
"alert delivery unverified"; an M12 GO check rejects it outright. A null or
inline-credential operator config is refused, not recorded.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import yaml

from nlw.ops.rollout.gates import GateError
from nlw.ops.rollout.keyfiles import StatLine

NULL_RECEIVER = "null"
EXPECTED_RULE_GROUPS = frozenset({"nlw-backup", "nlw-signed-context"})
LAUNCH_GATE_ALERT_DELIVERY = "alert delivery unverified"
# Where the operator's config and credential files appear INSIDE the container.
CONFIG_MOUNT = "/etc/alertmanager/alertmanager.yml"
SECRETS_MOUNT = "/etc/alertmanager/secrets"
ALERTMANAGER_UID = 65534  # prom/alertmanager runs as nobody (docker-compose.staging.yml)
RECORD_MAX_AGE = timedelta(days=7)
DELIVERY_VERIFIED = "verified"
# Problems that make a PRESENT record unusable and stop reopen/go-check outright.
RECORD_FATAL = frozenset({"unreadable", "malformed"})
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
    # Where the evaluated receiver configuration came from: the RUNNING container
    # ("running-alertmanager") or a committed file ("committed-file", never for
    # staging/production).
    config_source: str = "committed-file"
    # Why delivery is / is not verified (one word; stored as evidence).
    delivery_status: str = "absent"

    def evidence(self) -> dict[str, Any]:
        return {
            "rules_loaded": self.rules_loaded,
            "rule_groups": list(self.rule_groups),
            "alertmanager_reachable": self.alertmanager_reachable,
            "receiver": self.receiver,
            "receiver_is_null": self.receiver_is_null,
            "credential_files_present": self.credential_files_present,
            "delivery_verified": self.delivery_verified,
            "config_source": self.config_source,
            "delivery_status": self.delivery_status,
        }


def parse_rule_groups(rules_json: dict[str, Any]) -> tuple[str, ...]:
    groups = (rules_json.get("data") or {}).get("groups") or []
    return tuple(sorted(str(g.get("name")) for g in groups if isinstance(g, dict)))


def delivery_status_for(
    record: dict[str, Any] | None,
    *,
    default_receiver: str,
    is_null: bool,
    creds_ok: bool,
    now: datetime,
    record_problem: str | None = None,
) -> str:
    """One word for why a controlled-delivery record does (not) verify delivery.
    A record only counts when the receiver is real and credentialed, it names
    that receiver, is confirmed by a human, and carries a timezone-aware
    ``delivered_at`` within ``RECORD_MAX_AGE``."""
    if record_problem:
        return record_problem
    if record is None:
        return "absent"
    if is_null:
        return "null-receiver"
    if not creds_ok:
        return "credentials-missing"
    if record.get("receiver") != default_receiver:
        return "receiver-mismatch"
    if not str(record.get("confirmed_by") or "").strip():
        return "unconfirmed"
    try:
        at = datetime.fromisoformat(str(record.get("delivered_at", "")).replace("Z", "+00:00"))
    except ValueError:
        return "stale"
    if at.tzinfo is None or not (timedelta(0) <= now - at.astimezone(UTC) <= RECORD_MAX_AGE):
        return "stale"
    return DELIVERY_VERIFIED


def build_status(
    *,
    rule_groups: tuple[str, ...],
    alertmanager_reachable: bool,
    default_receiver: str,
    receivers: dict[str, ReceiverConfig],
    present_files: set[str],
    delivery_record: dict[str, Any] | None,
    now: datetime,
    config_source: str = "committed-file",
    record_problem: str | None = None,
) -> AlertingStatus:
    """Derive the three-way status. ``delivery_record`` is an operator-written
    confirmation of a controlled test alert; it only counts when it names the
    configured non-null receiver, is recent, and that receiver has all of its
    credential files present (see ``delivery_status_for``)."""
    recv = receivers[default_receiver]
    is_null = recv.integrations == 0 or default_receiver == NULL_RECEIVER
    creds_ok = bool(recv.credential_files) and all(
        f in present_files for f in recv.credential_files
    )
    status = delivery_status_for(
        delivery_record,
        default_receiver=default_receiver,
        is_null=is_null,
        creds_ok=creds_ok,
        now=now,
        record_problem=record_problem,
    )
    return AlertingStatus(
        rules_loaded=set(rule_groups) >= EXPECTED_RULE_GROUPS,
        rule_groups=rule_groups,
        alertmanager_reachable=alertmanager_reachable,
        receiver=default_receiver,
        receiver_is_null=is_null,
        credential_files_present=creds_ok,
        delivery_verified=status == DELIVERY_VERIFIED,
        delivery_record=dict(delivery_record or {}),
        config_source=config_source,
        delivery_status=status,
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


def check_delivery_record_usable(status: AlertingStatus) -> None:
    """A PRESENT record that cannot be read or parsed is an operator error that
    stops reopen/go-check outright (an absent record merely leaves the gate open)."""
    if status.delivery_status == "unreadable":
        raise GateError(
            "alert delivery record exists but is not readable by the rollout user: "
            "it must be root:<rollout group> 0640 (scripts/ops/record-alert-delivery.sh) — STOP"
        )
    if status.delivery_status == "malformed":
        raise GateError(
            "alert delivery record is malformed (expected a JSON object with receiver, "
            "delivered_at, confirmed_by): fix or remove it — STOP"
        )


def check_go(status: AlertingStatus, *, environment: str) -> None:
    """The M12 GO decision: staging/production require a real, credentialed
    receiver whose delivery was verified. A healthy null pipeline is a NO-GO."""
    check_rules_and_connectivity(status)
    if environment in ("staging", "production"):
        check_delivery_record_usable(status)
        if status.receiver_is_null:
            raise GateError("alert delivery: the null receiver is configured — NO-GO")
        if not status.credential_files_present:
            raise GateError("alert delivery: receiver credential file(s) missing — NO-GO")
        if not status.delivery_verified:
            raise GateError(
                "alert delivery: no verified controlled test alert on record "
                f"(record status: {status.delivery_status}) — NO-GO"
            )


def receiver_from_config(config_text: str) -> tuple[str, dict[str, ReceiverConfig]]:
    return parse_alertmanager_config(config_text)


_CONFIG_RE = re.compile(r"receivers:", re.M)


def looks_like_alertmanager_config(text: str) -> bool:
    return bool(_CONFIG_RE.search(text))


# ---- operator authority: host files, override, running container ----------------------
def check_operator_config(text: str) -> tuple[str, dict[str, ReceiverConfig]]:
    """The operator's alertmanager.yml: a real default receiver whose credentials
    are ``*_file`` references INSIDE the secrets mount. Null is refused (the
    operator file exists precisely to wire a receiver); inline credentials are
    refused by the parser."""
    default, receivers = parse_alertmanager_config(text)
    recv = receivers[default]
    if default == NULL_RECEIVER or recv.integrations == 0:
        raise GateError(
            "operator Alertmanager config routes to the null receiver: wire a real receiver "
            "(docs/ops/alerting.md) — the committed null file is never operator authority"
        )
    if not recv.credential_files:
        raise GateError(
            f"operator receiver {default!r} references no credential file (*_file); "
            "inline credentials are refused and a credential-less receiver cannot deliver"
        )
    for f in recv.credential_files:
        if not f.startswith(SECRETS_MOUNT + "/") or "/../" in f or f.endswith("/"):
            raise GateError(
                f"credential file {f!r} is outside the secrets mount {SECRETS_MOUNT}/: "
                "every receiver credential must live in the operator secrets directory"
            )
    return default, receivers


def credential_host_paths(
    receivers: dict[str, ReceiverConfig], default: str, secrets_dir: str
) -> dict[str, str]:
    """container path -> host path for every credential file of the default receiver."""
    return {
        f: f"{secrets_dir}/{f[len(SECRETS_MOUNT) + 1 :]}"
        for f in receivers[default].credential_files
    }


def override_alertmanager_mounts(doc: Any) -> dict[str, tuple[str, bool]]:
    """destination -> (source, read_only) of the ``alertmanager`` service's volumes
    in a Compose override document (short and long syntax)."""
    services = (doc or {}).get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict) or not isinstance(services.get("alertmanager"), dict):
        raise GateError("operator Compose override must define services.alertmanager")
    if set(services) != {"alertmanager"}:
        raise GateError(
            "operator Compose override may configure ONLY the alertmanager service "
            f"(found {sorted(services)})"
        )
    am = services["alertmanager"]
    extra = set(am) - {"volumes"}
    if extra:
        raise GateError(
            f"operator Compose override may only add alertmanager volumes (found {sorted(extra)})"
        )
    out: dict[str, tuple[str, bool]] = {}
    for v in am.get("volumes") or []:
        if isinstance(v, str):
            parts = v.split(":")
            if len(parts) < 2:
                raise GateError(f"malformed volume entry in operator override: {v!r}")
            out[parts[1]] = (parts[0], len(parts) > 2 and "ro" in parts[2].split(","))
        elif isinstance(v, dict):
            out[str(v.get("target"))] = (str(v.get("source")), bool(v.get("read_only")))
        else:
            raise GateError("malformed volume entry in operator override")
    return out


def check_override_mounts(
    mounts: dict[str, tuple[str, bool]], *, config_path: str, secrets_dir: str, what: str
) -> None:
    """The alertmanager service must mount the operator config and secrets
    directory — from THOSE host paths, read-only. ``what`` names the source of
    ``mounts`` (override file / rendered config / running container)."""
    want = {CONFIG_MOUNT: config_path, SECRETS_MOUNT: secrets_dir}
    for dest, src in want.items():
        got = mounts.get(dest)
        if got is None:
            raise GateError(f"{what}: alertmanager does not mount {dest} (want {src})")
        if got[0].rstrip("/") != src.rstrip("/"):
            raise GateError(
                f"{what}: alertmanager mounts {dest} from {got[0]!r}, not the operator path "
                f"{src!r} — mount disagreement, STOP"
            )
        if not got[1]:
            raise GateError(f"{what}: alertmanager mount {dest} must be read-only")


def check_loaded_matches_mounted(
    loaded_text: str, *, default: str, receivers: dict[str, ReceiverConfig]
) -> None:
    """What Alertmanager LOADED (``/api/v2/status`` ``config.original``) must
    route to the same default receiver with the same credential files as the
    mounted operator file — a stale process or a different file is refused."""
    try:
        got_default, got_receivers = parse_alertmanager_config(loaded_text)
    except GateError as exc:
        raise GateError(f"running Alertmanager loaded configuration rejected: {exc}") from exc
    except Exception as exc:  # yaml errors: the API answered with something else
        raise GateError("running Alertmanager loaded configuration is unparseable") from exc
    want = (default, sorted(receivers[default].credential_files))
    got = (
        got_default,
        sorted(got_receivers.get(got_default, ReceiverConfig("", 0, ())).credential_files),
    )
    if want != got:
        raise GateError(
            f"running Alertmanager loaded configuration (receiver {got_default!r}) does not "
            f"match the mounted operator file (receiver {default!r}): restart/reload it — STOP"
        )


def classify_delivery_record(raw: str) -> tuple[dict[str, Any] | None, str | None]:
    """Parse the sentinel-prefixed read of alert-delivery.json:
    ``__ABSENT__`` / ``__UNREADABLE__`` / ``__OK__\n<json>``. Returns
    (record, problem) where problem is None, 'unreadable' or 'malformed'."""
    text = raw.strip()
    if text == "__ABSENT__" or not text:
        return None, None
    if text.startswith("__UNREADABLE__"):
        return None, "unreadable"
    if not text.startswith("__OK__"):
        return None, "malformed"
    body = text[len("__OK__") :].strip()
    try:
        loaded = json.loads(body)
    except json.JSONDecodeError:
        return None, "malformed"
    if not isinstance(loaded, dict):
        return None, "malformed"
    return loaded, None


# ---- host-side permission model (probed through a root container) ---------------------
# Alertmanager runs as uid 65534. A root:root 0600 credential inside a root:root
# 0700 directory is unreadable to it (reproduced on the pilot host); the working
# least-privilege layout is dir root:65534 0750, credential root:65534 0640, config
# root:root 0644. Nothing may be world-readable; readability is proved separately
# AS uid 65534, so ownership itself is not prescribed here.
def _others(mode: str) -> int:
    return int(mode[-1])


def _group(mode: str) -> int:
    return int(mode[-2])


def check_config_file_stat(st: StatLine, path: str) -> None:
    if st.kind != "regular file":
        raise GateError(f"operator Alertmanager config {path} is not a regular file ({st.kind})")
    if st.uid != 0:
        raise GateError(f"operator Alertmanager config {path} must be owned by root (uid {st.uid})")
    if _group(st.mode) & 2 or _others(st.mode) & 2:
        raise GateError(f"operator Alertmanager config {path} is group/world-writable ({st.mode})")


def check_secrets_dir_stat(st: StatLine, path: str) -> None:
    if st.kind != "directory":
        raise GateError(f"Alertmanager secrets directory {path} is not a directory ({st.kind})")
    if _others(st.mode) != 0:
        raise GateError(
            f"Alertmanager secrets directory {path} has mode {st.mode}: it must not be "
            "world-accessible (want root:65534 0750)"
        )


def check_credential_file_stat(st: StatLine, path: str) -> None:
    if st.kind != "regular file":
        raise GateError(
            f"credential file {path} is not a regular file ({st.kind}); symlinks rejected"
        )
    if _others(st.mode) != 0:
        raise GateError(
            f"credential file {path} has mode {st.mode}: it must not be world-readable "
            "(want root:65534 0640)"
        )
    if st.size == 0:
        raise GateError(f"credential file {path} is empty")
