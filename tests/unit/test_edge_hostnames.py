"""Reviewed public-edge hostnames: one primary (the attested manifest) + at most one
sslip.io fallback (the reviewed target), bound to the instance and served ONLY by
Caddy. Pure gates, strict target parsing and the real rendered Compose scope; no
network, no host, no DNS (resolution is injected in the phase tests)."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from nlw.ops import release_manifest as rm
from nlw.ops.rollout import gates
from nlw.ops.rollout.gates import GateError
from nlw.ops.rollout.remote import AMBIENT_UNSET, TargetConfigError, load_target, parse_target_env

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "deploy/staging/target.env"
PRIMARY = "app.nlwplatform.com"
FALLBACK = "32-197-83-193.sslip.io"
IP = "32.197.83.193"
REL = rm.parse_manifest(
    {
        "format_version": 2,
        "kind": "release",
        "deployable": True,
        "generated_by": "ci",
        "created_at": "2026-09-27T10:00:00+00:00",
        "release_sha": "a" * 40,
        "backend_image": f"ghcr.io/o/r@sha256:{'a' * 64}",
        "web_image": f"ghcr.io/o/r/web@sha256:{'b' * 64}",
        "expected_current_revision": "0021_analytics_handoff",
        "target_revision": "0021_analytics_handoff",
        "environment": "staging",
        "instance_id": "i-0d1e65cdc9401dbb9",
        "region": "us-east-1",
        "compose_project": "app",
        "public_hostname": PRIMARY,
        "key_ids": {"api": "stg-api-1", "worker": "stg-worker-1", "scheduler": "stg-sched-1"},
        "ci": {"workflow": "Delivery", "run_id": "1", "run_url": "https://x/1"},
    }
)
BAD_HOSTNAMES = [
    "",
    "https://app.nlwplatform.com",
    "app.nlwplatform.com:443",
    "app.nlwplatform.com/login",
    "*.nlwplatform.com",
    "App.NLWplatform.com",
    "app.nlwplatform.com.",
    "app nlwplatform.com",
    '"app.nlwplatform.com"',
    "localhost",
    "-app.nlwplatform.com",
    "app..nlwplatform.com",
    f"{'a' * 64}.nlwplatform.com",
    "app.nlwplatform.com,evil.example",
]


# --- canonical hostnames / sslip decoding --------------------------------------
@pytest.mark.parametrize("value", [PRIMARY, FALLBACK, "rehearsal.localhost", "a.b"])
def test_canonical_hostnames_are_accepted(value: str) -> None:
    assert gates.hostname_problem(value) is None


@pytest.mark.parametrize("value", BAD_HOSTNAMES)
def test_non_canonical_hostnames_are_rejected(value: str) -> None:
    assert gates.hostname_problem(value) is not None


@pytest.mark.parametrize(
    "host,ip",
    [
        (FALLBACK, IP),
        ("0-0-0-0.sslip.io", "0.0.0.0"),
        ("32-197-83-193.sslip.io.evil.example", None),
        ("032-197-83-193.sslip.io", None),  # leading zero: not the canonical encoding
        ("32-197-83-256.sslip.io", None),
        ("32.197.83.193.sslip.io", None),
        ("32-197-83.sslip.io", None),
        (PRIMARY, None),
    ],
)
def test_sslip_decoding_is_canonical_only(host: str, ip: str | None) -> None:
    assert gates.sslip_ipv4(host) == ip


# --- reviewed target parsing -----------------------------------------------------
def _target_with(**changes: str | None) -> str:
    text = TARGET.read_text()
    for key, value in changes.items():
        line = re.compile(rf"^{key}=.*$", re.M)
        text = line.sub("" if value is None else f"{key}={value}", text)
    return text


def test_committed_target_names_the_reviewed_primary_and_fallback() -> None:
    values = parse_target_env(TARGET.read_text())
    assert values["NLW_STAGING_PUBLIC_HOSTNAME"] == PRIMARY
    assert values["NLW_STAGING_PUBLIC_HOSTNAME_FALLBACK"] == FALLBACK
    assert values["NLW_STAGING_CURRENT_REVISION"] == "0023_plan_outcome_events"
    target = load_target(TARGET)
    assert (target.public_hostname, target.public_hostname_fallback) == (PRIMARY, FALLBACK)


@pytest.mark.parametrize(
    "key", ["NLW_STAGING_PUBLIC_HOSTNAME", "NLW_STAGING_PUBLIC_HOSTNAME_FALLBACK"]
)
@pytest.mark.parametrize("value", BAD_HOSTNAMES + [" app.nlwplatform.com", "app.nlwplatform.com "])
def test_target_rejects_malformed_or_url_form_hostnames(key: str, value: str) -> None:
    with pytest.raises(TargetConfigError):
        parse_target_env(_target_with(**{key: value}))


@pytest.mark.parametrize(
    "key", ["NLW_STAGING_PUBLIC_HOSTNAME", "NLW_STAGING_PUBLIC_HOSTNAME_FALLBACK"]
)
def test_target_rejects_duplicate_hostname_keys(key: str) -> None:
    text = TARGET.read_text() + f"\n{key}={FALLBACK if 'FALLBACK' in key else PRIMARY}\n"
    with pytest.raises(TargetConfigError, match="exactly once"):
        parse_target_env(text)


def test_target_requires_a_primary_hostname() -> None:
    with pytest.raises(TargetConfigError, match="NLW_STAGING_PUBLIC_HOSTNAME"):
        parse_target_env(_target_with(NLW_STAGING_PUBLIC_HOSTNAME=None))


@pytest.mark.parametrize(
    "fallback,msg",
    [
        ("status.nlwplatform.com", "sslip"),  # arbitrary extra hostnames are refused
        ("032-197-83-193.sslip.io", "sslip"),
        (PRIMARY, "sslip"),
    ],
)
def test_target_fallback_must_be_a_canonical_sslip_name(fallback: str, msg: str) -> None:
    with pytest.raises(TargetConfigError, match=msg):
        parse_target_env(_target_with(NLW_STAGING_PUBLIC_HOSTNAME_FALLBACK=fallback))


def test_target_fallback_may_not_duplicate_the_primary() -> None:
    text = _target_with(NLW_STAGING_PUBLIC_HOSTNAME=FALLBACK)
    with pytest.raises(TargetConfigError, match="duplicates the primary"):
        parse_target_env(text)


def test_target_without_fallback_is_the_supported_primary_only_shape() -> None:
    target = load_target(TARGET)
    values = parse_target_env(_target_with(NLW_STAGING_PUBLIC_HOSTNAME_FALLBACK=None))
    assert "NLW_STAGING_PUBLIC_HOSTNAME_FALLBACK" not in values
    assert replace(target, public_hostname_fallback=None).public_hostname_fallback is None


# --- instance binding / DNS ------------------------------------------------------
def test_edge_identity_binds_target_primary_and_fallback_to_the_instance() -> None:
    gates.check_edge_identity(IP, REL, target_primary=PRIMARY, fallback=FALLBACK)
    gates.check_edge_identity(IP, REL, target_primary=None, fallback=None)
    with pytest.raises(GateError, match="differs from the attested release"):
        gates.check_edge_identity(IP, REL, target_primary="other.nlwplatform.com", fallback=None)
    with pytest.raises(GateError, match="does not encode the instance public IPv4"):
        gates.check_edge_identity("3.3.3.3", REL, target_primary=PRIMARY, fallback=FALLBACK)
    with pytest.raises(GateError, match="sslip"):
        gates.check_edge_identity(IP, REL, target_primary=PRIMARY, fallback="x.nlwplatform.com")


@pytest.mark.parametrize(
    "resolved,ok",
    [
        ({IP}, True),
        ({"104.16.1.1", IP}, True),  # the instance must be AMONG the A records
        (set(), False),  # missing DNS
        ({"104.16.1.1"}, False),  # wrong IP (e.g. a proxied/stale record)
    ],
)
def test_primary_dns_must_include_the_instance_ipv4(resolved: set[str], ok: bool) -> None:
    if ok:
        gates.check_primary_dns(PRIMARY, IP, resolved)
    else:
        with pytest.raises(GateError, match="A record|resolves to"):
            gates.check_primary_dns(PRIMARY, IP, resolved)


def test_primary_dns_special_names_need_no_lookup_but_stay_bound() -> None:
    gates.check_primary_dns(FALLBACK, IP, set())  # sslip primary: its encoding
    with pytest.raises(GateError, match="does not encode"):
        gates.check_primary_dns(FALLBACK, "3.3.3.3", set())
    gates.check_primary_dns("rehearsal.localhost", "127.0.0.1", set())  # RFC 6761 loopback
    with pytest.raises(GateError, match="loopback rehearsal"):
        gates.check_primary_dns("rehearsal.localhost", IP, set())
    with pytest.raises(GateError, match="public IPv4"):
        gates.check_primary_dns(PRIMARY, "", {IP})


def test_active_hostname_may_be_the_primary_or_the_reviewed_fallback_only() -> None:
    gates.check_active_hostname({"PUBLIC_HOSTNAME": FALLBACK}, REL, FALLBACK)  # the switch
    gates.check_active_hostname({"PUBLIC_HOSTNAME": PRIMARY}, REL, FALLBACK)  # re-run
    for active in ("evil.example", "", None):
        pins: dict[str, str] = {} if active is None else {"PUBLIC_HOSTNAME": active}
        with pytest.raises(GateError, match="unknown edge state"):
            gates.check_active_hostname(pins, REL, FALLBACK)
    with pytest.raises(GateError, match="unknown edge state"):
        gates.check_active_hostname({"PUBLIC_HOSTNAME": FALLBACK}, REL, None)


def test_active_hostname_allows_the_documented_reverse_switch_only() -> None:
    sslip_only = replace(REL, public_hostname=FALLBACK)  # rollback release: sslip primary
    active = {"PUBLIC_HOSTNAME": PRIMARY, "PUBLIC_HOSTNAME_FALLBACK": FALLBACK}
    gates.check_active_hostname(active, sslip_only, None)  # active edge already serves it
    for other_fallback in ("", "1-2-3-4.sslip.io"):
        other = {"PUBLIC_HOSTNAME": PRIMARY, "PUBLIC_HOSTNAME_FALLBACK": other_fallback}
        with pytest.raises(GateError, match="unknown edge state"):
            gates.check_active_hostname(other, sslip_only, None)


# --- staged pins -----------------------------------------------------------------
STAGED = (
    f"NLW_IMAGE={REL.backend_image}\nNLW_WEB_IMAGE={REL.web_image}\n"
    "NLW_CTX_KEYS_DIR=/srv/nlw/ctx-keys\nNLW_CTX_API_KEY_ID=stg-api-1\n"
    "NLW_CTX_WORKER_KEY_ID=stg-worker-1\nNLW_CTX_SCHEDULER_KEY_ID=stg-sched-1\n"
    f"DEMO_TOOLS_ENABLED=true\nPUBLIC_HOSTNAME={PRIMARY}\nPUBLIC_HOSTNAME_FALLBACK={FALLBACK}\n"
)


def _staged_ok(text: str, fallback: str | None = FALLBACK) -> None:
    gates.check_release_pins(
        gates.parse_env_pins(text),
        REL,
        post_pin=True,
        demo_tools_enabled=True,
        public_hostname_fallback=fallback,
    )


def test_canonical_staged_edge_pins_pass() -> None:
    _staged_ok(STAGED)
    _staged_ok(
        STAGED.replace(f"PUBLIC_HOSTNAME_FALLBACK={FALLBACK}", "PUBLIC_HOSTNAME_FALLBACK="), None
    )


@pytest.mark.parametrize(
    "line",
    [
        f"export PUBLIC_HOSTNAME={PRIMARY}",
        f" PUBLIC_HOSTNAME={PRIMARY}",
        f"PUBLIC_HOSTNAME ={PRIMARY}",
        f"PUBLIC_HOSTNAME={PRIMARY}",  # duplicate
        f"PUBLIC_HOSTNAME_FALLBACK={FALLBACK}",  # duplicate
        f"export PUBLIC_HOSTNAME_FALLBACK={FALLBACK}",
        f'PUBLIC_HOSTNAME="{PRIMARY}"',
        "PUBLIC_HOSTNAME=https://app.nlwplatform.com",
        f"PUBLIC_HOSTNAME={PRIMARY} evil.example",
    ],
)
def test_noncanonical_or_duplicate_edge_pins_fail(line: str) -> None:
    with pytest.raises(GateError, match="noncanonical edge-hostname pin; re-run stage-release"):
        gates.parse_env_pins(STAGED + line + "\n")


@pytest.mark.parametrize(
    "text,fallback,msg",
    [
        (STAGED.replace(f"PUBLIC_HOSTNAME={PRIMARY}\n", "PUBLIC_HOSTNAME=x.nlwplatform.com\n"),
         FALLBACK, "does not match the release"),
        (STAGED.replace(f"PUBLIC_HOSTNAME_FALLBACK={FALLBACK}\n", ""),
         FALLBACK, "fallback hostname mismatch"),
        (STAGED, None, "fallback hostname mismatch"),  # target dropped the fallback
        (STAGED.replace(FALLBACK, "1-2-3-4.sslip.io"), FALLBACK, "fallback hostname mismatch"),
    ],
)  # fmt: skip
def test_staged_edge_pins_must_equal_the_reviewed_values(
    text: str, fallback: str | None, msg: str
) -> None:
    with pytest.raises(GateError, match=msg):
        _staged_ok(text, fallback)


# --- adapted Caddy config / running container facts --------------------------------
def _adapted(*route_hosts: list[str]) -> str:
    routes = [{"match": [{"host": hosts}]} for hosts in route_hosts]
    return json.dumps({"apps": {"http": {"servers": {"srv0": {"routes": routes}}}}})


def test_adapted_caddy_hosts_must_be_exactly_the_reviewed_hosts() -> None:
    assert gates.check_adapted_caddy_hosts(_adapted([PRIMARY, FALLBACK]), PRIMARY, FALLBACK) == [
        FALLBACK,
        PRIMARY,
    ]
    gates.check_adapted_caddy_hosts(_adapted([PRIMARY]), PRIMARY, "")
    for bad, msg in (
        (_adapted([PRIMARY]), "!= reviewed"),  # fallback silently dropped
        (_adapted([PRIMARY, FALLBACK, "evil.example"]), "!= reviewed"),  # an extra host
        (_adapted([PRIMARY, FALLBACK, FALLBACK]), "!= reviewed"),  # duplicated host
        (_adapted([PRIMARY], [FALLBACK]), "want exactly one"),  # two sites could diverge
        (_adapted([PRIMARY, FALLBACK], ["evil.example"]), "want exactly one"),
        (_adapted(), "want exactly one"),  # no site at all
    ):
        with pytest.raises(GateError, match=msg):
            gates.check_adapted_caddy_hosts(bad, PRIMARY, FALLBACK)
    with pytest.raises(GateError, match="cannot read"):
        gates.check_adapted_caddy_hosts("{not json", PRIMARY, FALLBACK)


def test_running_edge_facts_accept_only_the_reviewed_values_and_release_mount() -> None:
    src = "/opt/nlw/releases/x/docker/caddy/Caddyfile"
    good = [
        f"PUBLIC_HOSTNAME={PRIMARY}",
        f"PUBLIC_HOSTNAME_FALLBACK={FALLBACK}",
        f"MOUNT={src}:false",
    ]
    gates.check_running_edge_facts(good, PRIMARY, FALLBACK, {src})
    bad_sets = [
        ["NOT_RUNNING"],
        good[:1] + good[2:],  # fallback missing from the container
        [f"PUBLIC_HOSTNAME={FALLBACK}", f"PUBLIC_HOSTNAME_FALLBACK={PRIMARY}", good[2]],
        [*good[:2], "PUBLIC_HOSTNAME=evil.example", good[2]],  # duplicate injected value
        [*good[:2], f"MOUNT={src}:true"],  # writable mount
        [*good[:2], "MOUNT=/opt/nlw/releases/old/docker/caddy/Caddyfile:false"],
        good[:2],  # no Caddyfile mount at all
    ]
    for lines in bad_sets:
        with pytest.raises(GateError, match="keep traffic closed"):
            gates.check_running_edge_facts(lines, PRIMARY, FALLBACK, {src})


# --- rendered Compose: Caddy-only scope and ambient-shell protection --------------
EDGE_KEYS = ("PUBLIC_HOSTNAME", "PUBLIC_HOSTNAME_FALLBACK")


def _render(
    tmp_path: Path, *, ambient: dict[str, str], protected: bool
) -> dict[str, dict[str, str]]:
    for file in ("docker-compose.prod.yml", "docker-compose.staging.yml"):
        shutil.copyfile(ROOT / file, tmp_path / file)
    (tmp_path / ".env.prod").write_text(
        f"PUBLIC_HOSTNAME={PRIMARY}\nPUBLIC_HOSTNAME_FALLBACK={FALLBACK}\nDEMO_TOOLS_ENABLED=true\n"
    )
    target = replace(load_target(TARGET), operator_alerting=None)
    command = target.dc_in(str(tmp_path))
    assert command.startswith(
        f"cd '{tmp_path}' && env " + " ".join(f"-u {k}" for k in AMBIENT_UNSET)
    )
    if not protected:
        command = re.sub(r"env( -u [A-Z_]+)+ ", "", command)  # the unprotected form
    env = {
        k: f"fixture-{k}"
        for k in re.findall(r"\$\{([A-Z_]+):\?", (ROOT / "docker-compose.prod.yml").read_text())
    }
    env.update(PATH=os.environ["PATH"], NLW_CTX_KEYS_DIR="/srv/nlw/ctx-keys", **ambient)
    result = subprocess.run(
        ["bash", "-c", command + " --profile '*' config --format json"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    services = json.loads(result.stdout)["services"]
    return {
        name: {k: v for k, v in (svc.get("environment") or {}).items() if k in EDGE_KEYS}
        for name, svc in services.items()
    }


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker compose CLI not installed")
@pytest.mark.parametrize(
    "ambient",
    [
        {},
        {"PUBLIC_HOSTNAME": "evil.example", "PUBLIC_HOSTNAME_FALLBACK": "1-2-3-4.sslip.io"},
        {"PUBLIC_HOSTNAME": "", "PUBLIC_HOSTNAME_FALLBACK": ""},
    ],
)
def test_reviewed_render_gives_the_edge_values_to_caddy_only(
    tmp_path: Path, ambient: dict[str, str]
) -> None:
    holders = {k: v for k, v in _render(tmp_path, ambient=ambient, protected=True).items() if v}
    assert holders == {"caddy": {"PUBLIC_HOSTNAME": PRIMARY, "PUBLIC_HOSTNAME_FALLBACK": FALLBACK}}


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker compose CLI not installed")
def test_unprotected_render_reproduces_the_ambient_override_defect(tmp_path: Path) -> None:
    ambient = {"PUBLIC_HOSTNAME": "evil.example", "PUBLIC_HOSTNAME_FALLBACK": "1-2-3-4.sslip.io"}
    caddy = _render(tmp_path, ambient=ambient, protected=False)["caddy"]
    assert caddy == ambient  # why every rollout Compose invocation unsets them


def test_caddyfile_serves_exactly_the_two_reviewed_placeholders_in_one_site() -> None:
    text = (ROOT / "docker/caddy/Caddyfile").read_text()
    sites = [ln for ln in text.splitlines() if ln and not ln.startswith(("#", "\t", " ", "}"))]
    assert sites == ["{$PUBLIC_HOSTNAME} {$PUBLIC_HOSTNAME_FALLBACK} {"]


def test_compose_mentions_the_fallback_on_exactly_one_caddy_line() -> None:
    lines = [
        ln.strip()
        for ln in (ROOT / "docker-compose.prod.yml").read_text().splitlines()
        if "PUBLIC_HOSTNAME_FALLBACK" in ln
    ]
    assert lines == ["PUBLIC_HOSTNAME_FALLBACK: ${PUBLIC_HOSTNAME_FALLBACK:-}"]


def test_running_edge_mismatch_names_only_the_filtered_edge_facts() -> None:
    src = "/opt/nlw/releases/x/docker/caddy/Caddyfile"
    wrong_mount = [
        f"PUBLIC_HOSTNAME={PRIMARY}",
        f"PUBLIC_HOSTNAME_FALLBACK={FALLBACK}",
        "MOUNT=/opt/nlw/releases/old/docker/caddy/Caddyfile:false",
    ]
    with pytest.raises(GateError) as mount_err:
        gates.check_running_edge_facts(wrong_mount, PRIMARY, FALLBACK, {src})
    assert "releases/old/docker/caddy/Caddyfile:false" in str(mount_err.value)
    assert f"{src}:false" in str(mount_err.value)
    wrong_env = [f"PUBLIC_HOSTNAME={PRIMARY}", "PUBLIC_HOSTNAME_FALLBACK=", f"MOUNT={src}:false"]
    with pytest.raises(GateError) as env_err:
        gates.check_running_edge_facts(wrong_env, PRIMARY, FALLBACK, {src})
    assert "PUBLIC_HOSTNAME_FALLBACK=" in str(env_err.value) and FALLBACK in str(env_err.value)
