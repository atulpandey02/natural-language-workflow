"""Deployment-tooling gaps are closed and cannot regress (M12A-Prep §A, §J–§M;
tests O.17, O.19, O.20). These are the tests that FAILED against the M11-pinned
tooling and pass now: they assert the reviewed scripts/configs, not the host.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
OPS = ROOT / "scripts" / "ops"
STALE_IP = "54.196.254.101"


def _load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load((ROOT / name).read_text())
    return data


def _rendered_staging() -> dict[str, Any]:
    """Render prod + staging exactly as the VPS does, with dummy required values."""
    env = {
        k: f"dummy-{k}"
        for k in re.findall(r"\$\{([A-Z_]+):\?", (ROOT / "docker-compose.prod.yml").read_text())
    }
    env["NLW_CTX_KEYS_DIR"] = "/srv/nlw/ctx-keys"
    p = subprocess.run(
        ["docker", "compose", "-f", "docker-compose.prod.yml",
         "-f", "docker-compose.staging.yml", "config"],
        cwd=ROOT, env={**env, "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"},
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    if p.returncode != 0:
        import pytest

        pytest.skip(f"docker compose unavailable: {p.stderr[-200:]}")
    doc: dict[str, Any] = yaml.safe_load(p.stdout)
    return doc


# --- A.1–A.4: the reviewed deploy path is P3B-capable and atomic ---------------
def test_deploy_script_provisions_and_verifies_p3b_roles() -> None:
    text = (OPS / "deploy-staging.sh").read_text()
    for role in ("nlw_membership_admin", "nlw_ctx_verifier"):
        assert role in text, f"deploy script must verify {role}"
    verify = (OPS / "verify-staging-deployment.sh").read_text()
    assert '"nlw_ctx_verifier:fff"' in verify and '"nlw_membership_admin:fft"' in verify


def test_deploy_script_requires_installed_keys_before_starting_runtimes() -> None:
    text = (OPS / "deploy-staging.sh").read_text()
    assert "require_context_keys" in text
    main = text[text.index("main() {") :]
    assert main.index("require_context_keys") < main.index("start_app_services")
    assert "nlw.ctxkeys check" in text and "--secret-file /run/nlw/keys/" in text
    assert "NLW_CTX_KEYS_DIR" in text


def test_deploy_script_reads_release_identity_not_hard_coded_pins() -> None:
    text = (OPS / "deploy-staging.sh").read_text()
    assert "deploy/staging/release.json" in text or "release.json" in text
    assert "staging-target.sh" in text
    assert not re.search(r'^DEPLOY_SHA="[0-9a-f]{40}"', text, re.M)
    assert not re.search(r'^BACKEND_IMAGE="ghcr', text, re.M)
    assert "EXPECTED_INSTANCE_ID" in text and "staging_assert_instance" in text


def test_upgrade_path_is_the_phased_rollout_not_the_first_deploy_script() -> None:
    """0010 -> 0016 must go through the gated state machine (stop/migrate/install/
    recreate), never `alembic upgrade head` + `up -d` in one breath."""
    from nlw.ops.rollout.state import PHASES

    assert PHASES.index("drain") < PHASES.index("migrate") < PHASES.index("install-context-keys")
    assert (
        PHASES.index("install-context-keys")
        < PHASES.index("recreate-runtime")
        < PHASES.index("validate")
    )
    assert PHASES.index("validate") < PHASES.index("reopen")
    assert (
        PHASES.index("prepare-keys") < PHASES.index("verify-escrow") < PHASES.index("pin-release")
    )
    assert (
        PHASES.index("pin-release") < PHASES.index("prepare-roles") < PHASES.index("verify-backup")
    )
    assert PHASES.index("verify-backup") < PHASES.index("drain")


# --- A.5 / §J: every referenced Prometheus rule file is mounted ------------------
def test_prometheus_rule_files_exist_and_staging_mounts_the_directory() -> None:
    prom = _load("docker/prometheus/prometheus.yml")
    rule_files = prom.get("rule_files") or []
    assert rule_files, "prometheus.yml must reference rule files"
    for rf in rule_files:
        assert (ROOT / "docker" / "prometheus" / rf).is_file(), f"missing rule file {rf}"
        assert rf.startswith("alerts/")
    staging = _load("docker-compose.staging.yml")
    vols = [str(v) for v in staging["services"]["prometheus"]["volumes"]]
    assert any(
        v.startswith("./docker/prometheus/alerts:/etc/prometheus/alerts:ro") for v in vols
    ), vols
    assert any(
        v.startswith("./docker/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro")
        for v in vols
    )
    assert staging["services"]["prometheus"].get("user") == "65534:65534"
    groups = [g["name"] for rf in rule_files for g in _load(f"docker/prometheus/{rf}")["groups"]]
    assert set(groups) == {"nlw-backup", "nlw-signed-context"}


def test_rule_labels_are_low_cardinality_and_secret_free() -> None:
    for rf in ("backup.rules.yml", "signed-context.rules.yml"):
        doc = _load(f"docker/prometheus/alerts/{rf}")
        text = (ROOT / "docker/prometheus/alerts" / rf).read_text().lower()
        for needle in (
            "password",
            "secret",
            "token",
            "user_id",
            "tenant_id",
            "run_id",
            "nonce",
            "signature",
        ):
            assert needle not in text, (rf, needle)
        for g in doc["groups"]:
            for rule in g["rules"]:
                assert set(rule.get("labels", {})) <= {"severity", "component"}


def test_alertmanager_is_internal_with_null_receiver_and_no_credentials() -> None:
    staging = _load("docker-compose.staging.yml")
    am = staging["services"]["alertmanager"]
    assert "ports" not in am and am.get("expose") == ["9093"]
    assert am.get("user") == "65534:65534"
    cfg = _load("docker/alertmanager/alertmanager.yml")
    assert [r["name"] for r in cfg["receivers"]] == ["null"]
    text = (ROOT / "docker/alertmanager/alertmanager.yml").read_text().lower()
    for needle in (
        "api_url",
        "hooks.slack.com",
        "smtp_auth_password",
        "service_key",
        "routing_key",
        "xox",
    ):
        assert needle not in text
    prom = _load("docker/prometheus/prometheus.yml")
    targets = prom["alerting"]["alertmanagers"][0]["static_configs"][0]["targets"]
    assert targets == ["alertmanager:9093"]


def test_rendered_staging_keeps_runtime_key_isolation_and_maintenance_volume() -> None:
    doc = _rendered_staging()
    services = doc["services"]
    holders = {"api": "api.key", "worker": "worker.key", "scheduler": "scheduler.key"}
    for name, svc in services.items():
        mounts = [
            m for m in (svc.get("volumes") or []) if "/run/nlw/keys/" in str(m.get("target", m))
        ]
        if name in holders:
            assert len(mounts) == 1 and mounts[0]["target"] == f"/run/nlw/keys/{holders[name]}"
            assert mounts[0].get("read_only") is True
        else:
            assert mounts == [], f"{name} must not mount a key file"
    caddy_targets = {m["target"] for m in services["caddy"]["volumes"]}
    assert "/srv/maint" in caddy_targets
    prom_targets = {m["target"] for m in services["prometheus"]["volumes"]}
    assert {"/etc/prometheus/prometheus.yml", "/etc/prometheus/alerts"} <= prom_targets
    assert "alertmanager" in services and not services["alertmanager"].get("ports")


def test_caddyfile_has_maintenance_matcher() -> None:
    text = (ROOT / "docker/caddy/Caddyfile").read_text()
    assert "@maintenance file" in text and "try_files /MAINTENANCE" in text and "503" in text


# --- A.6 / §L: the CI job is a simulation, never real-VPS evidence --------------
def test_ci_staging_job_is_labelled_simulation_and_contacts_no_host() -> None:
    wf = _load(".github/workflows/staging.yml")
    names = {j["name"] for j in wf["jobs"].values()}
    assert not any(re.search(r"^Deploy digest to staging", n) for n in names), names
    sim = wf["jobs"]["ci-staging-simulation"]
    assert "SIMULATION" in sim["name"] and "NOT the real VPS" in sim["name"]
    text = (ROOT / ".github/workflows/staging.yml").read_text()
    for needle in ("ssh ", "ssh-", "SSH_KEY", "nlw-staging-key", "nlwops@", "32.197.83.193"):
        assert needle not in text, needle
    assert "python -m nlw.ops.rollout" in text


# --- A.7 / §M: one source of host identity, no stale IPs -------------------------
def test_no_stale_ip_in_scripts_and_single_ssh_host_source() -> None:
    for f in OPS.glob("*.sh"):
        text = f.read_text()
        assert STALE_IP not in text, f
        if f.name in (
            "deploy-staging.sh",
            "verify-staging-deployment.sh",
            "verify-staging-host.sh",
            "bootstrap-staging-host.sh",
        ):
            assert 'SSH_HOST="${SSH_HOST:-' not in text, (
                f"{f.name} must not default its own SSH host"
            )
            assert "staging-target.sh" in text
    target = (ROOT / "deploy/staging/target.env").read_text()
    assert re.search(r"^NLW_STAGING_SSH_HOST=", target, re.M)
    assert re.search(r"^NLW_STAGING_INSTANCE_ID=i-[0-9a-f]+", target, re.M)
    # Historical evidence keeps the bootstrap-era address only there.
    for f in ROOT.rglob("*.md"):
        if STALE_IP in f.read_text():
            assert f.parts[-3:-1] == ("docs", "staging") or "historical" in f.read_text().lower(), f


def test_staging_target_lib_asserts_instance_identity() -> None:
    lib = OPS / "lib" / "staging-target.sh"
    p = subprocess.run(
        ["bash", "-c",
         f'source "{lib}"; staging_assert_instance "i-0000000000000001 us-east-1 1.2.3.4"'],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert p.returncode != 0 and "wrong target" in p.stderr
    p = subprocess.run(
        ["bash", "-c",
         f'source "{lib}"; staging_assert_instance "$EXPECTED_INSTANCE_ID us-east-1 1.2.3.4"'
         " && echo MATCH"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert p.returncode == 0 and "MATCH" in p.stdout
    p = subprocess.run(
        ["bash", "-c",
         f'source "{lib}"; staging_assert_instance "$EXPECTED_INSTANCE_ID eu-west-1 1.2.3.4"'],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert p.returncode != 0 and "region" in p.stderr


# --- A.8 / §G: the documented backup path actually renders and is enforced -------
def test_backup_env_example_matches_compose_interpolation_names() -> None:
    compose = (ROOT / "docker-compose.prod.yml").read_text()
    backup_block = compose[compose.index("  backup:") : compose.index("  restore:")]
    referenced = set(re.findall(r"\$\{([A-Z_]+):-", backup_block))
    example = {
        ln.split("=", 1)[0]
        for ln in (ROOT / ".env.backup.example").read_text().splitlines()
        if "=" in ln and not ln.startswith("#")
    }
    required = {
        "RESTIC_REPOSITORY",
        "RESTIC_PASSWORD",
        "BACKUP_AWS_ACCESS_KEY_ID",
        "BACKUP_AWS_SECRET_ACCESS_KEY",
        "BACKUP_AWS_REGION",
        "NLW_BACKUP_DATABASE_URL",
    }
    assert required <= referenced, referenced
    assert required <= example, example - required
    assert "AWS_ACCESS_KEY_ID" not in example  # the un-prefixed name is NOT interpolated


def test_backup_systemd_unit_renders_with_both_env_files() -> None:
    unit = (ROOT / "docker/systemd/nlw-backup.service").read_text()
    assert "--env-file /opt/nlw/app/.env.prod --env-file /opt/nlw/.env.backup" in unit
    assert "/opt/nlw/app/docker-compose.prod.yml" in unit


def test_rollout_backup_gate_is_wired_before_migration() -> None:
    from nlw.ops.rollout import phases

    src = (ROOT / "src/nlw/ops/rollout/phases.py").read_text()
    assert "evaluate_backup_evidence" in src
    migrate_body = src[src.index("def migrate(") :]
    assert '"verify-backup"' in migrate_body[: migrate_body.index("pull -q")]
    assert phases.EXPECTED_SIGNED_POLICIES == 51
