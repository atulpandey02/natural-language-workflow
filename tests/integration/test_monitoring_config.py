"""Container-level validation of the monitoring wiring (M12A-Prep §J/§K, O.18):
promtool and amtool from the pinned images validate the exact files the
staging overlay mounts, at the exact in-container paths.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[2]


def _image(service: str) -> str:
    doc = yaml.safe_load((ROOT / "docker-compose.staging.yml").read_text())
    return str(doc["services"][service]["image"])


def _docker(*args: str) -> subprocess.CompletedProcess[str]:
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False)


def test_promtool_validates_config_and_every_rule_file_at_mounted_paths() -> None:
    res = _docker(
        "run", "--rm",
        "-v", f"{ROOT}/docker/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro",
        "-v", f"{ROOT}/docker/prometheus/alerts:/etc/prometheus/alerts:ro",
        "--entrypoint", "promtool", _image("prometheus"),
        "check", "config", "/etc/prometheus/prometheus.yml",
    )  # fmt: skip
    assert res.returncode == 0, res.stdout + res.stderr
    assert "SUCCESS: 4 rules found" in res.stdout and "SUCCESS: 2 rules found" in res.stdout


def test_promtool_fails_when_a_referenced_rule_file_is_missing() -> None:
    """The gap the staging overlay had: prometheus.yml references rule files the
    container could not see. Mounting only prometheus.yml must FAIL validation."""
    res = _docker(
        "run", "--rm",
        "-v", f"{ROOT}/docker/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro",
        "--entrypoint", "promtool", _image("prometheus"),
        "check", "config", "/etc/prometheus/prometheus.yml",
    )  # fmt: skip
    assert res.returncode != 0


def test_amtool_validates_alertmanager_config() -> None:
    res = _docker(
        "run", "--rm",
        "-v", f"{ROOT}/docker/alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro",
        "--entrypoint", "amtool", _image("alertmanager"),
        "check-config", "/etc/alertmanager/alertmanager.yml",
    )  # fmt: skip
    assert res.returncode == 0, res.stdout + res.stderr
    assert "1 receivers" in res.stdout
