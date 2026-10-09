"""Container-level validation of the monitoring wiring (M12A-Prep §J/§K, O.18):
promtool and amtool from the pinned images validate the exact files the
staging overlay mounts, at the exact in-container paths.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from nlw.backup.metrics_file import BackupMetrics, parse_metrics_text, write_metrics

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


def test_promtool_unit_tests_prove_the_backup_dead_man() -> None:
    """NlwBackupStale (ADR-022 amendment 1): silent while a fresh backup is
    scraped, fires when the series is stale or absent, clears on recovery."""
    res = _docker(
        "run", "--rm",
        "-v", f"{ROOT}/docker/prometheus/alerts:/etc/prometheus/alerts:ro",
        "-v", f"{ROOT}/docker/prometheus/tests:/etc/prometheus/tests:ro",
        "--entrypoint", "promtool", _image("prometheus"),
        "test", "rules", "/etc/prometheus/tests/backup.rules.test.yml",
    )  # fmt: skip
    assert res.returncode == 0, res.stdout + res.stderr
    assert "SUCCESS" in res.stdout


def test_node_exporter_serves_the_backup_textfile_the_job_writes(tmp_path: Path) -> None:
    """The pinned exporter, run exactly as the staging overlay runs it (user,
    read-only root, no capabilities, textfile collector only, read-only mount),
    exposes the series the backup job writes, so Prometheus sees a real value
    instead of an absent one."""
    svc = yaml.safe_load((ROOT / "docker-compose.staging.yml").read_text())["services"][
        "node-exporter"
    ]
    textfile = tmp_path / "textfile"
    textfile.mkdir()
    now = time.time()
    write_metrics(
        str(textfile / "nlw_backup.prom"),
        BackupMetrics(
            success=True,
            duration_seconds=12.5,
            verify_success=True,
            retention_success=True,
            verified_off_host=True,
        ),
        now=now,
    )
    textfile.chmod(0o755)
    (textfile / "nlw_backup.prom").chmod(0o644)
    started = _docker(
        "run", "-d", "--rm",
        "--user", svc["user"], "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "-v", f"{textfile}:/textfile:ro",
        svc["image"], *svc["command"],
    )  # fmt: skip
    assert started.returncode == 0, started.stderr
    cid = started.stdout.strip()
    try:
        body = ""
        for _ in range(30):
            got = _docker("exec", cid, "wget", "-qO-", "http://127.0.0.1:9100/metrics")
            if got.returncode == 0 and "nlw_backup_last_success_timestamp_seconds" in got.stdout:
                body = got.stdout
                break
            time.sleep(0.5)
        assert body, "exporter never served the backup series"
        parsed = parse_metrics_text(body)
        assert parsed.success is True and parsed.verify_success is True
        assert parsed.last_success is not None and abs(parsed.last_success - now) < 2
        assert 'node_scrape_collector_success{collector="textfile"} 1' in body
        assert "node_textfile_scrape_error 0" in body
        # Textfile only: no host collector is enabled.
        assert "node_cpu_seconds_total" not in body and "node_filesystem" not in body
    finally:
        _docker("rm", "-f", cid)


def test_promtool_unit_tests_prove_the_dataset_processing_alerts() -> None:
    """ADR-032: pending > 15 min, expired requests and a stalled dispatcher fire;
    a healthy dispatcher stays silent. (Not wired into prometheus.yml until O-6.)"""
    res = _docker(
        "run", "--rm",
        "-v", f"{ROOT}/docker/prometheus/alerts:/etc/prometheus/alerts:ro",
        "-v", f"{ROOT}/docker/prometheus/tests:/etc/prometheus/tests:ro",
        "--entrypoint", "promtool", _image("prometheus"),
        "test", "rules", "/etc/prometheus/tests/datasets.rules.test.yml",
    )  # fmt: skip
    assert res.returncode == 0, res.stdout + res.stderr
    assert "SUCCESS" in res.stdout
    check = _docker(
        "run", "--rm",
        "-v", f"{ROOT}/docker/prometheus/alerts:/etc/prometheus/alerts:ro",
        "--entrypoint", "promtool", _image("prometheus"),
        "check", "rules", "/etc/prometheus/alerts/datasets.rules.yml",
    )  # fmt: skip
    assert check.returncode == 0 and "SUCCESS: 5 rules found" in check.stdout
