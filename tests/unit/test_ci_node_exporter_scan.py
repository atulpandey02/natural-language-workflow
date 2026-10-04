"""CI contract: fixed CRITICAL vulnerabilities in the pinned third-party
node-exporter image are REPORTED (job summary + warning) without gating, while
the two app-image scans keep their gating thresholds. No suppression file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
NODE_EXPORTER = "prom/node-exporter:v1.12.1"


def _steps(name: str) -> list[dict[str, Any]]:
    doc: dict[str, Any] = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
    return [step for job in doc["jobs"].values() for step in job.get("steps", [])]


def _index(steps: list[dict[str, Any]], pred: Any) -> int:
    matches = [i for i, s in enumerate(steps) if pred(s)]
    assert len(matches) == 1, matches
    return matches[0]


def _trivy_steps() -> list[dict[str, Any]]:
    return [s for s in _steps("ci.yml") if str(s.get("uses", "")).startswith("aquasecurity/")]


def test_node_exporter_scan_is_pinned_critical_fixed_only_and_non_gating() -> None:
    scans = [s for s in _trivy_steps() if s["with"]["image-ref"] == NODE_EXPORTER]
    assert len(scans) == 1
    step = scans[0]
    assert step["with"]["severity"] == "CRITICAL"
    assert step["with"]["ignore-unfixed"] is True
    assert step["with"]["exit-code"] == "0"
    assert step["with"]["version"] == "v0.65.0"
    assert step["env"]["TRIVY_PLATFORM"] == "linux/amd64"
    assert "trivyignores" not in step["with"] and "skip-files" not in step["with"]
    assert not (ROOT / ".trivyignore").exists()


def test_existing_app_image_scans_keep_their_gating_thresholds() -> None:
    by_image = {s["with"]["image-ref"]: s["with"] for s in _trivy_steps()}
    assert set(by_image) == {"nlw:ci", "nlw-web:ci", NODE_EXPORTER}
    for image in ("nlw:ci", "nlw-web:ci"):
        assert by_image[image]["exit-code"] == "1"
        assert by_image[image]["severity"] == "CRITICAL"
        assert by_image[image]["ignore-unfixed"] is True


def test_scan_result_is_summarized_and_warned_on() -> None:
    steps = _steps("ci.yml")
    summary = steps[_index(steps, lambda s: s.get("name") == "Summarize node-exporter scan")]
    assert summary["if"] == "always()"
    assert "$GITHUB_STEP_SUMMARY" in summary["run"]
    assert "::warning title=node-exporter scan::" in summary["run"]
