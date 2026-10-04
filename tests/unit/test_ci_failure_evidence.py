"""CI contract: staging-validation keeps SAFE browser-failure evidence.

Screenshots, failure video, error context, the HTML report and bounded redacted
logs are kept, never traces and never credential-bearing files, for seven days,
and only when the browser suite itself failed. No workflow's permissions widen.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "web/playwright.config.ts"
COLLECTOR = ROOT / "scripts/ci/collect_browser_evidence.sh"


def _workflow(name: str) -> dict[str, Any]:
    doc: dict[str, Any] = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
    return doc


def _staging_steps() -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = _workflow("staging-validation.yml")["jobs"]["validate"]["steps"]
    return steps


def _index(steps: list[dict[str, Any]], pred: Any) -> int:
    matches = [i for i, s in enumerate(steps) if pred(s)]
    assert len(matches) == 1, matches
    return matches[0]


# --- Playwright configuration ---------------------------------------------------------


def test_traces_are_disabled_everywhere() -> None:
    text = CONFIG.read_text()
    assert re.findall(r"\btrace:\s*\"([^\"]+)\"", text) == ["off"]
    assert (
        "on-first-retry" not in text and 'retain-on-failure",' not in text.split("trace:")[1][:30]
    )


def test_screenshots_and_video_only_with_failure_evidence_and_never_an_html_report() -> None:
    text = CONFIG.read_text()
    assert 'const failureEvidence = process.env.E2E_FAILURE_EVIDENCE === "1";' in text
    assert 'screenshot: failureEvidence ? "only-on-failure" : "off"' in text
    assert 'video: failureEvidence ? "retain-on-failure" : "off"' in text
    # The HTML report embeds raw authenticated report data: never generated.
    assert '["html"' not in text and "playwright-report" not in text


# --- staging-validation workflow ---------------------------------------------------


def test_evidence_steps_follow_playwright_and_precede_teardown() -> None:
    steps = _staging_steps()
    pw = _index(steps, lambda s: s.get("id") == "playwright")
    collect = _index(steps, lambda s: s.get("id") == "browser_evidence")
    upload = _index(steps, lambda s: s.get("name") == "Upload browser failure evidence")
    teardown = _index(steps, lambda s: s.get("name") == "Tear down")
    assert pw < collect < upload < teardown
    assert collect == pw + 1 and upload == collect + 1
    assert steps[pw]["env"]["E2E_FAILURE_EVIDENCE"] == "1"


def test_evidence_is_collected_and_uploaded_only_when_the_browser_suite_failed() -> None:
    steps = _staging_steps()
    collect = steps[_index(steps, lambda s: s.get("id") == "browser_evidence")]
    upload = steps[_index(steps, lambda s: s.get("name") == "Upload browser failure evidence")]
    assert collect["if"] == "failure() && steps.playwright.outcome == 'failure'"
    assert upload["if"] == "failure() && steps.browser_evidence.outputs.ready == 'true'"
    assert "always()" not in collect["if"] + upload["if"]
    assert collect["run"].strip() == (
        'bash scripts/ci/collect_browser_evidence.sh "${RUNNER_TEMP}/browser-evidence"'
    )


def test_upload_is_bounded_to_the_scanned_directory_for_seven_days() -> None:
    steps = _staging_steps()
    upload = steps[_index(steps, lambda s: s.get("name") == "Upload browser failure evidence")]
    assert upload["uses"].startswith("actions/upload-artifact@")
    w = upload["with"]
    assert w["path"] == "${{ runner.temp }}/browser-evidence/"
    assert w["retention-days"] == 7
    assert w.get("include-hidden-files") in (None, False)
    assert w["name"] == "browser-failure-evidence"


# --- collector -------------------------------------------------------------------------


def test_collector_copies_by_allowlist_and_never_the_html_report() -> None:
    text = COLLECTOR.read_text()
    assert "web/playwright-report" not in text.split("set -euo pipefail", 1)[1]
    rsync = text[text.index("rsync -a") : text.index('web/test-results/ "$OUT/test-results/"')]
    for flag in (
        "--no-links",
        "--exclude='trace*'",
        "--exclude='*.trace'",
        "--exclude='.env*'",
        "--include='*/'",
        "--include='*.png'",
        "--include='*.jpg'",
        "--include='*.jpeg'",
        "--include='*.webm'",
        "--include='*.md'",
        "--include='*.txt'",
        "--exclude='*'",
    ):
        assert flag in rsync, flag
    # Excludes come before the allowlist; the catch-all exclude comes last.
    assert rsync.index("--exclude='.env*'") < rsync.index("--include='*/'")
    assert rsync.rstrip(" \\\n").endswith("--exclude='*'")


def test_collector_bounds_and_redacts_logs() -> None:
    text = COLLECTOR.read_text()
    assert 'LOG_SINCE="${EVIDENCE_LOG_SINCE:-20m}"' in text
    assert 'LOG_TAIL="${EVIDENCE_LOG_TAIL:-1500}"' in text
    assert 'MAX_MB="${EVIDENCE_MAX_MB:-200}"' in text
    assert text.index("-name '*.webm' -delete") < text.rindex("even without video")
    assert "for svc in api web worker; do" in text
    assert text.index("guard self-test") < text.index("logs --no-color")
    assert 'guard redact < "$RAW" > "$OUT/logs/$svc.log"' in text
    assert "logs_ok=false" in text and 'rm -rf "$OUT/logs"' in text


def test_collector_redacts_text_artifacts_before_the_final_scan_and_fails_closed() -> None:
    text = COLLECTOR.read_text()
    assert "set -euo pipefail" in text
    redact_tree = text.index('if ! guard redact-tree "$OUT"; then')
    final_scan = text.index('if ! guard scan "$OUT"; then')
    assert redact_tree < final_scan
    assert 'nothing "text artifact redaction failed"' in text[redact_tree : redact_tree + 120]
    assert "nothing " in text[final_scan : final_scan + 120]
    assert 'nothing() { echo "$1: nothing uploaded"; rm -rf "$OUT"; ready false; exit 0; }' in text
    assert text.rstrip().endswith("ready true")
    assert text.index('guard scan "$OUT/logs"') < final_scan


# --- permissions ------------------------------------------------------------------------


def test_no_workflow_permission_expansion() -> None:
    ci = _workflow("ci.yml")
    assert ci.get("permissions") is None
    assert {name: job.get("permissions") for name, job in ci["jobs"].items()} == {
        "quality": None,
        "integration": None,
        "migrations": None,
        "docker-build": None,
        "web": None,
        "release-provenance-pr-negative-proof": {
            "contents": "read",
            "id-token": "write",
            "attestations": "write",
        },
        "security": None,
    }
    sv = _workflow("staging-validation.yml")
    assert sv.get("permissions") is None
    assert all(job.get("permissions") is None for job in sv["jobs"].values())
