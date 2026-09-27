"""Fail the pilot browser CI job unless its harness run really exercised the browser.

The pilot harness (tests/integration/test_pilot_browser.py) is opt-in and skips
without PILOT_AUTH_CONFIG. Playwright also exits 0 when every test is skipped.
Checking exit codes alone is therefore not enough. This checks both reports:

- pytest JUnit XML: at least one test, and no skip, failure or error;
- Playwright JSON (E2E_JSON_REPORT): at least one expected (passed) test, and no
  skipped, unexpected or flaky test and no global error.

Usage: check_pilot_browser_run.py --junit run.xml --playwright report.json
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def junit_problems(path: Path) -> list[str]:
    if not path.is_file():
        return [f"pytest JUnit report missing: {path}"]
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    totals = {key: 0 for key in ("tests", "skipped", "failures", "errors")}
    for suite in suites:
        for key in totals:
            totals[key] += int(suite.get(key, "0"))
    problems = []
    if totals["tests"] < 1:
        problems.append("pytest collected no pilot harness test")
    for key in ("skipped", "failures", "errors"):
        if totals[key]:
            problems.append(f"pytest reported {totals[key]} {key}")
    return problems


def playwright_problems(path: Path) -> list[str]:
    if not path.is_file():
        return [f"Playwright JSON report missing: {path} (browser tests never ran)"]
    report = json.loads(path.read_text())
    stats = report.get("stats", {})
    problems = []
    if int(stats.get("expected", 0)) < 1:
        problems.append("Playwright ran no passing pilot browser test")
    for key in ("skipped", "unexpected", "flaky"):
        if int(stats.get(key, 0)):
            problems.append(f"Playwright reported {stats[key]} {key} test(s)")
    if report.get("errors"):
        problems.append(f"Playwright reported {len(report['errors'])} global error(s)")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--playwright", type=Path, required=True)
    args = parser.parse_args(argv)
    problems = junit_problems(args.junit) + playwright_problems(args.playwright)
    for problem in problems:
        print(f"::error::{problem}")
    if not problems:
        stats = json.loads(args.playwright.read_text())["stats"]
        print(f"pilot browser run OK: {stats['expected']} passed, 0 skipped, 0 failed")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
