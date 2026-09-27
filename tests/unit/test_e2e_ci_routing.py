"""E2E CI routing: seeded-stack specs and harness-only pilot specs run in separate
required jobs, and the pilot job fails rather than passing on a skipped or empty run."""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/e2e.yml"


def _jobs() -> dict[str, Any]:
    jobs: dict[str, Any] = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    return jobs


def _step(job: dict[str, Any], name: str) -> dict[str, Any]:
    return next(s for s in job["steps"] if s.get("name") == name)


def _checker() -> ModuleType:
    path = ROOT / "scripts/ci/check_pilot_browser_run.py"
    spec = importlib.util.spec_from_file_location("check_pilot_browser_run", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_seeded_stack_job_is_unchanged_and_guards_against_pilot_specs() -> None:
    seeded = _jobs()["e2e"]
    assert seeded["name"] == "Required Playwright E2E (seeded stack)"
    run = _step(seeded, "Run required E2E")
    assert run["run"].strip() == "npx playwright test"
    assert run["env"]["E2E_REQUIRED"] == "1" and "E2E_PILOT" not in run["env"]
    guard = _step(seeded, "Assert seeded-stack collection excludes harness-only specs")
    names = [s.get("name") for s in seeded["steps"]]
    assert names.index(guard["name"]) < names.index("Run required E2E")
    assert "npx playwright test --list" in guard["run"]
    assert 'grep -q "pilot-"' in guard["run"] and "exit 1" in guard["run"]
    assert "E2E_PILOT" not in guard.get("env", {})


def test_pilot_job_runs_both_harness_journeys_and_rejects_skips() -> None:
    pilot = _jobs()["pilot"]
    assert pilot["name"] == "Required pilot browser harness (isolated)"
    golden = _step(pilot, "Golden pilot journeys (Sales -> Slack proposal -> approval; Support)")
    visual = _step(pilot, "Failure / partial / UNKNOWN pilot journey")
    assert "PILOT_VISUAL_STATES" not in golden.get("env", {})
    assert visual["env"]["PILOT_VISUAL_STATES"] == "1"
    assert "-p web.e2e.visual_states_plugin" in visual["run"]
    for step in (golden, visual):
        assert "tests/integration/test_pilot_browser.py" in step["run"]
        assert "--junitxml=" in step["run"] and step["env"]["E2E_JSON_REPORT"]
        assert "scripts/ci/check_pilot_browser_run.py" in step["run"]
        assert 'exit "$status"' in step["run"]
    paths = _step(pilot, "Define private harness paths")
    assert pilot["steps"][0] is paths
    assert 'PILOT_AUTH_CONFIG=$RUNNER_TEMP/pilot-auth.json" >> "$GITHUB_ENV"' in paths["run"]


def test_no_job_level_env_uses_the_runner_context() -> None:
    # GitHub rejects `${{ runner.* }}` in jobs.<id>.env (only step contexts allow it).
    for name, job in _jobs().items():
        assert "runner." not in json.dumps(job.get("env", {})), name


def test_pilot_job_keeps_local_auth_secrets_out_of_logs_and_always_tears_down() -> None:
    pilot = _jobs()["pilot"]
    start = _step(pilot, "Start isolated local Supabase auth")["run"]
    assert "umask 077" in start
    assert '> "$RUNNER_TEMP/pilot-auth-start.log"' in start
    assert 'status --workdir "$PILOT_AUTH_WORKDIR" -o json > "$PILOT_AUTH_CONFIG"' in start
    assert "tee" not in start and "$GITHUB_ENV" not in start
    teardown = _step(pilot, "Tear down local Supabase and credentials")
    assert teardown["if"] == "always()"
    assert "|| true" not in teardown["run"]
    assert 'rm -f "$PILOT_AUTH_CONFIG"' in teardown["run"]
    assert "supabase stop" in teardown["run"] and "exit 1" in teardown["run"]


def test_e2e_actions_are_pinned_to_full_commit_shas() -> None:
    uses = re.findall(r"uses:\s*(\S+)", WORKFLOW.read_text())
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref


def _junit(tmp: Path, tests: int = 1, skipped: int = 0, failures: int = 0) -> Path:
    path = tmp / "junit.xml"
    path.write_text(
        f'<testsuites><testsuite name="pytest" tests="{tests}" skipped="{skipped}" '
        f'failures="{failures}" errors="0"/></testsuites>'
    )
    return path


def _report(tmp: Path, **stats: int) -> Path:
    path = tmp / "report.json"
    base = {"expected": 2, "skipped": 0, "unexpected": 0, "flaky": 0}
    path.write_text(json.dumps({"stats": {**base, **stats}, "errors": []}))
    return path


def test_checker_accepts_a_real_passing_run(tmp_path: Path) -> None:
    args = ["--junit", str(_junit(tmp_path)), "--playwright", str(_report(tmp_path))]
    assert _checker().main(args) == 0


@pytest.mark.parametrize(
    ("junit", "stats"),
    [
        ({"skipped": 1}, {}),  # harness skipped (e.g. PILOT_AUTH_CONFIG missing)
        ({"tests": 0}, {}),  # nothing collected
        ({"failures": 1}, {}),
        ({}, {"expected": 0}),  # no browser test ran
        ({}, {"skipped": 1}),  # a browser test skipped
        ({}, {"unexpected": 1}),
        ({}, {"flaky": 1}),
    ],
)
def test_checker_rejects_skipped_empty_or_failed_runs(
    tmp_path: Path, junit: dict[str, int], stats: dict[str, int]
) -> None:
    args = [
        "--junit",
        str(_junit(tmp_path, **junit)),
        "--playwright",
        str(_report(tmp_path, **stats)),
    ]
    assert _checker().main(args) == 1


def test_checker_rejects_missing_reports(tmp_path: Path) -> None:
    missing = str(tmp_path / "absent")
    assert _checker().main(["--junit", missing, "--playwright", missing]) == 1
