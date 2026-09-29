"""Staging-validation role check: deterministic, never swallows a failed trigger.

Regression for the flake where the seeded approval workflow (no current
version) sorted first, the trigger returned 409 behind ``|| true``, and the
role check depended on a five-second sleep catching a transient connection.
"""

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "staging_role_check", ROOT / "scripts" / "ci" / "staging_role_check.py"
)
assert _spec and _spec.loader
rc = importlib.util.module_from_spec(_spec)
sys.modules["staging_role_check"] = rc
_spec.loader.exec_module(rc)

RUN_ID = "11111111-2222-3333-4444-555555555555"
RUNNABLE = {"id": "wf-run", "name": "E2E Seeded Workflow", "current_version_id": "v1"}
APPROVAL = {"id": "wf-appr", "name": "E2E Approval WF", "current_version_id": None}


class FakeApi:
    def __init__(self, trigger: tuple[int, dict[str, object]], statuses: list[str]) -> None:
        self.trigger = trigger
        self.statuses = statuses
        self.calls: list[tuple[str, str]] = []

    def __call__(self, method: str, url: str, headers: dict[str, str]) -> tuple[int, bytes]:
        self.calls.append((method, url))
        if method == "POST":
            return self.trigger[0], json.dumps(self.trigger[1]).encode()
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        return 200, json.dumps({"id": RUN_ID, "status": status}).encode()


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("K6_ADMIN_TOKEN", "tok-never-printed")
    monkeypatch.setenv("K6_WORKSPACE", "ws")


def test_success_requires_a_worker_owned_terminal_status(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    api = FakeApi((201, {"id": RUN_ID}), ["PENDING", "RUNNING", "COMPLETED"])
    monkeypatch.setattr(rc.time, "sleep", lambda _s: None)
    assert rc.main(["--api", "http://x", "--workflow", "wf-run"], http=api) == 0
    assert [m for m, _ in api.calls] == ["POST", "GET", "GET", "GET"]
    assert "tok-never-printed" not in capsys.readouterr().out


def test_409_trigger_fails_with_sanitized_code_and_polls_nothing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    api = FakeApi(
        (409, {"error": {"code": "conflict", "message": "workflow has no materialized version"}}),
        ["COMPLETED"],
    )
    assert rc.main(["--api", "http://x", "--workflow", "wf-appr"], http=api) == 1
    err = capsys.readouterr().err
    assert "HTTP 409 (conflict)" in err
    assert "materialized" not in err and "tok-never-printed" not in err
    assert [m for m, _ in api.calls] == ["POST"]  # no work enqueued, nothing awaited


def test_unsafe_error_code_is_not_echoed() -> None:
    assert rc.sanitized_code(b'{"error":{"code":"x y <script>"}}') == "unsafe"
    assert rc.sanitized_code(b"<html>proxy error</html>") == "unparseable"


def test_run_no_worker_picks_up_fails_at_the_deadline() -> None:
    now = [0.0]

    def clock() -> float:
        return now[0]

    def sleep(s: float) -> None:
        now[0] += s

    api = FakeApi((201, {"id": RUN_ID}), ["PENDING"])
    with pytest.raises(rc.CheckFailed, match="no worker finished the run within 5s"):
        rc.wait_for_worker(api, "http://x", {}, RUN_ID, deadline_s=5, clock=clock, sleep=sleep)


def test_failed_run_fails_the_check() -> None:
    api = FakeApi((201, {"id": RUN_ID}), ["FAILED"])
    assert rc.main(["--api", "http://x", "--workflow", "wf-run"], http=api) == 1


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize(
    ("workflows", "expected", "ok"),
    [
        ([APPROVAL, RUNNABLE], "wf-run", True),  # API order: newest (approval) first
        ([RUNNABLE, APPROVAL], "wf-run", True),  # reversed order: same answer
        ([APPROVAL, RUNNABLE], "wf-appr", False),  # version-less workflow refused
        ([APPROVAL], "wf-run", False),  # not visible in tenant A
        ([RUNNABLE], "", False),  # seed export missing
    ],
)
def test_seed_selects_the_exported_runnable_workflow_not_list_order(
    workflows: list[dict[str, object]], expected: str, ok: bool
) -> None:
    script = (
        "import { selectRunnableWorkflow } from './tests/load/seed_staging.mjs';"
        f"try {{ console.log(selectRunnableWorkflow({json.dumps(workflows)}, "
        f"{json.dumps(expected)})); }}"
        " catch (e) { console.log('ERR'); }"
    )
    out = subprocess.run(
        ["node", "--input-type=module", "-e", script], cwd=ROOT, capture_output=True, text=True
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == (expected if ok else "ERR")


def test_workflow_step_is_strict_and_seed_exports_the_runnable_id() -> None:
    wf = (ROOT / ".github" / "workflows" / "staging-validation.yml").read_text()
    step = wf[wf.index("Verify credentials + DB roles") : wf.index("Assert rate limits RAISED")]
    assert "|| true" not in step and "sleep 5" not in step and "pg_stat_activity" not in step
    assert "scripts/ci/staging_role_check.py" in step and "TENANT_A_WORKFLOW_ID" in step
    seed = (ROOT / "web" / "e2e" / "seed.mjs").read_text()
    assert "E2E_RUNNABLE_WORKFLOW_ID=${wf}" in seed
    load = (ROOT / "tests" / "load" / "seed_staging.mjs").read_text()
    assert "aWorkflows[0]" not in load


def test_former_list_order_choice_reproduces_the_409_and_now_fails_the_step(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pre-fix step took ``aWorkflows[0]`` (newest first = the version-less
    approval workflow) and hid the 409 behind ``|| true``. The same choice now
    fails the step; the exported runnable id reaches a worker-set COMPLETED."""
    listed = [APPROVAL, RUNNABLE]  # GET /workflows order: created_at DESC
    by_workflow = {
        "wf-appr": (409, {"error": {"code": "conflict", "message": "no current version"}}),
        "wf-run": (201, {"id": RUN_ID}),
    }
    calls: list[tuple[str, str]] = []

    def api(method: str, url: str, headers: dict[str, str]) -> tuple[int, bytes]:
        calls.append((method, url))
        if method == "POST":
            code, body = by_workflow[url.split("/workflows/")[1].split("/")[0]]
            return code, json.dumps(body).encode()
        return 200, json.dumps({"id": RUN_ID, "status": "COMPLETED"}).encode()

    monkeypatch.setattr(rc.time, "sleep", lambda _s: None)
    former_choice = str(listed[0]["id"])
    assert former_choice == "wf-appr"
    assert rc.main(["--api", "http://x", "--workflow", former_choice], http=api) == 1
    assert "HTTP 409 (conflict)" in capsys.readouterr().err
    assert [m for m, _ in calls] == ["POST"]
    calls.clear()
    assert rc.main(["--api", "http://x", "--workflow", str(RUNNABLE["id"])], http=api) == 0
    assert [m for m, _ in calls] == ["POST", "GET"]


@pytest.mark.parametrize(
    ("body", "match"),
    [
        (b'{"status": "PWNED token=abc"}', r"status unrecognised"),
        (b'{"status": "PARTIAL"}', r"status unrecognised"),
        (b"<html>gateway</html>", r"unparseable body"),
        (b'["not", "an", "object"]', r"unparseable body"),
    ],
)
def test_only_allowlisted_run_statuses_are_ever_printed(body: bytes, match: str) -> None:
    now = [0.0]

    def api(method: str, url: str, headers: dict[str, str]) -> tuple[int, bytes]:
        return 200, body

    def sleep(s: float) -> None:
        now[0] += s

    with pytest.raises(rc.CheckFailed, match=match) as exc:
        rc.wait_for_worker(
            api, "http://x", {}, RUN_ID, deadline_s=2, clock=lambda: now[0], sleep=sleep
        )
    assert "PWNED" not in str(exc.value) and "gateway" not in str(exc.value)
