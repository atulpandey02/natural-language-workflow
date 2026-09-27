"""Opt-in launch-closure journeys for the existing isolated browser harness.

Run from the repository root with PILOT_LAUNCH_JOURNEYS=1 and
python -m pytest tests/integration/test_pilot_browser.py -p web.e2e.launch_journeys_plugin.
Only the browser spec is swapped (e2e/pilot-launch.spec.ts). The unchanged harness
still runs real local auth, API, feasibility, queue, worker and DB with the golden
planner and mock Slack transport, and still asserts exactly one mock delivery.
"""

import subprocess
from typing import Any

import pytest


@pytest.fixture(autouse=True)
def launch_journeys(monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    if os.environ.get("PILOT_LAUNCH_JOURNEYS") != "1":
        return
    import test_pilot_browser as harness

    original_run = subprocess.run

    def run_launch_spec(args: Any, *positional: Any, **kwargs: Any) -> Any:
        if isinstance(args, list) and "e2e/pilot-analytics.spec.ts" in args:
            args = [
                "e2e/pilot-launch.spec.ts" if arg == "e2e/pilot-analytics.spec.ts" else arg
                for arg in args
            ]
            # Four journeys in one run need more than the golden spec's budget.
            kwargs["timeout"] = max(int(kwargs.get("timeout") or 0), 600)
        return original_run(args, *positional, **kwargs)

    monkeypatch.setattr(harness.subprocess, "run", run_launch_spec)
