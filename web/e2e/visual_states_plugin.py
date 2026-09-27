"""Opt-in visual evidence inputs for the existing isolated browser harness.

Run from the repository root with PILOT_VISUAL_STATES=1 and
python -m pytest tests/integration/test_pilot_browser.py -p web.e2e.visual_states_plugin.
Only the test planner response, mock HTTP outcome and browser spec are selected.
The unchanged harness still runs real auth, feasibility, queue, worker and DB,
and asserts exactly one mock delivery. No response or persisted state is forged.
"""

import json
import subprocess
from typing import Any

import pytest

from nlw.planner.provider import LLMRequest, LLMResult
from nlw.planner.schema import PlannerOutput


@pytest.fixture(autouse=True)
def visual_state_inputs(monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    if os.environ.get("PILOT_VISUAL_STATES") != "1":
        return
    import test_pilot_browser as harness

    class VisualProvider(harness.GoldenProvider):
        async def generate_plan(self, req: LLMRequest) -> LLMResult:
            context = json.loads(req.user.split("\n\n", 1)[1])
            prompt = context["user_request"].lower()
            if "visual partial" not in prompt and "visual failure" not in prompt:
                return await super().generate_plan(req)
            steps: list[dict[str, Any]] = []
            if "visual partial" in prompt:
                steps.append(
                    {
                        "id": "analyze",
                        "tool": "pilot.sales_analysis",
                        "args": {"dataset_version": "v1", "months": 6},
                    }
                )
            steps.append(
                {"id": "failure", "tool": "fake.fail", "depends_on": ["analyze"] if steps else []}
            )
            steps.append({"id": "skipped", "tool": "fake.echo", "depends_on": ["failure"]})
            output = PlannerOutput.model_validate(
                {"workflow_name": "Synthetic visual failure scenario", "steps": steps}
            )
            return LLMResult(raw_json=output.model_dump_json(), model="test-visual-state-1")

    monkeypatch.setattr(harness, "GoldenProvider", VisualProvider)
    monkeypatch.setenv("PILOT_DELIVERY_OUTCOME", "unknown")
    original_run = subprocess.run

    def run_visual_spec(args: Any, *positional: Any, **kwargs: Any) -> Any:
        if isinstance(args, list) and "e2e/pilot-analytics.spec.ts" in args:
            args = [
                "e2e/pilot-visual-states.spec.ts" if arg == "e2e/pilot-analytics.spec.ts" else arg
                for arg in args
            ]
        return original_run(args, *positional, **kwargs)

    monkeypatch.setattr(harness.subprocess, "run", run_visual_spec)
