"""Planner orchestration + structured-output parsing (M6).

Uses a scripted async provider (no network, no key) to prove the pipeline:
valid output -> feasibility verdict; invalid output -> PLANNER_INVALID_OUTPUT.
"""

import pytest

import nlw.tools.builtin  # noqa: F401,E402
from nlw.feasibility.engine import FeasibilityCode, FeasibilityStatus
from nlw.feasibility.limits import DEFAULT_LIMITS
from nlw.planner.capabilities import CapabilityView, build_capability_view
from nlw.planner.planner import plan_and_check
from nlw.planner.provider import (
    LLMInvalidOutputError,
    LLMRequest,
    LLMResult,
    StubLLMProvider,
    parse_planner_output,
)
from nlw.registry.registry import REGISTRY


class ScriptedProvider:
    """Returns a fixed raw JSON payload as the model output."""

    model = "scripted"

    def __init__(self, raw_json: str) -> None:
        self._raw = raw_json

    async def generate_plan(self, req: LLMRequest) -> LLMResult:
        return LLMResult(raw_json=self._raw, model=self.model)


def _view() -> CapabilityView:
    return build_capability_view(REGISTRY.all(), [])


def _tool_names() -> set[str]:
    return {s.name for s in REGISTRY.all()}


# --- Parsing ---


def test_parse_valid_output() -> None:
    raw = '{"workflow_name": "wf", "steps": [{"id": "a", "tool": "fake.echo"}]}'
    out = parse_planner_output(raw)
    assert out.workflow_name == "wf"
    assert out.steps[0].tool == "fake.echo"


def test_parse_rejects_extra_keys() -> None:
    raw = '{"workflow_name": "wf", "steps": [], "sneaky": true}'
    with pytest.raises(LLMInvalidOutputError):
        parse_planner_output(raw)


def test_parse_rejects_bad_json() -> None:
    with pytest.raises(LLMInvalidOutputError):
        parse_planner_output("not json {")


def test_parse_rejects_bad_step_id() -> None:
    raw = '{"workflow_name": "wf", "steps": [{"id": "bad id!", "tool": "fake.echo"}]}'
    with pytest.raises(LLMInvalidOutputError):
        parse_planner_output(raw)


# --- Orchestration ---


async def test_plan_and_check_pass() -> None:
    provider = ScriptedProvider(
        '{"workflow_name": "echo wf", "steps": [{"id": "a", "tool": "fake.echo"}]}'
    )
    result = await plan_and_check(
        provider=provider,
        view=_view(),
        all_tool_names=_tool_names(),
        limits=DEFAULT_LIMITS,
        user_request="echo hi",
        max_output_tokens=1024,
        timeout_s=10,
    )
    assert result.report.status == FeasibilityStatus.PASS
    assert result.workflow_name == "echo wf"


async def test_plan_and_check_invalid_output_is_reject() -> None:
    provider = ScriptedProvider("totally not json")
    result = await plan_and_check(
        provider=provider,
        view=_view(),
        all_tool_names=_tool_names(),
        limits=DEFAULT_LIMITS,
        user_request="do something",
        max_output_tokens=1024,
        timeout_s=10,
    )
    assert result.report.status == FeasibilityStatus.REJECT
    assert result.output is None
    assert any(f.code == FeasibilityCode.PLANNER_INVALID_OUTPUT for f in result.report.findings)


async def test_plan_and_check_unknown_tool_is_reject() -> None:
    provider = ScriptedProvider('{"workflow_name": "x", "steps": [{"id": "a", "tool": "made.up"}]}')
    result = await plan_and_check(
        provider=provider,
        view=_view(),
        all_tool_names=_tool_names(),
        limits=DEFAULT_LIMITS,
        user_request="x",
        max_output_tokens=1024,
        timeout_s=10,
    )
    assert result.report.status == FeasibilityStatus.REJECT


async def test_stub_provider_requests_clarification() -> None:
    result = await plan_and_check(
        provider=StubLLMProvider(),
        view=_view(),
        all_tool_names=_tool_names(),
        limits=DEFAULT_LIMITS,
        user_request="anything",
        max_output_tokens=1024,
        timeout_s=10,
    )
    assert result.report.status == FeasibilityStatus.NEEDS_CLARIFICATION
