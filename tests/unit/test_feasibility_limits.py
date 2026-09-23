"""Serialized-size bounds in feasibility (M12B-A, audit F1).

A plan is persisted verbatim into ``workflow_versions.plan`` and its step args
into ``step_runs.input``. Step-count/DAG bounds do not cap the BYTES a single arg
blob or the whole plan can carry, so an over-cap plan is rejected with a stable
code and never written to durable state. Security-critical content is rejected,
never silently truncated.
"""

from pydantic import BaseModel, ConfigDict

from nlw.domain.workflow import WorkflowPlan
from nlw.feasibility.engine import FeasibilityCode, FeasibilityStatus, check_plan
from nlw.feasibility.limits import DEFAULT_LIMITS, PlatformLimits
from nlw.planner.capabilities import CapabilityView, ToolCapability


class EchoArgs(BaseModel):
    model_config = ConfigDict(extra="allow")


def _view() -> CapabilityView:
    return CapabilityView(
        tools=[
            ToolCapability(
                name="fake.echo",
                description="",
                category="processing",
                connector_type=None,
                read_only=True,
                requires_approval=False,
                timeout_seconds=30,
                input_model=EchoArgs,
            )
        ],
        connectors=[],
    )


ALL = {"fake.echo"}


def _codes(report: object) -> set[FeasibilityCode]:
    return {f.code for f in report.findings}  # type: ignore[attr-defined]


def test_oversized_single_arg_rejected() -> None:
    big = "x" * (DEFAULT_LIMITS.max_step_args_bytes + 100)
    plan = WorkflowPlan.model_validate(
        {"steps": [{"id": "a", "tool": "fake.echo", "args": {"blob": big}}]}
    )
    report = check_plan(plan, _view(), DEFAULT_LIMITS, ALL)
    assert report.status == FeasibilityStatus.REJECT
    assert FeasibilityCode.ARGS_TOO_LARGE in _codes(report)
    # A finding names the offending step and never echoes the payload.
    offender = next(f for f in report.findings if f.code == FeasibilityCode.ARGS_TOO_LARGE)
    assert offender.step_id == "a"
    assert big not in offender.message
    assert report.normalized_plan is None  # not executable


def test_oversized_whole_plan_rejected_even_with_small_args() -> None:
    # Each arg under the per-step cap, but many steps push the whole plan over.
    limits = PlatformLimits(max_steps=1000, max_plan_bytes=20_000, max_step_args_bytes=16_384)
    steps = [{"id": f"s{i}", "tool": "fake.echo", "args": {"note": "y" * 200}} for i in range(200)]
    plan = WorkflowPlan.model_validate({"steps": steps})
    report = check_plan(plan, _view(), limits, ALL)
    assert report.status == FeasibilityStatus.REJECT
    assert FeasibilityCode.PLAN_TOO_LARGE in _codes(report)


def test_normal_plan_within_bounds_passes() -> None:
    plan = WorkflowPlan.model_validate(
        {"steps": [{"id": "a", "tool": "fake.echo", "args": {"note": "hello"}}]}
    )
    report = check_plan(plan, _view(), DEFAULT_LIMITS, ALL)
    assert report.status == FeasibilityStatus.PASS
    assert not (_codes(report) & {FeasibilityCode.ARGS_TOO_LARGE, FeasibilityCode.PLAN_TOO_LARGE})
