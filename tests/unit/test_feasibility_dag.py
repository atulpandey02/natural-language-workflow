"""DAG validation (Kahn) unit tests (M6)."""

from pydantic import BaseModel, ConfigDict

from nlw.domain.workflow import WorkflowPlan
from nlw.feasibility.engine import FeasibilityCode, FeasibilityStatus, check_plan
from nlw.feasibility.limits import DEFAULT_LIMITS, PlatformLimits
from nlw.planner.capabilities import CapabilityView, ToolCapability


class _Args(BaseModel):
    model_config = ConfigDict(extra="allow")


def _view() -> CapabilityView:
    return CapabilityView(
        tools=[
            ToolCapability(
                name="t",
                description="",
                category="processing",
                connector_type=None,
                read_only=True,
                requires_approval=False,
                timeout_seconds=1,
                input_model=_Args,
            )
        ],
        connectors=[],
    )


def _plan(steps: list[dict[str, object]]) -> WorkflowPlan:
    return WorkflowPlan.model_validate({"steps": steps})


TOOLS = {"t"}


def _codes(plan: WorkflowPlan) -> set[FeasibilityCode]:
    return {f.code for f in check_plan(plan, _view(), DEFAULT_LIMITS, TOOLS).findings}


def test_linear_chain_ok() -> None:
    plan = _plan(
        [
            {"id": "a", "tool": "t"},
            {"id": "b", "tool": "t", "depends_on": ["a"]},
            {"id": "c", "tool": "t", "depends_on": ["b"]},
        ]
    )
    assert check_plan(plan, _view(), DEFAULT_LIMITS, TOOLS).status == FeasibilityStatus.PASS


def test_diamond_ok() -> None:
    plan = _plan(
        [
            {"id": "a", "tool": "t"},
            {"id": "b", "tool": "t", "depends_on": ["a"]},
            {"id": "c", "tool": "t", "depends_on": ["a"]},
            {"id": "d", "tool": "t", "depends_on": ["b", "c"]},
        ]
    )
    assert check_plan(plan, _view(), DEFAULT_LIMITS, TOOLS).status == FeasibilityStatus.PASS


def test_unknown_dependency() -> None:
    plan = _plan([{"id": "a", "tool": "t", "depends_on": ["ghost"]}])
    assert FeasibilityCode.UNKNOWN_DEPENDENCY in _codes(plan)


def test_self_dependency() -> None:
    plan = _plan([{"id": "a", "tool": "t", "depends_on": ["a"]}])
    assert FeasibilityCode.SELF_DEPENDENCY in _codes(plan)


def test_two_node_cycle() -> None:
    plan = _plan(
        [
            {"id": "a", "tool": "t", "depends_on": ["b"]},
            {"id": "b", "tool": "t", "depends_on": ["a"]},
        ]
    )
    assert FeasibilityCode.CYCLE_DETECTED in _codes(plan)


def test_three_node_cycle() -> None:
    plan = _plan(
        [
            {"id": "a", "tool": "t", "depends_on": ["c"]},
            {"id": "b", "tool": "t", "depends_on": ["a"]},
            {"id": "c", "tool": "t", "depends_on": ["b"]},
        ]
    )
    assert FeasibilityCode.CYCLE_DETECTED in _codes(plan)


def test_too_many_dependencies() -> None:
    limits = PlatformLimits(max_depends_on_per_step=2)
    plan = _plan(
        [
            {"id": "a", "tool": "t"},
            {"id": "b", "tool": "t"},
            {"id": "c", "tool": "t"},
            {"id": "d", "tool": "t", "depends_on": ["a", "b", "c"]},
        ]
    )
    codes = {f.code for f in check_plan(plan, _view(), limits, TOOLS).findings}
    assert FeasibilityCode.TOO_MANY_DEPENDENCIES in codes
