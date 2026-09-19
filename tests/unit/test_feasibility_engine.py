"""Deterministic feasibility matrix (M6).

Pure unit tests over ``check_plan``: tool availability, connector compatibility,
argument validation, limits, approval/clarification, and status precedence. No
DB, no LLM. Uses a small in-test registry projection so cases are explicit.
"""

from pydantic import BaseModel, ConfigDict

from nlw.domain.workflow import WorkflowPlan
from nlw.feasibility.engine import (
    FeasibilityCode,
    FeasibilityStatus,
    Severity,
    check_plan,
)
from nlw.feasibility.limits import DEFAULT_LIMITS, PlatformLimits
from nlw.planner.capabilities import CapabilityView, SafeConnector, ToolCapability


class EchoArgs(BaseModel):
    model_config = ConfigDict(extra="allow")


class NoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _tool(
    name: str,
    *,
    connector_type: str | None = None,
    requires_approval: bool = False,
    timeout: int = 30,
    input_model: type[BaseModel] = EchoArgs,
) -> ToolCapability:
    return ToolCapability(
        name=name,
        description="",
        category="processing",
        connector_type=connector_type,
        read_only=True,
        requires_approval=requires_approval,
        timeout_seconds=timeout,
        input_model=input_model,
    )


def _view(
    tools: list[ToolCapability], connectors: list[SafeConnector] | None = None
) -> CapabilityView:
    return CapabilityView(tools=tools, connectors=connectors or [])


def _plan(steps: list[dict[str, object]]) -> WorkflowPlan:
    return WorkflowPlan.model_validate({"steps": steps})


ALL_TOOLS = {"fake.echo", "static.echo", "postgres.query", "needs.approval"}


# --- PASS ---


def test_pass_simple_connectorless() -> None:
    view = _view([_tool("fake.echo")])
    report = check_plan(_plan([{"id": "a", "tool": "fake.echo"}]), view, DEFAULT_LIMITS, ALL_TOOLS)
    assert report.status == FeasibilityStatus.PASS
    assert report.normalized_plan is not None


def test_pass_with_dependencies() -> None:
    view = _view([_tool("fake.echo")])
    plan = _plan(
        [
            {"id": "a", "tool": "fake.echo"},
            {"id": "b", "tool": "fake.echo", "depends_on": ["a"]},
        ]
    )
    assert check_plan(plan, view, DEFAULT_LIMITS, ALL_TOOLS).status == FeasibilityStatus.PASS


# --- Tool availability ---


def test_unknown_tool_rejected() -> None:
    view = _view([_tool("fake.echo")])
    report = check_plan(_plan([{"id": "a", "tool": "nope.tool"}]), view, DEFAULT_LIMITS, ALL_TOOLS)
    assert report.status == FeasibilityStatus.REJECT
    assert any(f.code == FeasibilityCode.UNKNOWN_TOOL for f in report.findings)


def test_tool_exists_but_not_available_to_tenant() -> None:
    # postgres.query exists in the registry but is filtered out of the view.
    view = _view([_tool("fake.echo")])
    report = check_plan(
        _plan([{"id": "a", "tool": "postgres.query", "connector": "pg"}]),
        view,
        DEFAULT_LIMITS,
        ALL_TOOLS,
    )
    assert report.status == FeasibilityStatus.REJECT
    assert any(f.code == FeasibilityCode.TOOL_NOT_AVAILABLE for f in report.findings)


# --- Connector compatibility ---


def test_connector_required_but_missing() -> None:
    view = _view(
        [_tool("static.echo", connector_type="static")],
        [SafeConnector(name="s1", type="static", status="active")],
    )
    report = check_plan(
        _plan([{"id": "a", "tool": "static.echo"}]), view, DEFAULT_LIMITS, ALL_TOOLS
    )
    assert any(f.code == FeasibilityCode.CONNECTOR_REQUIRED for f in report.findings)


def test_connector_not_found() -> None:
    view = _view(
        [_tool("static.echo", connector_type="static")],
        [SafeConnector(name="s1", type="static", status="active")],
    )
    report = check_plan(
        _plan([{"id": "a", "tool": "static.echo", "connector": "other"}]),
        view,
        DEFAULT_LIMITS,
        ALL_TOOLS,
    )
    assert any(f.code == FeasibilityCode.CONNECTOR_NOT_FOUND for f in report.findings)


def test_connector_type_mismatch() -> None:
    view = _view(
        [_tool("static.echo", connector_type="static")],
        [SafeConnector(name="pg", type="postgres", status="active")],
    )
    report = check_plan(
        _plan([{"id": "a", "tool": "static.echo", "connector": "pg"}]),
        view,
        DEFAULT_LIMITS,
        ALL_TOOLS,
    )
    assert any(f.code == FeasibilityCode.CONNECTOR_TYPE_MISMATCH for f in report.findings)


def test_disabled_connector_rejected() -> None:
    # The tool is present in the view because we inject it; the specific
    # connector referenced is disabled -> reject.
    view = _view(
        [_tool("static.echo", connector_type="static")],
        [
            SafeConnector(name="ok", type="static", status="active"),
            SafeConnector(name="off", type="static", status="disabled"),
        ],
    )
    report = check_plan(
        _plan([{"id": "a", "tool": "static.echo", "connector": "off"}]),
        view,
        DEFAULT_LIMITS,
        ALL_TOOLS,
    )
    assert report.status == FeasibilityStatus.REJECT
    assert any(f.code == FeasibilityCode.CONNECTOR_UNUSABLE for f in report.findings)


def test_error_connector_is_recoverable_and_passes() -> None:
    view = _view(
        [_tool("static.echo", connector_type="static")],
        [SafeConnector(name="s1", type="static", status="error")],
    )
    report = check_plan(
        _plan([{"id": "a", "tool": "static.echo", "connector": "s1"}]),
        view,
        DEFAULT_LIMITS,
        ALL_TOOLS,
    )
    assert report.status == FeasibilityStatus.PASS
    assert any(f.code == FeasibilityCode.CONNECTOR_HEALTH_UNVERIFIED for f in report.findings)


def test_unchecked_connector_is_usable() -> None:
    view = _view(
        [_tool("static.echo", connector_type="static")],
        [SafeConnector(name="s1", type="static", status="unchecked")],
    )
    report = check_plan(
        _plan([{"id": "a", "tool": "static.echo", "connector": "s1"}]),
        view,
        DEFAULT_LIMITS,
        ALL_TOOLS,
    )
    assert report.status == FeasibilityStatus.PASS


def test_connector_on_connectorless_tool_rejected() -> None:
    view = _view([_tool("fake.echo")], [SafeConnector(name="s1", type="static", status="active")])
    report = check_plan(
        _plan([{"id": "a", "tool": "fake.echo", "connector": "s1"}]),
        view,
        DEFAULT_LIMITS,
        ALL_TOOLS,
    )
    assert any(f.code == FeasibilityCode.CONNECTOR_ON_CONNECTORLESS_TOOL for f in report.findings)


# --- Argument validation ---


def test_arg_validation_failure() -> None:
    view = _view([_tool("strict", input_model=NoArgs)])
    report = check_plan(
        _plan([{"id": "a", "tool": "strict", "args": {"unexpected": 1}}]),
        view,
        DEFAULT_LIMITS,
        {"strict"},
    )
    assert report.status == FeasibilityStatus.REJECT
    assert any(f.code == FeasibilityCode.ARG_VALIDATION_FAILED for f in report.findings)


# --- Structural / limits ---


def test_empty_plan_without_clarification_rejected() -> None:
    report = check_plan(_plan([]), _view([]), DEFAULT_LIMITS, ALL_TOOLS)
    assert report.status == FeasibilityStatus.REJECT
    assert any(f.code == FeasibilityCode.EMPTY_PLAN for f in report.findings)


def test_empty_plan_with_clarification_is_needs_clarification() -> None:
    report = check_plan(
        _plan([]),
        _view([]),
        DEFAULT_LIMITS,
        ALL_TOOLS,
        clarification_requested=True,
        clarification_questions=["which table?"],
    )
    assert report.status == FeasibilityStatus.NEEDS_CLARIFICATION
    assert report.clarification_questions == ["which table?"]


def test_duplicate_step_ids_rejected() -> None:
    view = _view([_tool("fake.echo")])
    report = check_plan(
        _plan([{"id": "a", "tool": "fake.echo"}, {"id": "a", "tool": "fake.echo"}]),
        view,
        DEFAULT_LIMITS,
        ALL_TOOLS,
    )
    assert any(f.code == FeasibilityCode.DUPLICATE_STEP_ID for f in report.findings)


def test_too_many_steps_rejected() -> None:
    view = _view([_tool("fake.echo")])
    limits = PlatformLimits(max_steps=2)
    plan = _plan([{"id": f"s{i}", "tool": "fake.echo"} for i in range(3)])
    report = check_plan(plan, view, limits, ALL_TOOLS)
    assert any(f.code == FeasibilityCode.TOO_MANY_STEPS for f in report.findings)


def test_step_timeout_exceeded() -> None:
    view = _view([_tool("slow", timeout=1000)])
    limits = PlatformLimits(max_step_timeout_seconds=100)
    report = check_plan(_plan([{"id": "a", "tool": "slow"}]), view, limits, {"slow"})
    assert any(f.code == FeasibilityCode.STEP_TIMEOUT_EXCEEDED for f in report.findings)


def test_total_timeout_exceeded() -> None:
    view = _view([_tool("t", timeout=100)])
    limits = PlatformLimits(max_step_timeout_seconds=100, max_total_timeout_seconds=150)
    plan = _plan([{"id": "a", "tool": "t"}, {"id": "b", "tool": "t"}])
    report = check_plan(plan, view, limits, {"t"})
    assert any(f.code == FeasibilityCode.TOTAL_TIMEOUT_EXCEEDED for f in report.findings)


# --- Approval / clarification / precedence ---


def test_approval_required_status() -> None:
    view = _view([_tool("needs.approval", requires_approval=True)])
    report = check_plan(
        _plan([{"id": "a", "tool": "needs.approval"}]), view, DEFAULT_LIMITS, ALL_TOOLS
    )
    assert report.status == FeasibilityStatus.NEEDS_APPROVAL
    assert report.approvals_required == ["a"]


def test_clarification_on_valid_plan() -> None:
    view = _view([_tool("fake.echo")])
    report = check_plan(
        _plan([{"id": "a", "tool": "fake.echo"}]),
        view,
        DEFAULT_LIMITS,
        ALL_TOOLS,
        clarification_requested=True,
        clarification_questions=["confirm?"],
    )
    assert report.status == FeasibilityStatus.NEEDS_CLARIFICATION


def test_precedence_reject_beats_clarify_and_approve() -> None:
    # A plan that is both approval-worthy and unknown-tool must REJECT.
    view = _view([_tool("needs.approval", requires_approval=True)])
    plan = _plan(
        [
            {"id": "a", "tool": "needs.approval"},
            {"id": "b", "tool": "does.not.exist"},
        ]
    )
    report = check_plan(plan, view, DEFAULT_LIMITS, ALL_TOOLS, clarification_requested=True)
    assert report.status == FeasibilityStatus.REJECT


def test_reject_has_no_normalized_plan() -> None:
    view = _view([_tool("fake.echo")])
    report = check_plan(_plan([{"id": "a", "tool": "x"}]), view, DEFAULT_LIMITS, ALL_TOOLS)
    assert report.status == FeasibilityStatus.REJECT
    assert report.normalized_plan is None


def test_all_findings_are_secret_safe_severity_enum() -> None:
    view = _view([_tool("fake.echo")])
    report = check_plan(_plan([{"id": "a", "tool": "fake.echo"}]), view, DEFAULT_LIMITS, ALL_TOOLS)
    for f in report.findings:
        assert f.severity in set(Severity)
