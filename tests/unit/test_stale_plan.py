"""Feasibility as an execution gate — stale-plan detection (M12B-A, Part E, F7).

A plan that PASSed earlier is never trusted: it is re-checked against the CURRENT
authoritative capability state before it can execute. These unit tests prove the
gate deterministically: when a connector or tool that a plan depends on is
removed/disabled/loses availability, the SAME plan re-checks to a clean REJECT
(never a partial execution). This mirrors what the materialize endpoint does
("never trust the stored PASS") and what the worker re-validates per step.
"""

from nlw.feasibility.engine import FeasibilityStatus, check_plan
from nlw.feasibility.limits import DEFAULT_LIMITS
from nlw.planner.capabilities import SafeConnector, build_capability_view
from nlw.planner.schema import PlannerOutput
from nlw.registry.registry import REGISTRY

import nlw.tools.builtin  # noqa: F401  isort:skip

ALL = {s.name for s in REGISTRY.all()}
PG_ACTIVE = SafeConnector(
    name="pg",
    type="postgres",
    status="active",
    allowed_schemas=["public"],
    allowed_tables=["public.people"],
)
PLAN = PlannerOutput.model_validate(
    {
        "workflow_name": "x",
        "steps": [
            {
                "id": "a",
                "tool": "postgres.query",
                "args": {"sql": "SELECT id FROM public.people"},
                "connector": "pg",
            }
        ],
    }
)


def _check(connectors: list[SafeConnector]) -> FeasibilityStatus:
    view = build_capability_view(REGISTRY.all(), connectors, include_demo=True)
    return check_plan(PLAN.to_workflow_plan(), view, DEFAULT_LIMITS, ALL).status


def test_plan_passes_then_rejects_when_connector_removed() -> None:
    # t0: valid.
    assert _check([PG_ACTIVE]) == FeasibilityStatus.PASS
    # t1: the connector no longer exists -> the SAME plan is not executable.
    report = check_plan(
        PLAN.to_workflow_plan(),
        build_capability_view(REGISTRY.all(), [], include_demo=True),
        DEFAULT_LIMITS,
        ALL,
    )
    assert report.status == FeasibilityStatus.REJECT
    codes = {f.code.value for f in report.findings}
    # The tool is no longer available to the tenant (no usable postgres connector).
    assert "TOOL_NOT_AVAILABLE" in codes
    assert report.normalized_plan is None  # nothing executable


def test_plan_rejects_when_connector_disabled() -> None:
    disabled = SafeConnector(
        name="pg",
        type="postgres",
        status="disabled",
        allowed_schemas=["public"],
        allowed_tables=["public.people"],
    )
    # A disabled connector is not usable, so the tool is no longer offered and the
    # explicit reference is rejected — a clean, deterministic stop.
    report = check_plan(
        PLAN.to_workflow_plan(),
        build_capability_view(REGISTRY.all(), [disabled], include_demo=True),
        DEFAULT_LIMITS,
        ALL,
    )
    assert report.status == FeasibilityStatus.REJECT


def test_revalidation_is_pure_and_repeatable() -> None:
    # The gate is a pure function of (plan, current capabilities): same inputs ->
    # same verdict, so a re-check at materialize and at execution agree.
    assert _check([PG_ACTIVE]) == _check([PG_ACTIVE]) == FeasibilityStatus.PASS
