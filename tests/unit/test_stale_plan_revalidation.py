"""Stale-plan re-validation classifier (M12B-A addendum, Part 2).

Deterministic tests that distinguish the stable outcomes a previously-accepted
plan can re-validate to — FRESH / STALE_PLAN / POLICY_DENIED / INVALID_PLAN —
and confirm these are separate from the transient-infra and
ACTION_OUTCOME_UNKNOWN concepts (which this module never produces).
"""

from nlw.domain.workflow import WorkflowPlan
from nlw.feasibility.limits import DEFAULT_LIMITS
from nlw.feasibility.revalidation import RevalidationOutcome, revalidate_plan
from nlw.planner.capabilities import SafeConnector, build_capability_view
from nlw.planner.schema import PlannerOutput
from nlw.registry.registry import REGISTRY

import nlw.tools.builtin  # noqa: F401  isort:skip

ALL = {s.name for s in REGISTRY.all()}
PG = SafeConnector(
    name="pg",
    type="postgres",
    status="active",
    allowed_schemas=["public"],
    allowed_tables=["public.people"],
)


def _plan(sql: str = "SELECT id FROM public.people", tool: str = "postgres.query") -> WorkflowPlan:
    return PlannerOutput.model_validate(
        {
            "workflow_name": "x",
            "steps": [{"id": "a", "tool": tool, "args": {"sql": sql}, "connector": "pg"}],
        }
    ).to_workflow_plan()


def _reval(plan: WorkflowPlan, connectors: list[SafeConnector]) -> RevalidationOutcome:
    view = build_capability_view(REGISTRY.all(), connectors, include_demo=True)
    return revalidate_plan(plan, view, DEFAULT_LIMITS, ALL).outcome


def test_fresh_when_state_unchanged() -> None:
    assert _reval(_plan(), [PG]) == RevalidationOutcome.FRESH


def test_stale_when_connector_removed() -> None:
    r = revalidate_plan(
        _plan(), build_capability_view(REGISTRY.all(), [], include_demo=True), DEFAULT_LIMITS, ALL
    )
    assert r.outcome == RevalidationOutcome.STALE_PLAN
    assert r.reason_code == "TOOL_NOT_AVAILABLE"  # stable, low-cardinality
    assert "connector or tool" in r.message.lower()
    assert "pg" not in r.message  # sanitized: no connector/db internals leaked


def test_stale_when_connector_disabled() -> None:
    disabled = SafeConnector(
        name="pg",
        type="postgres",
        status="disabled",
        allowed_schemas=["public"],
        allowed_tables=["public.people"],
    )
    assert _reval(_plan(), [disabled]) == RevalidationOutcome.STALE_PLAN


def test_stale_when_connector_type_changed() -> None:
    # The name still resolves but to a different type (connector recreated).
    webhookish = SafeConnector(name="pg", type="webhook", status="active")
    assert _reval(_plan(), [webhookish]) == RevalidationOutcome.STALE_PLAN


def test_policy_denied_is_not_stale() -> None:
    # A SQL-policy rejection is forbidden regardless of freshness.
    r = revalidate_plan(
        _plan("DELETE FROM public.people"),
        build_capability_view(REGISTRY.all(), [PG], include_demo=True),
        DEFAULT_LIMITS,
        ALL,
    )
    assert r.outcome == RevalidationOutcome.POLICY_DENIED
    assert r.reason_code == "SQL_REJECTED"
    assert "policy" in r.message.lower()


def test_invalid_plan_is_distinct_from_stale() -> None:
    # A structurally malformed plan (cycle) classifies INVALID_PLAN, not STALE.
    cyclic = PlannerOutput.model_validate(
        {
            "workflow_name": "x",
            "steps": [
                {"id": "a", "tool": "fake.echo", "depends_on": ["b"]},
                {"id": "b", "tool": "fake.echo", "depends_on": ["a"]},
            ],
        }
    ).to_workflow_plan()
    r = revalidate_plan(
        cyclic, build_capability_view(REGISTRY.all(), [], include_demo=True), DEFAULT_LIMITS, ALL
    )
    assert r.outcome == RevalidationOutcome.INVALID_PLAN


def test_needs_approval_is_still_fresh() -> None:
    # An approval-gated action is executable (it pauses for approval, never
    # bypasses it) -> FRESH, not a block.
    plan = PlannerOutput.model_validate(
        {
            "workflow_name": "x",
            "steps": [
                {"id": "a", "tool": "webhook.send", "args": {"payload": {}}, "connector": "h"}
            ],
        }
    ).to_workflow_plan()
    hook = SafeConnector(name="h", type="webhook", status="active")
    assert _reval(plan, [hook]) == RevalidationOutcome.FRESH


def test_outcomes_are_the_documented_stable_set() -> None:
    assert {o.value for o in RevalidationOutcome} == {
        "FRESH",
        "STALE_PLAN",
        "POLICY_DENIED",
        "INVALID_PLAN",
    }
