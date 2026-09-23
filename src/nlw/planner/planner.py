"""Planner orchestration (M6): propose a plan, then let deterministic code judge it.

Ties the pieces together: build the prompt from the tenant capability view, call
the async provider, strictly parse the structured output, and run the
deterministic feasibility engine which owns the final status. Provider
infrastructure faults propagate (the API maps them to 5xx); invalid model output
becomes a deterministic PLANNER_INVALID_OUTPUT reject.
"""

from dataclasses import dataclass

from nlw.feasibility.engine import FeasibilityReport, check_plan, planner_invalid_output_report
from nlw.feasibility.limits import PlatformLimits
from nlw.planner.budget import (
    assert_prompt_within_budget,
    assert_tool_catalog_within_budget,
)
from nlw.planner.capabilities import CapabilityView
from nlw.planner.prompt import build_system_prompt, build_user_prompt
from nlw.planner.provider import (
    LLMInvalidOutputError,
    LLMProvider,
    LLMRequest,
    parse_planner_output,
)
from nlw.planner.schema import PlannerOutput


@dataclass(frozen=True)
class PlanningResult:
    report: FeasibilityReport
    workflow_name: str
    model: str
    output: PlannerOutput | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None


async def plan_and_check(
    *,
    provider: LLMProvider,
    view: CapabilityView,
    all_tool_names: set[str],
    limits: PlatformLimits,
    user_request: str,
    max_output_tokens: int,
    timeout_s: int,
) -> PlanningResult:
    system = build_system_prompt()
    user = build_user_prompt(view, user_request, limits.max_steps)
    # Deterministic context budget (M12B-A, Part G): reject an over-budget prompt
    # or tool catalog BEFORE the provider call. Never truncate a schema/constraint.
    assert_tool_catalog_within_budget([t.description for t in view.tools])
    assert_prompt_within_budget(system, user)
    req = LLMRequest(
        system=system,
        user=user,
        output_schema=PlannerOutput.model_json_schema(),
        max_output_tokens=max_output_tokens,
        timeout_s=timeout_s,
    )
    # Infrastructure faults (timeout/unavailable/auth) intentionally propagate.
    result = await provider.generate_plan(req)

    try:
        output = parse_planner_output(result.raw_json)
    except LLMInvalidOutputError:
        return PlanningResult(
            report=planner_invalid_output_report(),
            workflow_name="invalid plan",
            model=result.model,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
        )

    plan = output.to_workflow_plan()
    report = check_plan(
        plan,
        view,
        limits,
        all_tool_names,
        clarification_requested=output.clarification_needed,
        clarification_questions=output.clarification_questions,
    )
    return PlanningResult(
        report=report,
        workflow_name=output.workflow_name,
        model=result.model,
        output=output,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
    )
