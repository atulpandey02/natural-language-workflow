"""Stale-plan re-validation (M12B-A addendum, Part 2).

A plan that was PASS/NEEDS_APPROVAL when it was materialized is never trusted to
still be executable. Before a run starts (and again when re-materializing), the
persisted plan is re-checked against the CURRENT authoritative capability state,
and the outcome is classified into one stable, product-level bucket:

- ``FRESH``        — still executable (PASS or NEEDS_APPROVAL; approval is
                     re-derived from the registry at execution, so a *strengthened*
                     approval requirement pauses the run, it does not bypass it);
- ``STALE_PLAN``   — was executable, now not, because relevant state changed: a
                     referenced connector was removed / disabled / type-changed /
                     un-owned, or a registry tool was removed or its argument
                     schema materially changed;
- ``POLICY_DENIED``— forbidden by current policy regardless of freshness (e.g. a
                     SQL-safety rejection);
- ``INVALID_PLAN`` — structurally invalid.

This is NOT a rename of connector errors: the classification is over the stable
``FeasibilityCode`` categories, and the boundary is authoritative — the planner
can never declare a plan fresh, and execution fails closed before any tool is
invoked. ``STALE_PLAN`` is non-retryable: the customer must re-plan (a new
proposal / a new workflow version), not simply retry.

Distinguished from ``ACTION_OUTCOME_UNKNOWN`` (a *transmitted* external action
whose result is ambiguous — see engine/actions.py) and from transient
infrastructure faults (which surface as 5xx and are retryable), neither of which
this module produces.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from nlw.domain.workflow import WorkflowPlan
from nlw.feasibility.engine import (
    FeasibilityCode,
    FeasibilityReport,
    FeasibilityStatus,
    Severity,
    check_plan,
)
from nlw.feasibility.limits import PlatformLimits
from nlw.planner.capabilities import CapabilityView


class RevalidationOutcome(enum.StrEnum):
    FRESH = "FRESH"
    STALE_PLAN = "STALE_PLAN"
    POLICY_DENIED = "POLICY_DENIED"
    INVALID_PLAN = "INVALID_PLAN"


# Reject codes that mean "the world changed since this plan was accepted".
_STALE_CODES = frozenset(
    {
        FeasibilityCode.TOOL_NOT_AVAILABLE,
        FeasibilityCode.UNKNOWN_TOOL,
        FeasibilityCode.CONNECTOR_NOT_FOUND,
        FeasibilityCode.CONNECTOR_TYPE_MISMATCH,
        FeasibilityCode.CONNECTOR_UNUSABLE,
        FeasibilityCode.CONNECTOR_REQUIRED,
        FeasibilityCode.CONNECTOR_ON_CONNECTORLESS_TOOL,
        FeasibilityCode.ARG_VALIDATION_FAILED,  # a tool's argument schema changed
    }
)
# Forbidden regardless of freshness.
_POLICY_CODES = frozenset({FeasibilityCode.SQL_REJECTED})

_REASONS: dict[RevalidationOutcome, str] = {
    RevalidationOutcome.STALE_PLAN: (
        "A connector or tool this workflow depends on has changed or is no longer "
        "available. Re-plan the request to continue."
    ),
    RevalidationOutcome.POLICY_DENIED: ("This workflow is not permitted by the current policy."),
    RevalidationOutcome.INVALID_PLAN: "This workflow is no longer valid.",
}


@dataclass(frozen=True)
class Revalidation:
    outcome: RevalidationOutcome
    # Stable, low-cardinality reason code (a FeasibilityCode value) or "" for FRESH.
    reason_code: str
    # Sanitized, member-safe message (never secrets or DB internals).
    message: str
    report: FeasibilityReport

    @property
    def fresh(self) -> bool:
        return self.outcome == RevalidationOutcome.FRESH


def revalidate_plan(
    plan: WorkflowPlan,
    view: CapabilityView,
    limits: PlatformLimits,
    all_tool_names: set[str],
) -> Revalidation:
    """Re-check a previously-accepted plan against current state and classify it."""
    report = check_plan(plan, view, limits, all_tool_names)
    if report.status in (FeasibilityStatus.PASS, FeasibilityStatus.NEEDS_APPROVAL):
        return Revalidation(RevalidationOutcome.FRESH, "", "", report)

    reject_codes = [f.code for f in report.findings if f.severity == Severity.REJECT]
    code_set = set(reject_codes)
    if code_set & _STALE_CODES:
        outcome = RevalidationOutcome.STALE_PLAN
        dominant = next(c for c in reject_codes if c in _STALE_CODES)
    elif code_set & _POLICY_CODES:
        outcome = RevalidationOutcome.POLICY_DENIED
        dominant = next(c for c in reject_codes if c in _POLICY_CODES)
    else:
        outcome = RevalidationOutcome.INVALID_PLAN
        dominant = reject_codes[0] if reject_codes else FeasibilityCode.EMPTY_PLAN
    return Revalidation(outcome, dominant.value, _REASONS[outcome], report)
