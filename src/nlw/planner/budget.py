"""Deterministic planner context budget (M12B-A, Part G / audit F4).

Context budgeting for the planner already exists in pieces — the user-request
char cap (``llm_max_prompt_chars``), the per-connector ``schema_hint`` size cap,
the per-tenant connector cap, the output-token cap, and the plan step-count /
serialized-bytes bounds. This adds one explicit, deterministic backstop on the
WHOLE assembled prompt and on the tool catalog, so a pathological capability view
(many connectors, large hints) cannot silently produce an oversized prompt.

Rule: an over-budget prompt is **rejected**, never silently truncated —
truncating a tool's input schema or a policy constraint would be a security
regression. The caller surfaces this as a deterministic 422, before any provider
call.
"""

from __future__ import annotations

# Generous bounds for a ~10-15 customer/day product with a small tool registry.
# The system prompt is code (small); the user prompt carries the capability view
# + the (already char-capped) request.
MAX_SYSTEM_PROMPT_CHARS = 8_000
MAX_USER_PROMPT_CHARS = 60_000
MAX_TOOL_DESCRIPTIONS = 100
MAX_TOOL_DESCRIPTION_CHARS = 4_000


class PromptBudgetError(ValueError):
    """The assembled planner prompt exceeds a deterministic budget (fail closed)."""


def assert_prompt_within_budget(system: str, user: str) -> None:
    """Reject (never truncate) an over-budget assembled prompt."""
    if len(system) > MAX_SYSTEM_PROMPT_CHARS:
        raise PromptBudgetError("planner system prompt exceeds its budget")
    if len(user) > MAX_USER_PROMPT_CHARS:
        raise PromptBudgetError("planner prompt exceeds its budget (capability view too large)")


def assert_tool_catalog_within_budget(descriptions: list[str]) -> None:
    """Bound the number and size of tool descriptions shown to the model. Security-
    critical schemas are never trimmed — an over-budget catalog is rejected."""
    if len(descriptions) > MAX_TOOL_DESCRIPTIONS:
        raise PromptBudgetError("too many tools to present to the planner")
    for d in descriptions:
        if len(d) > MAX_TOOL_DESCRIPTION_CHARS:
            raise PromptBudgetError("a tool description exceeds its budget")
