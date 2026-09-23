"""Deterministic planner context budget (M12B-A, Part G / F4).

An over-budget prompt or tool catalog is REJECTED before any provider call,
never silently truncated (truncating a schema/constraint would be a security
regression). Normal small prompts pass.
"""

import pytest

from nlw.planner.budget import (
    MAX_TOOL_DESCRIPTION_CHARS,
    MAX_USER_PROMPT_CHARS,
    PromptBudgetError,
    assert_prompt_within_budget,
    assert_tool_catalog_within_budget,
)


def test_normal_prompt_and_catalog_pass() -> None:
    assert_prompt_within_budget("system instructions", '{"user_request": "list people"}')
    assert_tool_catalog_within_budget(["fake.echo: echo input", "postgres.query: read-only SELECT"])


def test_oversized_user_prompt_is_rejected_not_truncated() -> None:
    with pytest.raises(PromptBudgetError, match="capability view too large"):
        assert_prompt_within_budget("sys", "x" * (MAX_USER_PROMPT_CHARS + 1))


def test_oversized_tool_description_is_rejected() -> None:
    with pytest.raises(PromptBudgetError):
        assert_tool_catalog_within_budget(["ok", "y" * (MAX_TOOL_DESCRIPTION_CHARS + 1)])


def test_too_many_tools_is_rejected() -> None:
    with pytest.raises(PromptBudgetError, match="too many tools"):
        assert_tool_catalog_within_budget(["t"] * 101)
