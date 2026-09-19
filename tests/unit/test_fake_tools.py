"""Deterministic fake tools."""

import pytest

from nlw.tools.fake import ToolExecutionError, UnknownToolError, run_tool


def test_echo_returns_input() -> None:
    assert run_tool("fake.echo", {"x": 1}) == {"echo": {"x": 1}}


def test_fail_raises() -> None:
    with pytest.raises(ToolExecutionError):
        run_tool("fake.fail", {})


def test_unknown_tool_raises() -> None:
    with pytest.raises(UnknownToolError):
        run_tool("does.not.exist", {})
