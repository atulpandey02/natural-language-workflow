"""Deterministic, side-effect-free tools for the durable engine (M3 only).

These exist to prove execution durability without any real connector, network,
or external side effect. Purity is what makes at-least-once redelivery safe in
M3. Real tools (with idempotency keys for side effects) arrive in later
milestones.
"""

from collections.abc import Callable
from typing import Any


class UnknownToolError(Exception):
    """Raised when a plan references a tool that is not registered."""


class ToolExecutionError(Exception):
    """Raised by a tool to signal deterministic failure."""


def _echo(args: dict[str, Any]) -> dict[str, Any]:
    return {"echo": args}


def _fail(args: dict[str, Any]) -> dict[str, Any]:
    raise ToolExecutionError("fake.fail")


FAKE_TOOLS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "fake.echo": _echo,
    "fake.fail": _fail,
}


def run_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Execute a registered fake tool. Unknown tool -> UnknownToolError."""
    try:
        tool = FAKE_TOOLS[name]
    except KeyError as exc:
        raise UnknownToolError(name) from exc
    return tool(args)
