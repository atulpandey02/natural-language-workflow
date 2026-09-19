"""Deterministic Tool Registry.

Static catalog of capabilities. Only registered tools execute; the LLM never
executes code. A tool is either connector-less (pure) or connector-backed
(requires a connector of ``connector_type``).
"""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import BaseModel

from nlw.connectors.base import ConnectorContext


class ToolCategory(StrEnum):
    DATA = "data"
    PROCESSING = "processing"
    ACTION = "action"


class UnknownToolError(Exception):
    """Requested tool is not registered."""


class DuplicateToolError(Exception):
    """A tool with this name is already registered."""


class ToolExecutionError(Exception):
    """A tool signalled a deterministic execution failure."""


ToolCallable = Callable[[BaseModel, ConnectorContext | None], dict[str, Any]]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    category: ToolCategory
    connector_type: str | None  # None = connector-less (pure)
    input_model: type[BaseModel]
    read_only: bool
    requires_approval: bool
    # Metadata only in M4 — NOT enforced as a hard timeout (see ADR-006).
    timeout_seconds: int
    execute: ToolCallable


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise DuplicateToolError(spec.name)
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise UnknownToolError(name) from exc

    def available_for(self, owned_connector_types: set[str]) -> list[ToolSpec]:
        return [
            spec
            for spec in self._tools.values()
            if spec.connector_type is None or spec.connector_type in owned_connector_types
        ]

    def all(self) -> list[ToolSpec]:
        return list(self._tools.values())


REGISTRY = ToolRegistry()
