"""Deterministic Tool Registry.

Static catalog of capabilities. Only registered tools execute; the LLM never
executes code. A tool is either connector-less (pure) or connector-backed
(requires a connector of ``connector_type``).
"""

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpx
from pydantic import BaseModel

from nlw.connectors.base import ConnectorContext, ConnectorUnhealthyError


class ToolCategory(StrEnum):
    DATA = "data"
    PROCESSING = "processing"
    ACTION = "action"


class UnknownToolError(Exception):
    """Requested tool is not registered."""


class DuplicateToolError(Exception):
    """A tool with this name is already registered."""


class ToolExecutionError(Exception):
    """A tool signalled a deterministic execution failure (-> step FAILED)."""


class ActionAuthError(ToolExecutionError, ConnectorUnhealthyError):
    """Provider rejected the credential — deterministic + marks connector error."""


class RetryableActionError(Exception):
    """A transient failure that PROVABLY did NOT cause the side effect -> safe to
    retry with backoff. Either the request never left (DNS/pool/connect/TLS failure
    before any bytes were written) or a connector-specific contract makes retry
    safe (Slack HTTP 429 / Slack ``ok:false`` transient errors, where Slack
    documents the message as not delivered). A generic webhook 429 or 5xx is NOT
    retryable — it is ``AmbiguousActionError``, since an arbitrary receiver gives
    no guarantee it produced no effect. Contrast ``AmbiguousActionError``, where
    the request may already have taken effect.

    ``retry_after_s`` (when set, e.g. from a Slack 429 Retry-After) is honored,
    bounded.
    """

    def __init__(self, message: str, retry_after_s: float | None = None) -> None:
        super().__init__(message)
        self.retry_after_s = retry_after_s


class AmbiguousActionError(Exception):
    """The external request MAY have been transmitted but the outcome cannot be
    proven (write/read timeout after send, connection reset after send, total
    deadline after send, response protocol failure). It is NOT safely retryable
    -> the action becomes a terminal UNKNOWN outcome (no automatic resend)."""


ToolCallable = Callable[[BaseModel, ConnectorContext | None], dict[str, Any]]


@dataclass(frozen=True)
class ActionContext:
    """Passed to a side-effecting tool's execute_action(). ``idempotency_key`` is
    stable across every retry/resume of the same (run, step) action. ``transport``
    is injectable so tests drive the HTTP boundary without real networking."""

    idempotency_key: uuid.UUID
    attempt: int
    transport: httpx.BaseTransport | None = None


@dataclass(frozen=True)
class ActionResult:
    """A successful external action's safe result (no secrets, no full response)."""

    output: dict[str, Any]
    provider_request_id: str | None = None


# Side-effecting tools receive a connector (never None) and the action context.
ActionCallable = Callable[[BaseModel, ConnectorContext, ActionContext], ActionResult]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    category: ToolCategory
    connector_type: str | None  # None = connector-less (pure)
    input_model: type[BaseModel]
    read_only: bool
    requires_approval: bool
    # Metadata only — NOT enforced as a hard timeout (see ADR-006).
    timeout_seconds: int
    # Inline (read/processing) tools set ``execute`` and run in the M3 run-lock.
    execute: ToolCallable | None = None
    # Side-effecting (ACTION) tools set ``side_effecting=True`` + ``execute_action``
    # and run OUTSIDE the run-lock via the two-transaction pattern (ADR-013).
    side_effecting: bool = False
    execute_action: ActionCallable | None = None
    # An ENFORCED end-to-end idempotency contract with the receiver (the receiver
    # is contractually required AND verified to deduplicate on the stable
    # ``external_action_key``). This is NOT satisfied by merely sending an
    # Idempotency-Key header. Only a tool with this set True may safely REPLAY an
    # action whose transmission may have started (ADR-013 crash window); every
    # other side-effecting tool becomes terminal UNKNOWN instead of resending.
    # No current connector has such a contract, so this defaults to False.
    idempotent_delivery: bool = False

    def __post_init__(self) -> None:
        if self.side_effecting:
            if self.execute_action is None or self.execute is not None:
                raise ValueError(f"{self.name}: side-effecting tool needs execute_action only")
        elif self.execute is None or self.execute_action is not None:
            raise ValueError(f"{self.name}: inline tool needs execute only")


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
