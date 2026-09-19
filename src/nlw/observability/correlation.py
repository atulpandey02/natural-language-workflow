"""Request/task correlation IDs (M9, ADR-016).

``run_id`` is the durable end-to-end correlation key for workflow execution;
this module adds a lightweight per-request/per-task ``request_id`` for the
control plane and binds it into structlog's contextvars so every log line in the
scope carries it. Contextvars are cleared at each boundary so a pooled worker
thread or a reused event-loop task never inherits a previous request's context.

Inbound IDs are NOT trusted by default: the server mints a UUID. When inbound
IDs are explicitly enabled, they are still strictly validated and length-bounded.
"""

import re
import uuid

import structlog

# Conservative inbound-ID shape: short, printable, no injection surface.
_INBOUND_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def new_request_id() -> str:
    """Mint a fresh server-side request id."""
    return uuid.uuid4().hex


def sanitize_inbound_id(value: str | None) -> str | None:
    """Return a bounded, safe inbound id, or None if absent/invalid."""
    if value is None:
        return None
    value = value.strip()
    if _INBOUND_ID_RE.match(value):
        return value
    return None


def bind_request_context(**fields: str) -> None:
    """Clear any inherited context, then bind the given correlation fields."""
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(**fields)


def clear_request_context() -> None:
    """Clear all bound correlation context at a request/task boundary."""
    structlog.contextvars.clear_contextvars()
