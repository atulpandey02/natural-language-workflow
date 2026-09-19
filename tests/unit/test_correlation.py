"""Correlation-id helpers (M9)."""

import structlog

from nlw.observability.correlation import (
    bind_request_context,
    clear_request_context,
    new_request_id,
    sanitize_inbound_id,
)


def test_new_request_id_is_unique_hex() -> None:
    a, b = new_request_id(), new_request_id()
    assert a != b
    assert len(a) == 32 and all(c in "0123456789abcdef" for c in a)


def test_sanitize_inbound_id_bounds() -> None:
    assert sanitize_inbound_id("abc-123_ID.4") == "abc-123_ID.4"
    assert sanitize_inbound_id(None) is None
    assert sanitize_inbound_id("has spaces") is None
    assert sanitize_inbound_id("x" * 65) is None  # too long
    assert sanitize_inbound_id("bad;semi") is None


def test_bind_clears_previous_context() -> None:
    bind_request_context(request_id="first", extra="keep")
    bind_request_context(request_id="second")  # must clear "extra"
    ctx = structlog.contextvars.get_contextvars()
    assert ctx.get("request_id") == "second"
    assert "extra" not in ctx
    clear_request_context()
    assert structlog.contextvars.get_contextvars() == {}
