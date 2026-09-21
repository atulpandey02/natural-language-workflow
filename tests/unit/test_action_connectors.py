"""Webhook + Slack connector config, classification, and action registration (M7)."""

import httpx
import pytest
from pydantic import ValidationError

import nlw.tools.builtin  # noqa: F401,E402
from nlw.connectors.base import ConnectorConfigError
from nlw.connectors.slack import (
    SlackConnectorConfig,
    send_slack_message,
)
from nlw.connectors.slack import (
    parse_config as parse_slack,
)
from nlw.connectors.webhook import (
    WebhookConnectorConfig,
    send_webhook,
)
from nlw.connectors.webhook import (
    parse_config as parse_webhook,
)
from nlw.registry.registry import (
    REGISTRY,
    ActionAuthError,
    AmbiguousActionError,
    RetryableActionError,
    ToolExecutionError,
    ToolSpec,
)

# --- Webhook config ---


def test_webhook_requires_https() -> None:
    with pytest.raises(ConnectorConfigError):
        parse_webhook({"url": "http://example.com/hook"})


def test_webhook_rejects_userinfo() -> None:
    with pytest.raises(ConnectorConfigError):
        parse_webhook({"url": "https://u:p@example.com/hook"})


def test_webhook_header_allowlist() -> None:
    with pytest.raises(ValidationError):
        WebhookConnectorConfig(url="https://x.example/h", auth_header_name="Host")
    ok = WebhookConnectorConfig(url="https://x.example/h", auth_header_name="Authorization")
    assert ok.auth_header_name == "Authorization"


def test_webhook_caps() -> None:
    cfg = WebhookConnectorConfig(url="https://x.example/h", timeout_s=999, max_response_bytes=10**9)
    assert cfg.timeout_s == 15
    assert cfg.max_response_bytes == 1_000_000


def test_webhook_only_post() -> None:
    with pytest.raises(ValidationError):
        WebhookConnectorConfig(url="https://x.example/h", method="GET")


def _webhook_send(status_code: int, headers: dict[str, str] | None = None) -> object:
    cfg = WebhookConnectorConfig(url="https://x.example/hook")
    transport = httpx.MockTransport(lambda req: httpx.Response(status_code, headers=headers or {}))
    return send_webhook(cfg, None, {"a": 1}, "key-1", transport)


def test_webhook_success() -> None:
    result = _webhook_send(200, {"X-Request-Id": "abc"})
    assert result.provider_request_id == "abc"  # type: ignore[attr-defined]


def test_webhook_auth_error() -> None:
    with pytest.raises(ActionAuthError):
        _webhook_send(401)


def test_webhook_rate_limit_is_retryable() -> None:
    with pytest.raises(RetryableActionError):
        _webhook_send(429, {"Retry-After": "2"})


def test_webhook_5xx_is_ambiguous_not_retried() -> None:
    # A generic webhook 5xx does NOT prove the effect did not occur (the receiver
    # may have acted and then failed responding). Conservative -> UNKNOWN, never a
    # silent resend (P1C).
    for code in (500, 502, 503, 504):
        with pytest.raises(AmbiguousActionError):
            _webhook_send(code)


def test_webhook_4xx_is_deterministic() -> None:
    with pytest.raises(ToolExecutionError):
        _webhook_send(400)


def test_webhook_auth_header_from_secret_only() -> None:
    cfg = WebhookConnectorConfig(
        url="https://x.example/h", auth_header_name="Authorization", auth_scheme="Bearer"
    )
    seen: dict[str, str] = {}

    def _inner(req: httpx.Request) -> httpx.Response:
        seen["auth"] = req.headers.get("Authorization", "")
        return httpx.Response(200)

    send_webhook(cfg, "s3cr3t-token", {}, "k", httpx.MockTransport(_inner))
    assert seen["auth"] == "Bearer s3cr3t-token"


# --- Slack config ---


def test_slack_requires_canonical_channel_id() -> None:
    with pytest.raises(ConnectorConfigError):
        parse_slack({"workspace_label": "w", "default_channel": "#general"})
    ok = parse_slack({"workspace_label": "w", "default_channel": "C0123ABCD"})
    assert ok.default_channel == "C0123ABCD"


def test_slack_resolve_channel_allowlist() -> None:
    cfg = SlackConnectorConfig(
        workspace_label="w", default_channel="C0000", allowed_channels=["C1111"]
    )
    assert cfg.resolve_channel(None) == "C0000"
    assert cfg.resolve_channel("C1111") == "C1111"
    with pytest.raises(ToolExecutionError):
        cfg.resolve_channel("C9999")


def _slack_send(status_code: int, body: dict[str, object] | None = None) -> object:
    cfg = SlackConnectorConfig(workspace_label="w", default_channel="C0000")
    transport = httpx.MockTransport(
        lambda req: httpx.Response(status_code, json=body if body is not None else {})
    )
    return send_slack_message(cfg, "xoxb-token", "C0000", "hi", transport)


def test_slack_success_returns_only_safe_metadata() -> None:
    result = _slack_send(200, {"ok": True, "ts": "1700000000.000100", "channel": "C0000"})
    assert result.provider_request_id == "1700000000.000100"  # type: ignore[attr-defined]
    assert result.output == {"ok": True, "channel": "C0000"}  # type: ignore[attr-defined]


def test_slack_invalid_auth() -> None:
    with pytest.raises(ActionAuthError):
        _slack_send(200, {"ok": False, "error": "invalid_auth"})


def test_slack_channel_not_found_deterministic() -> None:
    with pytest.raises(ToolExecutionError):
        _slack_send(200, {"ok": False, "error": "channel_not_found"})


def test_slack_ratelimited_retryable() -> None:
    with pytest.raises(RetryableActionError):
        _slack_send(429, {"ok": False, "error": "ratelimited"})


def test_slack_5xx_is_ambiguous_not_retried() -> None:
    # An HTTP 5xx is NOT part of Slack's deterministic ok/error contract; the
    # message may already have posted -> UNKNOWN, never a silent resend (P1C).
    for code in (500, 502, 503):
        with pytest.raises(AmbiguousActionError):
            _slack_send(code, {})


# --- Post-transmission ambiguity (P1C): the message was POSTed, but the outcome
# cannot be proven -> UNKNOWN (AmbiguousActionError), never a silent retry. ---


def test_slack_oversized_response_is_ambiguous() -> None:
    # The POST succeeded (status 200) but the response body exceeds the cap, so
    # ok/error cannot be read -> the message may have been delivered -> UNKNOWN.
    cfg = SlackConnectorConfig(workspace_label="w", default_channel="C0000", max_response_bytes=100)
    big = {"ok": True, "ts": "1", "padding": "P" * 5000}
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=big))
    with pytest.raises(AmbiguousActionError):
        send_slack_message(cfg, "xoxb-token", "C0000", "hi", transport)


def test_slack_non_json_body_is_ambiguous() -> None:
    cfg = SlackConnectorConfig(workspace_label="w", default_channel="C0000")
    transport = httpx.MockTransport(lambda req: httpx.Response(200, content=b"not json <html>"))
    with pytest.raises(AmbiguousActionError):
        send_slack_message(cfg, "xoxb-token", "C0000", "hi", transport)


def test_slack_non_object_body_is_ambiguous() -> None:
    cfg = SlackConnectorConfig(workspace_label="w", default_channel="C0000")
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=[1, 2, 3]))
    with pytest.raises(AmbiguousActionError):
        send_slack_message(cfg, "xoxb-token", "C0000", "hi", transport)


# --- Action registration ---


def test_action_tools_registered_with_approval() -> None:
    for name in ("webhook.send", "slack.send_message"):
        spec = REGISTRY.get(name)
        assert spec.side_effecting is True
        assert spec.requires_approval is True
        assert spec.execute is None
        assert spec.execute_action is not None


def test_toolspec_rejects_inconsistent_action_config() -> None:
    from nlw.registry.registry import ToolCategory
    from nlw.tools.schemas import NoArgs

    with pytest.raises(ValueError):
        ToolSpec(
            name="bad",
            description="",
            category=ToolCategory.ACTION,
            connector_type="webhook",
            input_model=NoArgs,
            read_only=False,
            requires_approval=True,
            timeout_seconds=10,
            side_effecting=True,
            execute_action=None,
        )
