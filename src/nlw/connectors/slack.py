"""The ``slack`` connector: post a message to a tenant-owned Slack channel (M7).

The connector owns the workspace + canonical channel ID(s) and the bot-token
secret_ref; the tool supplies only message content. ``chat.postMessage`` is
treated as AT-LEAST-ONCE (Slack has no idempotency key); the bot token never
appears in plans, logs, output, errors, or the audit table, and the full Slack
response (which echoes message content) is never persisted.
"""

import re
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, field_validator

from nlw.connectors.base import (
    ConnectorConfigError,
    ConnectorContext,
    ConnectorType,
    register_connector_type,
)
from nlw.connectors.http_guard import GuardedTransport
from nlw.registry.registry import (
    ActionAuthError,
    ActionContext,
    ActionResult,
    RetryableActionError,
    ToolExecutionError,
)
from nlw.secrets.store import SecretError

_TIMEOUT_CAP_S = 15
_MAX_RESPONSE_BYTES_CAP = 200_000
_POST_MESSAGE_URL = "https://slack.com/api/chat.postMessage"
# Canonical Slack channel IDs (channels C…, groups G…, DMs D…).
_CHANNEL_ID_RE = re.compile(r"^[CGD][A-Z0-9]{2,}$")

_RETRYABLE_SLACK_ERRORS = frozenset({"ratelimited", "service_unavailable", "internal_error"})
_AUTH_SLACK_ERRORS = frozenset({"invalid_auth", "not_authed", "account_inactive", "token_revoked"})


class SlackConnectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workspace_label: str
    default_channel: str
    allowed_channels: list[str] | None = None
    timeout_s: int = 10
    max_response_bytes: int = 50_000

    @field_validator("default_channel")
    @classmethod
    def _valid_channel(cls, v: str) -> str:
        if not _CHANNEL_ID_RE.match(v):
            raise ValueError(
                "default_channel must be a canonical Slack channel ID (e.g. C0123ABCD)"
            )
        return v

    @field_validator("allowed_channels")
    @classmethod
    def _valid_channels(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            for c in v:
                if not _CHANNEL_ID_RE.match(c):
                    raise ValueError(f"allowed_channels entry is not a canonical channel ID: {c}")
        return v

    @field_validator("timeout_s")
    @classmethod
    def _cap_timeout(cls, v: int) -> int:
        return max(1, min(v, _TIMEOUT_CAP_S))

    @field_validator("max_response_bytes")
    @classmethod
    def _cap_response(cls, v: int) -> int:
        return max(1, min(v, _MAX_RESPONSE_BYTES_CAP))

    def resolve_channel(self, requested: str | None) -> str:
        """Return the channel to post to, enforcing the allowlist. Raises on a
        channel the connector does not permit."""
        channel = requested or self.default_channel
        if channel == self.default_channel:
            return channel
        if self.allowed_channels is not None and channel in self.allowed_channels:
            return channel
        raise ToolExecutionError("channel is not permitted by this connector")


def parse_config(config: dict[str, Any]) -> SlackConnectorConfig:
    try:
        return SlackConnectorConfig.model_validate(config)
    except ValueError as exc:
        raise ConnectorConfigError(f"invalid slack config: {exc}") from exc


def send_slack_message(
    config: SlackConnectorConfig,
    token: str,
    channel: str,
    text: str,
    transport: httpx.BaseTransport | None,
) -> ActionResult:
    """POST chat.postMessage. Raises typed errors; never leaks the token or the
    full response."""
    client_transport = transport if transport is not None else GuardedTransport()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "nlw-slack/1.0",
    }
    try:
        with httpx.Client(
            transport=client_transport,
            timeout=httpx.Timeout(config.timeout_s),
            follow_redirects=False,
        ) as client:
            resp = client.post(
                _POST_MESSAGE_URL, json={"channel": channel, "text": text}, headers=headers
            )
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.NetworkError):
        raise RetryableActionError("slack transport error") from None
    except httpx.HTTPError:
        raise RetryableActionError("slack request error") from None

    if resp.status_code == 429:
        retry_after = resp.headers.get("Retry-After")
        raise RetryableActionError(
            "slack rate limited", retry_after_s=float(retry_after) if retry_after else None
        )
    if 500 <= resp.status_code < 600:
        raise RetryableActionError(f"slack server error {resp.status_code}")
    if resp.status_code != 200:
        raise ToolExecutionError(f"slack returned status {resp.status_code}")

    # Parse ONLY the safe fields; never persist/log the full body (it contains
    # message content).
    try:
        body = resp.json()
    except ValueError:
        raise ToolExecutionError("slack returned a non-JSON response") from None
    if body.get("ok") is True:
        return ActionResult(
            output={"ok": True, "channel": body.get("channel")},
            provider_request_id=str(body.get("ts")) if body.get("ts") else None,
        )
    error = str(body.get("error", "unknown_error"))
    if error in _AUTH_SLACK_ERRORS:
        raise ActionAuthError("slack authentication failed")
    if error in _RETRYABLE_SLACK_ERRORS:
        raise RetryableActionError(f"slack transient error: {error}")
    raise ToolExecutionError(f"slack rejected the message: {error}")


def _slack_health(ctx: ConnectorContext) -> None:
    """Validate config + secret availability (no side-effecting HTTP in M7)."""
    parse_config(ctx.config)
    if not ctx.secret:
        raise SecretError("slack connector requires a bot-token secret")


SLACK_CONNECTOR = ConnectorType(
    name="slack",
    config_model=SlackConnectorConfig,
    secret_required=True,
    health_check=_slack_health,
)

register_connector_type(SLACK_CONNECTOR)


def execute_slack_action(
    args: BaseModel, connector: ConnectorContext, action_ctx: ActionContext
) -> ActionResult:
    """ToolSpec.execute_action for ``slack.send_message``."""
    from nlw.tools.action_schemas import SlackSendArgs

    assert isinstance(args, SlackSendArgs)
    config = parse_config(connector.config)
    if not connector.secret:
        raise ToolExecutionError("slack connector secret unavailable")
    channel = config.resolve_channel(args.channel)
    return send_slack_message(
        config=config,
        token=connector.secret,
        channel=channel,
        text=args.text,
        transport=action_ctx.transport,
    )
