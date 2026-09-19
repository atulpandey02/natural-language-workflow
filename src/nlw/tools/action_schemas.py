"""Strict arg models for M7 action tools.

The model supplies message CONTENT only. Destinations (webhook URL, Slack
workspace/token) come from the tenant-owned connector, never from these args.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

_SLACK_TEXT_MAX = 4000
# Canonical Slack channel IDs only (never mutable names).
_CHANNEL_ID_PATTERN = r"^[CGD][A-Z0-9]{2,}$"


class WebhookSendArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # JSON body to POST. No URL, headers, or method — those are connector-owned.
    payload: dict[str, Any] = Field(default_factory=dict)


class SlackSendArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=_SLACK_TEXT_MAX)
    # Optional canonical channel ID; validated against the connector allowlist.
    channel: str | None = Field(default=None, pattern=_CHANNEL_ID_PATTERN)
