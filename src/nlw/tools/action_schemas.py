"""Strict arg models for M7 action tools.

The model supplies message CONTENT only. Destinations (webhook URL, Slack
workspace/token) come from the tenant-owned connector, never from these args.
"""

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

_SLACK_TEXT_MAX = 4000
# Canonical Slack channel IDs only (never mutable names).
_CHANNEL_ID_PATTERN = r"^[CGD][A-Z0-9]{2,}$"
# An approval-gated action payload must be fully reviewable by a human before
# approval (never truncate-and-approve, P1C). Bound it at materialization so an
# oversized, unreviewable payload is rejected up front rather than approved unseen.
MAX_REVIEWABLE_ACTION_PAYLOAD_BYTES = 16_000


class WebhookSendArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # JSON body to POST. No URL, headers, or method — those are connector-owned.
    payload: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _bound_reviewable_payload(self) -> "WebhookSendArgs":
        size = len(json.dumps(self.payload, default=str).encode("utf-8"))
        if size > MAX_REVIEWABLE_ACTION_PAYLOAD_BYTES:
            raise ValueError("webhook payload exceeds the maximum reviewable size")
        return self


class SlackSendArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=_SLACK_TEXT_MAX)
    # Optional canonical channel ID; validated against the connector allowlist.
    channel: str | None = Field(default=None, pattern=_CHANNEL_ID_PATTERN)
