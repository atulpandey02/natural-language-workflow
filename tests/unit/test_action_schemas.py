"""Action arg schemas: the approval-review payload bound (M11.5 P1C, part G).

An approval-gated webhook payload must be fully reviewable by a human before
approval. An oversized payload is rejected at materialization so it can never
reach the approval queue as truncated, unreviewable content.
"""

import pytest
from pydantic import ValidationError

from nlw.tools.action_schemas import (
    MAX_REVIEWABLE_ACTION_PAYLOAD_BYTES,
    WebhookSendArgs,
)


def test_small_payload_is_accepted() -> None:
    args = WebhookSendArgs(payload={"hello": "world"})
    assert args.payload == {"hello": "world"}


def test_payload_at_the_limit_is_accepted() -> None:
    # A payload whose serialized size is just under the bound is fine.
    filler = "x" * (MAX_REVIEWABLE_ACTION_PAYLOAD_BYTES - 100)
    WebhookSendArgs(payload={"v": filler})


def test_oversized_payload_is_rejected_not_truncated() -> None:
    filler = "x" * (MAX_REVIEWABLE_ACTION_PAYLOAD_BYTES + 1000)
    with pytest.raises(ValidationError):
        WebhookSendArgs(payload={"v": filler})


def test_bound_uses_utf8_byte_length_not_char_count() -> None:
    # Multi-byte characters count by their encoded size, so a payload that is
    # under the limit in characters but over in bytes is still rejected.
    each = "€"  # 3 bytes in UTF-8
    n = (MAX_REVIEWABLE_ACTION_PAYLOAD_BYTES // 3) + 500
    with pytest.raises(ValidationError):
        WebhookSendArgs(payload={"v": each * n})
