"""Registration of M7 ACTION tools: ``webhook.send`` and ``slack.send_message``.

Both are side-effecting (``side_effecting=True``) and approval-gated
(``requires_approval=True``), so the durable engine runs them via the
two-transaction, out-of-lock pattern (ADR-013). The registry projection makes
them visible to the M6 planner automatically.
"""

from nlw.connectors.slack import execute_slack_action
from nlw.connectors.webhook import execute_webhook_action
from nlw.registry.registry import REGISTRY, ToolCategory, ToolSpec
from nlw.tools.action_schemas import SlackSendArgs, WebhookSendArgs


def _register() -> None:
    REGISTRY.register(
        ToolSpec(
            name="webhook.send",
            description="POST a JSON payload to a tenant-owned webhook connector",
            category=ToolCategory.ACTION,
            connector_type="webhook",
            input_model=WebhookSendArgs,
            read_only=False,
            requires_approval=True,
            timeout_seconds=15,
            side_effecting=True,
            execute_action=execute_webhook_action,
        )
    )
    REGISTRY.register(
        ToolSpec(
            name="slack.send_message",
            description="Post a message to a tenant-owned Slack channel",
            category=ToolCategory.ACTION,
            connector_type="slack",
            input_model=SlackSendArgs,
            read_only=False,
            requires_approval=True,
            timeout_seconds=15,
            side_effecting=True,
            execute_action=execute_slack_action,
        )
    )


_register()
