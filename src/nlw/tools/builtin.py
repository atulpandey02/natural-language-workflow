"""Built-in tool registrations.

Importing this module populates the global REGISTRY (and, via nlw.connectors,
the connector-type registry). Everything here is pure/local — no network or DB
I/O — per M4 scope.

- fake.echo / fake.fail   connector-less (migrated from M3)
- static.echo             connector-backed: proves ownership-gated execution
- static.secret_check     connector-backed: proves the secret resolved, returning
                          only a non-sensitive {"secret_available": true}
"""

from typing import Any

from pydantic import BaseModel

import nlw.connectors.postgres  # noqa: F401  (registers the 'postgres' connector type)
import nlw.connectors.slack  # noqa: F401  (registers the 'slack' connector type)
import nlw.connectors.static  # noqa: F401  (registers the 'static' connector type)
import nlw.connectors.webhook  # noqa: F401  (registers the 'webhook' connector type)
import nlw.tools.action_tools  # noqa: F401  (registers 'webhook.send' + 'slack.send_message')
import nlw.tools.postgres_tools  # noqa: F401  (registers 'postgres.query')
from nlw.connectors.base import ConnectorContext
from nlw.registry.registry import (
    REGISTRY,
    ToolCategory,
    ToolExecutionError,
    ToolSpec,
)
from nlw.tools.schemas import EchoArgs, NoArgs


def _fake_echo(args: BaseModel, ctx: ConnectorContext | None) -> dict[str, Any]:
    return {"echo": args.model_dump()}


def _fake_fail(args: BaseModel, ctx: ConnectorContext | None) -> dict[str, Any]:
    raise ToolExecutionError("fake.fail")


def _static_echo(args: BaseModel, ctx: ConnectorContext | None) -> dict[str, Any]:
    return {"echo": args.model_dump()}


def _static_secret_check(args: BaseModel, ctx: ConnectorContext | None) -> dict[str, Any]:
    if ctx is None or not ctx.secret:
        raise ToolExecutionError("secret not available")
    # Return only a non-sensitive result; never a secret-derived value.
    return {"secret_available": True}


def _register() -> None:
    REGISTRY.register(
        ToolSpec(
            name="fake.echo",
            description="Echo the args",
            category=ToolCategory.PROCESSING,
            connector_type=None,
            input_model=EchoArgs,
            read_only=True,
            requires_approval=False,
            timeout_seconds=30,
            execute=_fake_echo,
        )
    )
    REGISTRY.register(
        ToolSpec(
            name="fake.fail",
            description="Always fail deterministically",
            category=ToolCategory.PROCESSING,
            connector_type=None,
            input_model=NoArgs,
            read_only=True,
            requires_approval=False,
            timeout_seconds=30,
            execute=_fake_fail,
        )
    )
    REGISTRY.register(
        ToolSpec(
            name="static.echo",
            description="Echo through a static connector",
            category=ToolCategory.PROCESSING,
            connector_type="static",
            input_model=EchoArgs,
            read_only=True,
            requires_approval=False,
            timeout_seconds=30,
            execute=_static_echo,
        )
    )
    REGISTRY.register(
        ToolSpec(
            name="static.secret_check",
            description="Confirm the connector secret resolves",
            category=ToolCategory.PROCESSING,
            connector_type="static",
            input_model=NoArgs,
            read_only=True,
            requires_approval=False,
            timeout_seconds=30,
            execute=_static_secret_check,
        )
    )


_register()
