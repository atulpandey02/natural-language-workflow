"""The ``postgres.query`` tool: read-only SQL against a tenant-owned Postgres.

The tool never trusts the incoming SQL. It (1) validates it deterministically
with sqlglot against the connector's schema/table allowlist, then (2) runs the
re-rendered statement through the read-only, timeout- and size-bounded driver
path. The LLM never reaches the database; only this registered tool does.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nlw.connectors.base import ConnectorContext
from nlw.connectors.postgres import (
    parse_config,
    parse_secret,
    run_read_only_query,
)
from nlw.feasibility.sql_safety import validate_select
from nlw.registry.registry import (
    REGISTRY,
    ToolCategory,
    ToolExecutionError,
    ToolSpec,
)


class PostgresQueryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # M5 accepts a single SQL string only; no bind params (out of scope).
    sql: str = Field(min_length=1)


def _postgres_query(args: BaseModel, ctx: ConnectorContext | None) -> dict[str, Any]:
    if ctx is None:
        raise ToolExecutionError("postgres.query requires a connector")
    assert isinstance(args, PostgresQueryArgs)

    config = parse_config(ctx.config)
    secret = parse_secret(ctx.secret)

    # Layer 1: deterministic validation + canonical re-render.
    rendered = validate_select(args.sql, config.allowed_schemas, config.allowed_tables)

    # Layers 2 & 3: read-only session + (tenant-side) SELECT-only role.
    result = run_read_only_query(config, secret, rendered)

    return {
        "columns": result.columns,
        "rows": result.rows,
        "row_count": len(result.rows),
        "truncated": result.truncated,
    }


def _register() -> None:
    REGISTRY.register(
        ToolSpec(
            name="postgres.query",
            description="Run a read-only SELECT against a tenant-owned Postgres database",
            category=ToolCategory.DATA,
            connector_type="postgres",
            input_model=PostgresQueryArgs,
            read_only=True,
            requires_approval=False,
            timeout_seconds=30,
            execute=_postgres_query,
        )
    )


_register()
