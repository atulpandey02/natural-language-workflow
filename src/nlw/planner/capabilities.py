"""Tenant capability projection (M6).

A pure, deterministic, tenant-scoped view of what a plan may use: the Tool
Registry filtered to the tenant's USABLE connector inventory, plus a secret-free
connector list. The same object feeds both the LLM prompt and the deterministic
feasibility engine, so the model and the validator reason over one surface.

Never contains secrets, secret_ref, DB passwords, or connector infra fields
(host/port/database/sslmode). Connector availability reflects NON-disabled
inventory: a tenant whose only connector of a type is disabled is not offered
that capability.
"""

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from nlw.registry.registry import ToolSpec

# A disabled connector does not count toward capability availability.
USABLE_CONNECTOR_STATUSES = frozenset({"active", "unchecked", "error"})


@dataclass(frozen=True)
class SafeConnector:
    """Secret-free connector projection. Postgres carries its SQL allowlist and
    the optional operator-declared schema hint (all non-secret)."""

    name: str
    type: str
    status: str
    allowed_schemas: list[str] | None = None
    allowed_tables: list[str] | None = None
    schema_hint: dict[str, Any] | None = None

    @property
    def usable(self) -> bool:
        return self.status in USABLE_CONNECTOR_STATUSES


@dataclass(frozen=True)
class ToolCapability:
    name: str
    description: str
    category: str
    connector_type: str | None
    read_only: bool
    requires_approval: bool
    timeout_seconds: int
    # The Pydantic arg model (deterministic validation source). Its JSON schema
    # is what the model sees; the class itself is what feasibility validates with.
    input_model: type[BaseModel]

    def input_schema(self) -> dict[str, Any]:
        return self.input_model.model_json_schema()


@dataclass(frozen=True)
class CapabilityView:
    tools: list[ToolCapability]
    connectors: list[SafeConnector] = field(default_factory=list)

    def tool(self, name: str) -> ToolCapability | None:
        return next((t for t in self.tools if t.name == name), None)

    def connector(self, name: str) -> SafeConnector | None:
        return next((c for c in self.connectors if c.name == name), None)

    def usable_connector_types(self) -> set[str]:
        return {c.type for c in self.connectors if c.usable}


def build_capability_view(
    registry_tools: list[ToolSpec], connectors: list[SafeConnector]
) -> CapabilityView:
    """Project the registry against the tenant's usable connectors.

    Connector-less tools are always available. A connector-backed tool is
    available only if the tenant owns at least one NON-disabled connector of its
    type. Deterministic and ordering-stable (registry insertion order).
    """
    usable_types = {c.type for c in connectors if c.usable}
    tools: list[ToolCapability] = []
    for spec in registry_tools:
        if spec.connector_type is not None and spec.connector_type not in usable_types:
            continue
        tools.append(
            ToolCapability(
                name=spec.name,
                description=spec.description,
                category=spec.category.value,
                connector_type=spec.connector_type,
                read_only=spec.read_only,
                requires_approval=spec.requires_approval,
                timeout_seconds=spec.timeout_seconds,
                input_model=spec.input_model,
            )
        )
    return CapabilityView(tools=tools, connectors=list(connectors))


def capability_view_to_prompt_json(view: CapabilityView) -> dict[str, Any]:
    """Serialize the view for the model. Secret-free by construction."""
    return {
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "connector_type": t.connector_type,
                "read_only": t.read_only,
                "requires_approval": t.requires_approval,
                "input_schema": t.input_schema(),
            }
            for t in view.tools
        ],
        "connectors": [
            {
                "name": c.name,
                "type": c.type,
                "status": c.status,
                **(
                    {
                        "allowed_schemas": c.allowed_schemas,
                        "allowed_tables": c.allowed_tables,
                        "schema_hint": c.schema_hint,
                    }
                    if c.type == "postgres"
                    else {}
                ),
            }
            for c in view.connectors
        ],
    }
