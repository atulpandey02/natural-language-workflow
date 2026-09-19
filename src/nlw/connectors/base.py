"""Connector model: types, per-type config validation, and execution context.

A connector is a tenant-owned integration instance (a DB row). Each connector
*type* declares a strict Pydantic config model (``extra='forbid'``) and whether a
secret is required. M4 ships only the deterministic ``static`` type (no I/O).
"""

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ValidationError


class ConnectorError(Exception):
    """Base for deterministic connector failures (never carries a secret value)."""


class ConnectorUnhealthyError(Exception):
    """Marker: a failure that should flip an active connector's status to 'error'.

    Mixed into the specific error type raised (e.g. an auth failure), so the
    engine can mark the connector unhealthy while still classifying the failure.
    """


class UnknownConnectorTypeError(ConnectorError):
    """Connector type is not registered."""


class ConnectorConfigError(ConnectorError):
    """Config failed the type's strict schema, or a required secret_ref is missing."""


class ConnectorNotFoundError(ConnectorError):
    """No connector of the required type/name owned by the tenant."""


class ConnectorDisabledError(ConnectorError):
    """Connector is disabled."""


class MissingConnectorSelectorError(ConnectorError):
    """A connector-backed tool step did not specify which connector to use."""


@dataclass(frozen=True)
class ConnectorContext:
    """Passed to a tool's execute(). ``secret`` is repr-suppressed to avoid leaks."""

    type: str
    name: str
    config: dict[str, Any]
    secret: str | None = field(default=None, repr=False)
    connector_id: uuid.UUID | None = None


@dataclass(frozen=True)
class ConnectorType:
    name: str
    config_model: type[BaseModel]
    secret_required: bool
    # Optional richer health check (resolves secret + probes the external system).
    # Called only for unchecked/error connectors; raises on failure.
    health_check: Callable[[ConnectorContext], None] | None = None


_CONNECTOR_TYPES: dict[str, ConnectorType] = {}


def register_connector_type(connector_type: ConnectorType) -> None:
    _CONNECTOR_TYPES[connector_type.name] = connector_type


def get_connector_type(name: str) -> ConnectorType:
    try:
        return _CONNECTOR_TYPES[name]
    except KeyError as exc:
        raise UnknownConnectorTypeError(name) from exc


def validate_connector_config(type_name: str, config: Mapping[str, Any]) -> dict[str, Any]:
    """Validate config against the type's strict model; returns the normalized dict."""
    connector_type = get_connector_type(type_name)
    try:
        model = connector_type.config_model.model_validate(dict(config))
    except ValidationError as exc:
        raise ConnectorConfigError(str(exc)) from exc
    return model.model_dump()
