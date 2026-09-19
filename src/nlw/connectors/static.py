"""The ``static`` connector type — deterministic, no network/DB I/O.

Exists to prove the capability layer end-to-end: ownership gating, per-type
config validation, and secret resolution. Requires a secret (to exercise the
SecretStore path); its config carries no secret fields.
"""

from pydantic import BaseModel, ConfigDict

from nlw.connectors.base import ConnectorType, register_connector_type


class StaticConnectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = ""  # non-secret, optional


STATIC_CONNECTOR = ConnectorType(
    name="static",
    config_model=StaticConnectorConfig,
    secret_required=True,
)

register_connector_type(STATIC_CONNECTOR)
