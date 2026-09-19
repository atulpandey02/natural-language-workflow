"""Per-type connector config validation (strict, extra='forbid')."""

import pytest

import nlw.connectors.static  # noqa: F401  (registers 'static')
from nlw.connectors.base import (
    ConnectorConfigError,
    UnknownConnectorTypeError,
    get_connector_type,
    validate_connector_config,
)


def test_static_type_registered_and_requires_secret() -> None:
    ct = get_connector_type("static")
    assert ct.secret_required is True


def test_unknown_type_rejected() -> None:
    with pytest.raises(UnknownConnectorTypeError):
        get_connector_type("nope")
    with pytest.raises(UnknownConnectorTypeError):
        validate_connector_config("nope", {})


def test_valid_static_config() -> None:
    assert validate_connector_config("static", {"label": "hi"}) == {"label": "hi"}
    assert validate_connector_config("static", {}) == {"label": ""}


def test_unknown_config_field_rejected() -> None:
    with pytest.raises(ConnectorConfigError):
        validate_connector_config("static", {"label": "x", "secret": "leak"})
