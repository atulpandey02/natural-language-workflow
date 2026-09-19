"""Postgres connector config, credential parsing, and non-leak guarantees (M5)."""

import json

import pytest

from nlw.connectors.base import ConnectorConfigError
from nlw.connectors.postgres import (
    PostgresConnectorConfig,
    SecretFormatError,
    _normalize_cell,
    parse_config,
    parse_secret,
)
from nlw.registry.registry import ToolExecutionError

BASE = {"host": "db.internal", "database": "app"}


# --- Config ---


def test_minimal_config_defaults() -> None:
    cfg = parse_config(BASE)
    assert cfg.port == 5432
    assert cfg.allowed_schemas == ["public"]
    assert cfg.allowed_tables is None
    assert cfg.max_rows == 1000


def test_unknown_field_rejected() -> None:
    with pytest.raises(ConnectorConfigError):
        parse_config({**BASE, "password": "leak"})


def test_missing_required_field_rejected() -> None:
    with pytest.raises(ConnectorConfigError):
        parse_config({"host": "db.internal"})


def test_invalid_sslmode_rejected() -> None:
    with pytest.raises(ConnectorConfigError):
        parse_config({**BASE, "sslmode": "totally-secure"})


@pytest.mark.parametrize(
    ("field", "value", "cap"),
    [
        ("statement_timeout_ms", 10_000_000, 30_000),
        ("lock_timeout_ms", 10_000_000, 30_000),
        ("connect_timeout_s", 9999, 15),
        ("max_rows", 10_000_000, 10_000),
        ("max_result_bytes", 10**12, 10_000_000),
    ],
)
def test_hard_platform_caps_enforced(field: str, value: int, cap: int) -> None:
    cfg = parse_config({**BASE, field: value})
    assert getattr(cfg, field) == cap


def test_lower_bound_clamped() -> None:
    cfg = parse_config({**BASE, "max_rows": 0, "statement_timeout_ms": -5})
    assert cfg.max_rows == 1
    assert cfg.statement_timeout_ms == 1


def test_empty_allowed_schemas_rejected() -> None:
    with pytest.raises(ConnectorConfigError):
        parse_config({**BASE, "allowed_schemas": []})


# --- Secret ---


def test_valid_secret_parsed_and_password_repr_safe() -> None:
    secret = parse_secret(json.dumps({"username": "reader", "password": "hunter2"}))
    assert secret.username == "reader"
    assert secret.password.get_secret_value() == "hunter2"
    # SecretStr never reveals the value in repr/str.
    assert "hunter2" not in repr(secret)
    assert "hunter2" not in str(secret.password)


def test_extra_secret_fields_ignored() -> None:
    secret = parse_secret(json.dumps({"username": "u", "password": "p", "extra": "x"}))
    assert secret.username == "u"


def test_missing_secret_rejected() -> None:
    with pytest.raises(SecretFormatError):
        parse_secret(None)
    with pytest.raises(SecretFormatError):
        parse_secret("")


def test_malformed_secret_never_echoes_payload() -> None:
    payload = "this-is-not-json-SUPERSECRETVALUE"
    with pytest.raises(SecretFormatError) as exc:
        parse_secret(payload)
    assert "SUPERSECRETVALUE" not in str(exc.value)


def test_secret_missing_password_never_echoes_payload() -> None:
    payload = json.dumps({"username": "u", "pw": "LEAKME"})
    with pytest.raises(SecretFormatError) as exc:
        parse_secret(payload)
    assert "LEAKME" not in str(exc.value)


# --- JSON normalization contract ---


import datetime  # noqa: E402
import uuid  # noqa: E402
from decimal import Decimal  # noqa: E402


def test_normalize_scalars_and_none() -> None:
    assert _normalize_cell(None) is None
    assert _normalize_cell(True) is True
    assert _normalize_cell(3) == 3
    assert _normalize_cell(2.5) == 2.5
    assert _normalize_cell("x") == "x"


def test_normalize_uuid_datetime_decimal() -> None:
    u = uuid.uuid4()
    assert _normalize_cell(u) == str(u)
    assert _normalize_cell(datetime.date(2026, 9, 19)) == "2026-09-19"
    assert _normalize_cell(Decimal("1.10")) == "1.10"  # lossless string


def test_normalize_arrays_recurse() -> None:
    u = uuid.uuid4()
    assert _normalize_cell([1, u, None]) == [1, str(u), None]


def test_normalize_jsonb_passthrough() -> None:
    assert _normalize_cell({"a": 1}) == {"a": 1}


def test_normalize_rejects_bytea() -> None:
    with pytest.raises(ToolExecutionError):
        _normalize_cell(b"\x00\x01")


def test_normalize_rejects_unknown_type() -> None:
    class Weird:
        pass

    with pytest.raises(ToolExecutionError):
        _normalize_cell(Weird())


# --- Model-level cap constants are self-consistent ---


def test_config_model_is_strict() -> None:
    assert PostgresConnectorConfig.model_config.get("extra") == "forbid"
