"""Strict, bounded, allowlist-subset schema_hint on the postgres connector (M6)."""

import pytest
from pydantic import ValidationError

from nlw.connectors.postgres import (
    _HINT_MAX_COLUMNS_PER_TABLE,
    _HINT_MAX_TABLES,
    PostgresConnectorConfig,
)

BASE = {
    "host": "db",
    "database": "app",
    "allowed_schemas": ["public"],
    "allowed_tables": ["public.people"],
}


def _cfg(hint: dict[str, object]) -> PostgresConnectorConfig:
    return PostgresConnectorConfig.model_validate({**BASE, "schema_hint": hint})


def test_valid_hint_within_allowlist() -> None:
    cfg = _cfg(
        {
            "tables": [
                {
                    "schema": "public",
                    "table": "people",
                    "columns": [{"name": "id", "type": "int"}, {"name": "name", "type": "text"}],
                }
            ]
        }
    )
    assert cfg.schema_hint is not None
    assert cfg.schema_hint.tables[0].schema_name == "public"


def test_hint_schema_outside_allowlist_rejected() -> None:
    with pytest.raises(ValidationError):
        _cfg({"tables": [{"schema": "secret", "table": "creds", "columns": []}]})


def test_hint_table_outside_allowed_tables_rejected() -> None:
    with pytest.raises(ValidationError):
        _cfg({"tables": [{"schema": "public", "table": "orders", "columns": []}]})


def test_hint_extra_field_rejected() -> None:
    with pytest.raises(ValidationError):
        _cfg({"tables": [{"schema": "public", "table": "people", "note": "free text"}]})


def test_hint_free_text_description_not_allowed() -> None:
    # Columns take only name/type; a description field is forbidden.
    with pytest.raises(ValidationError):
        _cfg(
            {
                "tables": [
                    {
                        "schema": "public",
                        "table": "people",
                        "columns": [{"name": "id", "type": "int", "description": "the id"}],
                    }
                ]
            }
        )


def test_hint_unknown_column_type_rejected() -> None:
    with pytest.raises(ValidationError):
        _cfg(
            {
                "tables": [
                    {
                        "schema": "public",
                        "table": "people",
                        "columns": [{"name": "id", "type": "supertype"}],
                    }
                ]
            }
        )


def test_hint_too_many_tables_rejected() -> None:
    tables = [
        {"schema": "public", "table": "people", "columns": []} for _ in range(_HINT_MAX_TABLES + 1)
    ]
    with pytest.raises(ValidationError):
        _cfg({"tables": tables})


def test_hint_too_many_columns_rejected() -> None:
    columns = [{"name": f"c{i}", "type": "int"} for i in range(_HINT_MAX_COLUMNS_PER_TABLE + 1)]
    with pytest.raises(ValidationError):
        _cfg({"tables": [{"schema": "public", "table": "people", "columns": columns}]})


def test_hint_bad_identifier_rejected() -> None:
    with pytest.raises(ValidationError):
        _cfg(
            {
                "tables": [
                    {
                        "schema": "public",
                        "table": "people",
                        "columns": [{"name": "id; DROP", "type": "int"}],
                    }
                ]
            }
        )


def test_no_hint_is_fine() -> None:
    cfg = PostgresConnectorConfig.model_validate(BASE)
    assert cfg.schema_hint is None
