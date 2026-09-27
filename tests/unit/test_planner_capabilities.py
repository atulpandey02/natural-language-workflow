"""Capability projection: tenant-scoped, secret-free, deterministic (M6)."""

import json
import re

import pytest

import nlw.tools.builtin  # noqa: F401,E402  (populate the registry)
from nlw.planner.capabilities import (
    SafeConnector,
    build_capability_view,
    capability_view_to_prompt_json,
)
from nlw.registry.registry import REGISTRY


def _assert_no_forbidden_catalog_text(payload: object) -> None:
    blob = json.dumps(payload).lower()
    # Preserve the original substring checks for credential-like tokens.
    for forbidden in ("secret", "password", "secret_ref", "host", "sslmode"):
        assert forbidden not in blob, f"Forbidden catalog token: {forbidden}"
    # Check keys AND free text. Letter boundaries exclude support/transport,
    # while still detecting port=5432, PORT:5432 and database_port metadata.
    assert not re.search(r"(?<![a-z])port(?![a-z])", blob), "Forbidden catalog token: port"


@pytest.mark.parametrize(
    "payload",
    [
        {"port": 5432},
        {"tools": [{"description": "Connect using port 5432."}]},
        {"connectors": [{"schema_hint": {"notes": "Endpoint PORT:5432"}}]},
        {"connectors": [{"schema_hint": {"database_port": 5432}}]},
        {"tools": [{"input_schema": {"description": "Endpoint port=5432"}}]},
        {"description": "Credentials include password=test-only"},
        {"schema_hint": {"notes": "Use host=test.invalid"}},
        {"schema_hint": {"notes": "Use sslmode=require"}},
        {"description": "Credential secret_ref=test-only"},
    ],
)
def test_forbidden_catalog_content_is_detected(payload: object) -> None:
    with pytest.raises(AssertionError, match="Forbidden catalog token"):
        _assert_no_forbidden_catalog_text(payload)


@pytest.mark.parametrize(
    "word", ["supported", "support-v1", "transport", "export", "report", "portfolio"]
)
def test_benign_port_substrings_are_allowed(word: str) -> None:
    _assert_no_forbidden_catalog_text({"description": word, "schema_hint": {"notes": word}})


def test_connector_backed_tool_hidden_without_usable_connector() -> None:
    # No connectors -> postgres.query (connector-backed) must not appear.
    view = build_capability_view(REGISTRY.all(), [], include_demo=True)
    names = {t.name for t in view.tools}
    assert "postgres.query" not in names
    assert "fake.echo" in names  # connector-less always available


def test_connector_backed_tool_shown_with_active_connector() -> None:
    view = build_capability_view(
        REGISTRY.all(),
        [SafeConnector(name="pg", type="postgres", status="active")],
        include_demo=True,
    )
    assert "postgres.query" in {t.name for t in view.tools}


def test_only_disabled_connector_hides_capability() -> None:
    view = build_capability_view(
        REGISTRY.all(),
        [SafeConnector(name="pg", type="postgres", status="disabled")],
        include_demo=True,
    )
    assert "postgres.query" not in {t.name for t in view.tools}


def test_error_connector_keeps_capability_available() -> None:
    view = build_capability_view(
        REGISTRY.all(),
        [SafeConnector(name="pg", type="postgres", status="error")],
        include_demo=True,
    )
    assert "postgres.query" in {t.name for t in view.tools}


def test_prompt_json_is_secret_free_and_has_input_schema() -> None:
    view = build_capability_view(
        REGISTRY.all(),
        [
            SafeConnector(
                name="pg",
                type="postgres",
                status="active",
                allowed_schemas=["public"],
                allowed_tables=["public.people"],
                schema_hint={"tables": [{"schema": "public", "table": "people", "columns": []}]},
            )
        ],
        include_demo=True,
    )
    payload = capability_view_to_prompt_json(view)
    _assert_no_forbidden_catalog_text(payload)
    assert {"pilot.sales_analysis", "pilot.support_analysis"} <= {
        t["name"] for t in payload["tools"]
    }
    assert set(payload) == {"tools", "connectors"}
    # Each tool exposes its input JSON schema.
    for tool in payload["tools"]:
        assert set(tool) == {
            "name",
            "description",
            "category",
            "connector_type",
            "read_only",
            "requires_approval",
            "input_schema",
        }
        assert "input_schema" in tool and isinstance(tool["input_schema"], dict)
    # Postgres connector context is present (allowlist + hint), no infra fields.
    pg = next(c for c in payload["connectors"] if c["type"] == "postgres")
    assert set(pg) == {
        "name",
        "type",
        "status",
        "allowed_schemas",
        "allowed_tables",
        "schema_hint",
    }
    assert pg["allowed_schemas"] == ["public"]
    assert "schema_hint" in pg
