"""Capability projection: tenant-scoped, secret-free, deterministic (M6)."""

import json

import nlw.tools.builtin  # noqa: F401,E402  (populate the registry)
from nlw.planner.capabilities import (
    SafeConnector,
    build_capability_view,
    capability_view_to_prompt_json,
)
from nlw.registry.registry import REGISTRY


def test_connector_backed_tool_hidden_without_usable_connector() -> None:
    # No connectors -> postgres.query (connector-backed) must not appear.
    view = build_capability_view(REGISTRY.all(), [])
    names = {t.name for t in view.tools}
    assert "postgres.query" not in names
    assert "fake.echo" in names  # connector-less always available


def test_connector_backed_tool_shown_with_active_connector() -> None:
    view = build_capability_view(
        REGISTRY.all(), [SafeConnector(name="pg", type="postgres", status="active")]
    )
    assert "postgres.query" in {t.name for t in view.tools}


def test_only_disabled_connector_hides_capability() -> None:
    view = build_capability_view(
        REGISTRY.all(), [SafeConnector(name="pg", type="postgres", status="disabled")]
    )
    assert "postgres.query" not in {t.name for t in view.tools}


def test_error_connector_keeps_capability_available() -> None:
    view = build_capability_view(
        REGISTRY.all(), [SafeConnector(name="pg", type="postgres", status="error")]
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
    )
    payload = capability_view_to_prompt_json(view)
    blob = json.dumps(payload)
    # No secret-ish tokens leak into the model-facing projection.
    for forbidden in ("secret", "password", "secret_ref", "host", "port", "sslmode"):
        assert forbidden not in blob
    # Each tool exposes its input JSON schema.
    for tool in payload["tools"]:
        assert "input_schema" in tool and isinstance(tool["input_schema"], dict)
    # Postgres connector context is present (allowlist + hint), no infra fields.
    pg = next(c for c in payload["connectors"] if c["type"] == "postgres")
    assert pg["allowed_schemas"] == ["public"]
    assert "schema_hint" in pg
