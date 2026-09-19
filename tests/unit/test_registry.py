"""Tool Registry: deterministic lookup, availability filtering, tool behavior."""

import pytest

import nlw.tools.builtin  # noqa: F401  (populates the registry)
from nlw.connectors.base import ConnectorContext
from nlw.registry.registry import (
    REGISTRY,
    DuplicateToolError,
    ToolCategory,
    ToolExecutionError,
    ToolSpec,
    UnknownToolError,
)
from nlw.tools.schemas import EchoArgs, NoArgs


def _run(name: str, args: object, ctx: ConnectorContext | None) -> dict[str, object]:
    spec = REGISTRY.get(name)
    assert spec.execute is not None  # inline tool
    return spec.execute(args, ctx)  # type: ignore[arg-type]


def test_unknown_tool_raises() -> None:
    with pytest.raises(UnknownToolError):
        REGISTRY.get("does.not.exist")


def test_duplicate_registration_rejected() -> None:
    spec = REGISTRY.get("fake.echo")
    with pytest.raises(DuplicateToolError):
        REGISTRY.register(spec)


def test_availability_filters_by_owned_connector_types() -> None:
    none_owned = {s.name for s in REGISTRY.available_for(set())}
    assert "fake.echo" in none_owned and "fake.fail" in none_owned  # connector-less
    assert "static.echo" not in none_owned  # needs a 'static' connector

    with_static = {s.name for s in REGISTRY.available_for({"static"})}
    assert {"static.echo", "static.secret_check"} <= with_static


def test_fake_echo_executes() -> None:
    out = _run("fake.echo", EchoArgs.model_validate({"x": 1}), None)
    assert out == {"echo": {"x": 1}}


def test_fake_fail_raises() -> None:
    with pytest.raises(ToolExecutionError):
        _run("fake.fail", NoArgs(), None)


def test_static_secret_check_requires_secret() -> None:
    with pytest.raises(ToolExecutionError):
        _run(
            "static.secret_check",
            NoArgs(),
            ConnectorContext(type="static", name="c", config={}, secret=None),
        )
    ok = _run(
        "static.secret_check",
        NoArgs(),
        ConnectorContext(type="static", name="c", config={}, secret="x"),
    )
    assert ok == {"secret_available": True}


def test_connector_context_repr_hides_secret() -> None:
    ctx = ConnectorContext(type="static", name="c", config={}, secret="topsecret")
    assert "topsecret" not in repr(ctx)


def test_tool_category_values() -> None:
    assert isinstance(REGISTRY.get("fake.echo").category, ToolCategory)
    assert all(isinstance(s, ToolSpec) for s in REGISTRY.all())
