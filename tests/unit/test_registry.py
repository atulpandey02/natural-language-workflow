"""Tool Registry: deterministic lookup, availability filtering, tool behavior."""

import pytest

import nlw.tools.builtin  # noqa: F401  (populates the registry)
from nlw.connectors.base import ConnectorContext
from nlw.registry.registry import (
    REGISTRY,
    DuplicateToolError,
    IdempotencyContract,
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


# --- Replay authorization is fail-closed at registration (ADR-013 P4) ----------------


def _action_spec(**overrides: object) -> ToolSpec:
    from nlw.registry.registry import ActionContext, ActionResult

    def _act(args: object, ctx: ConnectorContext, action_ctx: ActionContext) -> ActionResult:
        return ActionResult(output={})

    base: dict[str, object] = dict(
        name="test.replay_guard",
        description="registration-time guard fixture",
        category=ToolCategory.ACTION,
        connector_type="webhook",
        input_model=NoArgs,
        read_only=False,
        requires_approval=True,
        timeout_seconds=15,
        side_effecting=True,
        execute_action=_act,
    )
    base.update(overrides)
    return ToolSpec(**base)  # type: ignore[arg-type]


def _contract() -> IdempotencyContract:
    return IdempotencyContract(
        receiver="test receiver",
        dedup_key="Idempotency-Key = external_action_key",
        contract_ref="ADR-013 P4",
        verified_by="tests/unit/test_registry.py::test_contract_and_flag_together_are_accepted",
    )


def test_idempotent_delivery_flag_alone_is_rejected() -> None:
    # The Boolean can never authorize replay by itself: registration fails closed.
    with pytest.raises(ValueError, match="IdempotencyContract"):
        _action_spec(idempotent_delivery=True)


def test_contract_without_flag_is_rejected_as_inconsistent() -> None:
    with pytest.raises(ValueError, match="inconsistent"):
        _action_spec(idempotent_delivery=False, idempotency_contract=_contract())


def test_idempotent_delivery_on_inline_tool_is_rejected() -> None:
    with pytest.raises(ValueError, match="side-effecting"):
        ToolSpec(
            name="test.inline_replay",
            description="inline tools never replay a side effect",
            category=ToolCategory.PROCESSING,
            connector_type=None,
            input_model=NoArgs,
            read_only=True,
            requires_approval=False,
            timeout_seconds=1,
            execute=lambda args, ctx: {},
            idempotent_delivery=True,
            idempotency_contract=_contract(),
        )


def test_contract_and_flag_together_are_accepted() -> None:
    spec = _action_spec(idempotent_delivery=True, idempotency_contract=_contract())
    assert spec.may_replay_after_transmission is True


def test_contract_fields_must_be_non_empty() -> None:
    with pytest.raises(ValueError, match="verified_by"):
        IdempotencyContract(receiver="r", dedup_key="k", contract_ref="c", verified_by=" ")


def test_no_production_tool_may_replay_after_transmission() -> None:
    # Every production connector (webhook.send, slack.send_message, ...) is a
    # generic side effect: a crash after the transmission boundary is terminal
    # UNKNOWN, never a resend. Enabling replay for a real connector requires an
    # IdempotencyContract AND updating this allowlist deliberately.
    allowed_replay_tools = {"test.idempotent_webhook"}  # test-only contract tool
    replayers = {s.name for s in REGISTRY.all() if s.may_replay_after_transmission}
    assert replayers <= allowed_replay_tools, f"unexpected replay-capable tools: {replayers}"
    for spec in REGISTRY.all():
        if spec.idempotent_delivery:
            assert spec.idempotency_contract is not None
        else:
            assert spec.may_replay_after_transmission is False
    assert REGISTRY.get("webhook.send").may_replay_after_transmission is False
    assert REGISTRY.get("slack.send_message").may_replay_after_transmission is False
