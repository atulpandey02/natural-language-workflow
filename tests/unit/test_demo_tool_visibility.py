"""Demo-tool planner visibility policy (final audit, Package 6).

Demo tools (``fake.*``, ``static.*``) stay registered and executable everywhere;
the capability view offers them to NEW planning only on an explicit opt-in. The
API opts in solely from the operator setting ``DEMO_TOOLS_ENABLED``.
"""

import pytest
from pydantic import ValidationError

import nlw.tools.builtin  # noqa: F401  (populate the registry)
from nlw.api.capability import demo_tools_included
from nlw.core.config import Environment, Settings
from nlw.planner.capabilities import SafeConnector, build_capability_view
from nlw.registry.registry import REGISTRY

DEMO = {"fake.echo", "fake.fail", "static.echo", "static.secret_check"}
STATIC = SafeConnector(name="s", type="static", status="active")
PG = SafeConnector(name="pg", type="postgres", status="active")


def test_exactly_the_demo_tools_are_tagged() -> None:
    assert {s.name for s in REGISTRY.all() if s.demo} == DEMO
    assert {s.name for s in REGISTRY.all() if not s.demo} == {
        "webhook.send",
        "slack.send_message",
        "postgres.query",
    }


def test_view_hides_demo_tools_by_default_even_with_a_static_connector() -> None:
    view = build_capability_view(REGISTRY.all(), [STATIC, PG])
    names = {t.name for t in view.tools}
    assert names.isdisjoint(DEMO)
    assert "postgres.query" in names  # real tools unaffected
    # The connector inventory itself is still reported (secret-free) unchanged.
    assert {c.name for c in view.connectors} == {"s", "pg"}


def test_view_offers_demo_tools_only_on_explicit_opt_in() -> None:
    view = build_capability_view(REGISTRY.all(), [STATIC, PG], include_demo=True)
    names = {t.name for t in view.tools}
    assert names >= DEMO
    assert "postgres.query" in names
    # Connector gating still applies to demo tools: no static connector -> no static.*
    no_static = {t.name for t in build_capability_view(REGISTRY.all(), [], include_demo=True).tools}
    assert {"fake.echo", "fake.fail"} <= no_static and not ({"static.echo"} & no_static)


def test_real_tool_projection_is_identical_under_both_policies() -> None:
    hidden = [t for t in build_capability_view(REGISTRY.all(), [PG]).tools]
    shown = [t for t in build_capability_view(REGISTRY.all(), [PG], include_demo=True).tools]
    assert hidden == [t for t in shown if t.name not in DEMO]


def test_registry_and_execution_are_unaffected_by_visibility() -> None:
    # Hiding from planning never unregisters: existing workflow versions that
    # reference demo tools still resolve for execution and for STALE_PLAN
    # classification (UNKNOWN_TOOL vs TOOL_NOT_AVAILABLE).
    assert REGISTRY.get("fake.echo").demo is True
    assert "fake.echo" in {s.name for s in REGISTRY.available_for(set())}
    assert "fake.echo" in {s.name for s in REGISTRY.all()}


@pytest.mark.parametrize("env", ["local", "dev", "staging", "production"])
def test_unset_setting_hides_demo_tools_in_every_environment(env: Environment) -> None:
    s = Settings(_env_file=None, app_env=env)  # type: ignore[call-arg]
    assert s.demo_tools_enabled is None
    assert s.demo_tools_visible is False
    assert demo_tools_included(s, "planning") is False
    # Execution compatibility for already-materialized versions is always on.
    assert demo_tools_included(s, "execution_compat") is True


@pytest.mark.parametrize("env", ["local", "dev", "staging", "production"])
def test_explicit_true_enables_and_explicit_false_hides(env: Environment) -> None:
    on = Settings(_env_file=None, app_env=env, demo_tools_enabled=True)  # type: ignore[call-arg]
    off = Settings(_env_file=None, app_env=env, demo_tools_enabled=False)  # type: ignore[call-arg]
    assert on.demo_tools_visible is True and demo_tools_included(on, "planning") is True
    assert off.demo_tools_visible is False and demo_tools_included(off, "planning") is False


def test_invalid_setting_refuses_to_start(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEMO_TOOLS_ENABLED", "maybe")
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="production")  # type: ignore[call-arg]


def test_setting_is_read_from_the_environment_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEMO_TOOLS_ENABLED", "true")
    assert Settings(_env_file=None, app_env="production").demo_tools_visible is True  # type: ignore[call-arg]
    monkeypatch.setenv("DEMO_TOOLS_ENABLED", "false")
    assert Settings(_env_file=None, app_env="local").demo_tools_visible is False  # type: ignore[call-arg]
