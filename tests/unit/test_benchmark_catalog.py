"""Historical evaluation evidence keeps its measured catalog and real tools."""

from nlw.eval.catalog import BENCHMARK_TOOLS, benchmark_tools
from nlw.planner.capabilities import build_capability_view
from nlw.registry.registry import REGISTRY


def test_historical_catalog_uses_exact_original_registry_implementations() -> None:
    tools = benchmark_tools()
    assert {s.name for s in tools} == BENCHMARK_TOOLS
    assert all(s is REGISTRY.get(s.name) for s in tools)
    assert {s.name for s in tools} == {
        "fake.echo",
        "fake.fail",
        "static.echo",
        "static.secret_check",
        "postgres.query",
        "webhook.send",
        "slack.send_message",
    }


def test_pilot_tools_remain_in_current_planning_but_not_historical_catalog() -> None:
    historical = build_capability_view(benchmark_tools(), [], include_demo=True)
    current = build_capability_view(REGISTRY.all(), [], include_demo=True)
    pilot = {"pilot.sales_analysis", "pilot.support_analysis"}
    assert {t.name for t in historical.tools}.isdisjoint(pilot)
    assert {t.name for t in current.tools} >= pilot
