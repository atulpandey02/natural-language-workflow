"""Registry-backed catalog used by the historical v1/v2 benchmark corpora.

Freeze tool inventory, not implementations or safety logic: adding pilot tools
must not silently change the prompts measured by committed benchmark evidence.
New pilot workflows exercise the full current registry in integration tests.
"""

import nlw.tools.builtin  # noqa: F401
from nlw.registry.registry import REGISTRY, ToolSpec

BENCHMARK_TOOLS = frozenset(
    {
        "fake.echo",
        "fake.fail",
        "static.echo",
        "static.secret_check",
        "postgres.query",
        "webhook.send",
        "slack.send_message",
    }
)


def benchmark_tools() -> list[ToolSpec]:
    tools = [s for s in REGISTRY.all() if s.name in BENCHMARK_TOOLS]
    if {s.name for s in tools} != BENCHMARK_TOOLS:
        raise ValueError("historical benchmark catalog is incomplete")
    return tools
