"""B04 boundary regressions (plan section 21, properties 4-6).

- no planner visibility: nothing on the planning path imports the ingestion or
  storage packages, and the registry offers no dataset tool;
- no query execution: the ingestion package imports no query engine, database
  driver or connector;
- no customer-data model context: the ingestion package imports no provider,
  and profiling runs with sockets disabled.
"""

import ast
import socket
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "nlw"
PLANNING_PATH = ("planner", "feasibility", "registry", "tools", "api/capability.py", "eval")
NEW_PACKAGES = ("nlw.ingest", "nlw.storage")
FORBIDDEN_FOR_INGEST = (
    "nlw.planner",
    "nlw.feasibility",
    "nlw.registry",
    "nlw.tools",
    "nlw.connectors",
    "nlw.engine",
    "nlw.api",
    "nlw.db",
    "anthropic",
    "httpx",
    "requests",
    "socket",
    "urllib",
    "sqlalchemy",
    "psycopg",
    "sqlglot",
    "duckdb",
)


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _files(rel: str) -> list[Path]:
    p = SRC / rel
    return [p] if p.is_file() else sorted(p.rglob("*.py"))


def test_planning_path_never_imports_ingestion_or_storage() -> None:
    offenders = [
        f"{f.relative_to(SRC)}:{m}"
        for rel in PLANNING_PATH
        for f in _files(rel)
        for m in _imports(f)
        if m.startswith(NEW_PACKAGES)
    ]
    assert offenders == []


def test_ingestion_imports_no_planner_provider_query_engine_or_network() -> None:
    offenders = [
        f"{f.relative_to(SRC)}:{m}"
        for pkg in ("ingest", "storage")
        for f in _files(pkg)
        for m in _imports(f)
        if any(m == bad or m.startswith(bad + ".") for bad in FORBIDDEN_FOR_INGEST)
    ]
    assert offenders == []


def test_registry_offers_no_dataset_tool() -> None:
    import nlw.tools.builtin  # noqa: F401  (populate the registry as the API does)
    from nlw.registry.registry import REGISTRY

    tools = REGISTRY.all()
    assert tools  # the registry is populated, so an empty result is meaningful
    assert [t.name for t in tools if t.name.startswith("dataset")] == []


def test_profiling_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    from nlw.ingest.profile import profile_csv

    def _no_network(*_a: object, **_k: object) -> None:
        raise AssertionError("profiling attempted network access")

    monkeypatch.setattr(socket, "socket", _no_network)
    monkeypatch.setattr(socket, "create_connection", _no_network)
    p = profile_csv(b"site,open\nA,1\nB,2\n")
    assert p.row_count == 2
