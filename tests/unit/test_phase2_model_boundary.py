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
NEW_PACKAGES = ("nlw.ingest", "nlw.storage", "nlw.datasets")
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


# The ONLY permitted exceptions, each proven below: the isolated profiling
# process imports ``socket`` solely to DISABLE it, and the storage factory reads
# ``Settings`` (configuration, not a database, provider or network client).
INGEST_ALLOWED = {("ingest/runner.py", "socket")}


def test_ingestion_imports_no_planner_provider_query_engine_or_network() -> None:
    offenders = [
        f"{f.relative_to(SRC)}:{m}"
        for pkg in ("ingest", "storage")
        for f in _files(pkg)
        for m in _imports(f)
        if any(m == bad or m.startswith(bad + ".") for bad in FORBIDDEN_FOR_INGEST)
        and (str(f.relative_to(SRC)), m) not in INGEST_ALLOWED
    ]
    assert offenders == []


def test_the_profiling_process_disables_the_network() -> None:
    from nlw.ingest import runner

    real = (socket.socket, socket.create_connection, socket.getaddrinfo)
    try:
        runner._disable_network()
        for attempt in (
            lambda: socket.socket(),
            lambda: socket.create_connection(("192.0.2.1", 80)),
            lambda: socket.getaddrinfo("example.invalid", 80),
        ):
            with pytest.raises(OSError, match="network access is disabled"):
                attempt()
    finally:
        socket.socket, socket.create_connection, socket.getaddrinfo = real  # type: ignore[misc]


def test_strict_profiling_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    from nlw.ingest.strict import profile_bytes

    def _no_network(*_a: object, **_k: object) -> None:
        raise AssertionError("profiling attempted network access")

    monkeypatch.setattr(socket, "socket", _no_network)
    monkeypatch.setattr(socket, "create_connection", _no_network)
    assert profile_bytes(b"site,open\nA,1\nB,2\n").row_count == 2


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


# Dataset metadata (ADR-029) may use the database, but never the planner, tools,
# a model provider, HTTP, sockets, a query engine or the ingestion/storage layer
# (no bytes are read or written yet).
FORBIDDEN_FOR_DATASETS = (
    "nlw.planner",
    "nlw.feasibility",
    "nlw.registry",
    "nlw.tools",
    "nlw.connectors",
    "nlw.engine",
    "nlw.ingest",
    "nlw.storage",
    "anthropic",
    "httpx",
    "requests",
    "socket",
    "urllib",
    "sqlglot",
    "duckdb",
)


# ADR-030: ``nlw.datasets.ingestion`` is the ONE dataset module that touches
# bytes, through the storage abstraction and the strict profiler. Every other
# rule still applies to it, and every other dataset module stays byte-free.
BYTE_MODULES = {"datasets/ingestion.py"}
BYTE_PACKAGES = ("nlw.ingest", "nlw.storage")


def test_dataset_metadata_imports_no_planner_provider_storage_or_query_engine() -> None:
    offenders = []
    for f in _files("datasets"):
        rel = str(f.relative_to(SRC))
        for m in _imports(f):
            for bad in FORBIDDEN_FOR_DATASETS:
                if not (m == bad or m.startswith(bad + ".")):
                    continue
                if rel in BYTE_MODULES and bad in BYTE_PACKAGES:
                    continue
                offenders.append(f"{rel}:{m}")
    assert _files("datasets"), "the dataset package must exist"
    assert offenders == []


def test_only_the_ingestion_module_reads_bytes() -> None:
    users = sorted(
        str(f.relative_to(SRC))
        for f in _files("datasets")
        if any(m.startswith(BYTE_PACKAGES) for m in _imports(f))
    )
    assert users == sorted(BYTE_MODULES)


def test_planner_capability_view_has_no_dataset_route_or_tool() -> None:
    import nlw.tools.builtin  # noqa: F401  (populate the registry as the API does)
    from nlw.registry.registry import REGISTRY

    names = [t.name for t in REGISTRY.all()]
    assert not [n for n in names if "dataset" in n.lower()]


# ADR-031: the ingest RUNTIME (``nlw.ingest_service``) may use the database and
# the storage abstraction (it is the processing service), but never the planner,
# tools, connectors, the workflow engine, the worker, the API, the scheduler,
# the secret store, a model provider, HTTP or a query engine. ``nlw.ingest``
# itself stays the pure profiler (checked above).
FORBIDDEN_FOR_INGEST_RUNTIME = (
    "nlw.planner",
    "nlw.feasibility",
    "nlw.registry",
    "nlw.tools",
    "nlw.connectors",
    "nlw.engine",
    "nlw.worker",
    "nlw.api",
    "nlw.scheduler",
    "nlw.secrets",
    "anthropic",
    "httpx",
    "requests",
    "urllib",
    "sqlglot",
    "duckdb",
)


def test_the_ingest_runtime_imports_no_planner_worker_connector_provider_or_network() -> None:
    files = _files("ingest_service")
    assert files, "the ingest runtime package must exist"
    offenders = [
        f"{f.relative_to(SRC)}:{m}"
        for f in files
        for m in _imports(f)
        if any(m == bad or m.startswith(bad + ".") for bad in FORBIDDEN_FOR_INGEST_RUNTIME)
    ]
    assert offenders == []
