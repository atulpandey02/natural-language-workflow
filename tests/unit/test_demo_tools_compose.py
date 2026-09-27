"""Real Compose renders and fresh-process configuration; no containers or host contact."""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from nlw.ops.rollout.remote import load_target

ROOT = Path(__file__).resolve().parents[2]
RUNTIMES = {"api", "worker", "scheduler"}
FLAG = "DEMO_TOOLS_ENABLED"


def _render(tmp_path: Path, *, staging: bool, value: str | None) -> dict[str, Any]:
    if shutil.which("docker") is None:
        pytest.skip("Docker Compose is required for rendered-Compose tests")
    env = {
        key: f"fixture-{key}"
        for key in re.findall(r"\$\{([A-Z_]+):\?", (ROOT / "docker-compose.prod.yml").read_text())
    }
    env.update(
        PATH=os.environ["PATH"],
        NLW_CTX_KEYS_DIR="/srv/nlw/ctx-keys",
        REDIS_URL="redis://localhost:6379/0",
        SUPABASE_URL="https://fixture.supabase.co",
    )
    if value is not None:
        env[FLAG] = value
    # An empty project directory/env file prevents local .env and worker secret
    # files from influencing the render or appearing in captured output.
    args = [
        "docker",
        "compose",
        "--project-directory",
        str(tmp_path),
        "--env-file",
        "/dev/null",
        "-p",
        "nlw-demo-policy-test",
        "-f",
        str(ROOT / "docker-compose.prod.yml"),
    ]
    if staging:
        args += ["-f", str(ROOT / "docker-compose.staging.yml")]
    args += ["--profile", "*", "config", "--format", "json"]
    result = subprocess.run(args, env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    doc: dict[str, Any] = json.loads(result.stdout)
    return doc


@pytest.mark.parametrize("staging", [False, True])
@pytest.mark.parametrize("value", [None, "", "false", "true"])
def test_rendered_demo_policy_is_default_off_and_limited_to_registry_runtimes(
    tmp_path: Path, staging: bool, value: str | None
) -> None:
    services = _render(tmp_path, staging=staging, value=value)["services"]
    holders = {name for name, service in services.items() if FLAG in service.get("environment", {})}
    assert holders == RUNTIMES
    assert {services[name]["environment"][FLAG] for name in RUNTIMES} == {value or "false"}
    assert {"postgres", "redis", "caddy", "web", "backup", "restore", "migrate"} <= services.keys()
    if staging:
        assert {"prometheus", "alertmanager"} <= services.keys()
    # Ordinary render needs neither owner nor backup/restore credentials. They
    # remain outside every long-running runtime even with demo tools enabled.
    for name in (*RUNTIMES, "web"):
        keys = services[name].get("environment", {})
        assert "DATABASE_MIGRATION_URL" not in keys
        assert not any(
            k.startswith(("AWS_", "RESTIC_", "NLW_BACKUP_", "NLW_RESTORE_")) for k in keys
        )
    for name in ("worker", "scheduler", "web"):
        assert "NLW_LLM_API_KEY" not in services[name].get("environment", {})


@pytest.mark.parametrize("enabled", [False, True])
def test_reviewed_target_reaches_api_planning_worker_and_scheduler(
    tmp_path: Path, enabled: bool
) -> None:
    text = (ROOT / "deploy/staging/target.env").read_text()
    assert "NLW_STAGING_DEMO_TOOLS_ENABLED=true" in text
    if not enabled:
        text = text.replace(
            "NLW_STAGING_DEMO_TOOLS_ENABLED=true", "NLW_STAGING_DEMO_TOOLS_ENABLED=false"
        )
    path = tmp_path / "target.env"
    path.write_text(text)
    target = load_target(path)
    value = "true" if target.demo_tools_enabled else "false"
    services = _render(tmp_path, staging=True, value=value)["services"]
    script = """
import asyncio, json, sys
from nlw.core.config import get_settings
from nlw.registry.registry import REGISTRY
role = sys.argv[1]
if role == "api":
    from nlw.api.app import create_app
    from nlw.api.capability import demo_tools_included
    from nlw.api.routers.analytics import datasets
    from nlw.planner.capabilities import build_capability_view
    settings = create_app().state.settings
    catalog = asyncio.run(datasets(ctx=None, settings=settings))
    view = build_capability_view(
        REGISTRY.all(), [], include_demo=demo_tools_included(settings, "planning"))
    print(json.dumps({
        "enabled": settings.demo_tools_enabled, "catalog": [d["id"] for d in catalog],
        "pilot_tools": sorted(t.name for t in view.tools if t.name.startswith("pilot."))}))
else:
    # Scheduler's enqueue-only startup imports this same actor module. Importing
    # actors initializes Settings + the execution registry without starting work.
    from nlw.worker import actors
    settings = actors._settings
    assert settings is get_settings()
    tools = [REGISTRY.get(n) for n in ("pilot.sales_analysis", "pilot.support_analysis")]
    # Already-materialized tools stay executable under either visibility policy.
    outputs = [tool.execute(tool.input_model(), None) for tool in tools]
    print(json.dumps({"enabled": settings.demo_tools_enabled, "executed": len(outputs)}))
"""
    for role in sorted(RUNTIMES):
        process_env = {
            **services[role]["environment"],
            "PATH": os.environ["PATH"],
            "PYTHONPATH": str(ROOT / "src"),
        }
        result = subprocess.run(
            [sys.executable, "-c", script, role],
            cwd=tmp_path,
            env=process_env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        observed = json.loads(result.stdout)
        assert observed["enabled"] is enabled, role
        if role == "api":
            assert observed["catalog"] == (["sales-v1", "support-v1"] if enabled else [])
            assert observed["pilot_tools"] == (
                ["pilot.sales_analysis", "pilot.support_analysis"] if enabled else []
            )
        else:
            assert observed["executed"] == 2
