"""Process-level LLM key isolation (M6, requirement #3).

The platform LLM key is injected into the API process ONLY. It must never be
present in the worker or scheduler environment, and must not live in the shared
Compose env block. Proven against the authoritative merged Compose config.
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

_KEY = "NLW_LLM_API_KEY"
_COMPOSE = Path(__file__).resolve().parents[2] / "docker-compose.yml"


def _merged_config() -> dict[str, Any]:
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    proc = subprocess.run(
        ["docker", "compose", "-f", str(_COMPOSE), "config", "--format", "json"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"docker compose config unavailable: {proc.stderr[:200]}")
    result: dict[str, Any] = json.loads(proc.stdout)
    return result


def _env_of(service: dict[str, Any]) -> dict[str, str]:
    env = service.get("environment", {})
    if isinstance(env, dict):
        return {k: str(v) for k, v in env.items()}
    # list form: ["K=V", ...]
    out: dict[str, str] = {}
    for item in env:
        k, _, v = str(item).partition("=")
        out[k] = v
    return out


def test_llm_key_present_only_in_api() -> None:
    config = _merged_config()
    services = config["services"]
    assert isinstance(services, dict)

    api_env = _env_of(services["api"])
    worker_env = _env_of(services["worker"])
    scheduler_env = _env_of(services["scheduler"])

    assert _KEY in api_env, "API must receive the platform LLM key"
    assert _KEY not in worker_env, "worker must NOT receive the LLM key"
    assert _KEY not in scheduler_env, "scheduler must NOT receive the LLM key"


def test_shared_app_env_block_has_no_llm_key() -> None:
    # The shared anchor must not carry the key; it is set on the api service only.
    text = _COMPOSE.read_text()
    anchor_start = text.index("x-app-env:")
    services_start = text.index("\nservices:")
    shared_block = text[anchor_start:services_start]
    assert _KEY not in shared_block
