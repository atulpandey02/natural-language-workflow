"""Static validation of Docker/Compose hardening + secret isolation (M9).

These assert the deployment topology honors the M9 requirements without needing
Docker to run: non-root image, container hardening, process-level secret
isolation, and internal-only services behind the reverse proxy.
"""

from pathlib import Path
from typing import Any, cast

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str) -> dict[str, Any]:
    with (ROOT / name).open() as f:
        return cast(dict[str, Any], yaml.safe_load(f))  # resolves YAML merge keys (<<)


def test_dockerfile_runs_non_root_and_no_bytecode() -> None:
    text = (ROOT / "Dockerfile").read_text()
    assert "USER appuser" in text
    assert "PYTHONDONTWRITEBYTECODE=1" in text


def test_dev_compose_app_services_are_hardened() -> None:
    compose = _load("docker-compose.yml")
    for svc in ("api", "worker", "scheduler"):
        s = compose["services"][svc]
        assert s["read_only"] is True, svc
        assert s["cap_drop"] == ["ALL"], svc
        assert "no-new-privileges:true" in s["security_opt"], svc
        assert "/tmp" in s["tmpfs"], svc
        assert s["mem_limit"] and s["cpus"] and s["pids_limit"], svc


def test_stateful_services_keep_writable_state() -> None:
    compose = _load("docker-compose.yml")
    # Postgres/redis must NOT be read_only (they own writable state).
    assert compose["services"]["postgres"].get("read_only") is not True
    assert "pgdata:/var/lib/postgresql/data" in compose["services"]["postgres"]["volumes"]


def test_secret_isolation_worker_only() -> None:
    for name in ("docker-compose.yml", "docker-compose.prod.yml"):
        compose = _load(name)
        services = compose["services"]
        # Connector secrets: worker has the secrets env_file; api/scheduler don't.
        assert "env_file" in services["worker"], name
        assert "env_file" not in services.get("scheduler", {}), name
        assert "env_file" not in services.get("api", {}), name
        # The platform LLM key is only ever in the API environment.
        assert "NLW_LLM_API_KEY" in services["api"]["environment"], name
        assert "NLW_LLM_API_KEY" not in services["worker"].get("environment", {}), name
        assert "NLW_LLM_API_KEY" not in services["scheduler"].get("environment", {}), name


def test_prod_only_reverse_proxy_is_published() -> None:
    compose = _load("docker-compose.prod.yml")
    services = compose["services"]
    # Only caddy publishes host ports; everything else is internal.
    assert "ports" in services["caddy"]
    for svc in ("api", "worker", "scheduler", "postgres", "redis"):
        assert "ports" not in services[svc], f"{svc} must not publish a host port"


def test_prod_locks_hosts_and_trusts_only_proxy() -> None:
    compose = _load("docker-compose.prod.yml")
    api_env = compose["services"]["api"]["environment"]
    assert api_env["APP_ENV"] == "production"  # docs off + HSTS on by default
    assert "*" not in api_env["TRUSTED_HOSTS"]
    assert api_env["TRUSTED_PROXY_IPS"] != '["*"]'  # never trust arbitrary XFF


def test_worker_scheduler_healthchecks_check_dependencies() -> None:
    compose = _load("docker-compose.yml")
    for svc in ("worker", "scheduler"):
        test_cmd = compose["services"][svc]["healthcheck"]["test"]
        assert "nlw.ops.healthcheck" in " ".join(test_cmd), svc
