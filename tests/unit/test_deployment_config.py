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


# --- PR2: hardened role bootstrap ------------------------------------------

_INITDB = ROOT / "docker" / "postgres" / "initdb"
# Weak-password literals that must NEVER appear in a production bootstrap source.
_WEAK_LITERALS = (
    "PASSWORD 'nlw_app'",
    "PASSWORD 'nlw_worker'",
    "PASSWORD 'nlw_scheduler'",
    "nlw_app:nlw_app",
    "nlw_worker:nlw_worker",
    "nlw_scheduler:nlw_scheduler",
)


def test_role_bootstrap_is_executable_env_driven_script() -> None:
    # The static weak-password SQL is gone; the executable bootstrap replaces it.
    assert not (_INITDB / "00-roles.sql").exists(), "static 00-roles.sql must be removed"
    script = _INITDB / "00-roles.sh"
    assert script.exists(), "00-roles.sh bootstrap missing"
    text = script.read_text()
    getenv = "\\getenv"  # literal backslash-getenv marker (psql meta-command)
    # Requires the three role passwords (fail-fast) and imports each via \getenv
    # (no shell-string interpolation of secrets).
    for var in ("NLW_APP_DB_PASSWORD", "NLW_WORKER_DB_PASSWORD", "NLW_SCHEDULER_DB_PASSWORD"):
        assert f'"${{{var}:?' in text, f"{var} must be a required fail-fast guard"
        assert f"{getenv} " in text and var in text, f"{var} must be imported via \\getenv"
    assert text.count(f"{getenv} ") >= 3, "each role password must be imported via \\getenv"
    # Never enable password-echoing modes (ignore mentions inside comments).
    commands = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "set -x" not in commands
    assert "psql -a" not in commands and "psql -e" not in commands
    # Login roles keep their security properties; helper roles stay NOLOGIN.
    for role in ("nlw_app", "nlw_worker", "nlw_scheduler"):
        assert f"CREATE ROLE {role} LOGIN" in text, role
    for prop in ("NOSUPERUSER", "NOBYPASSRLS", "NOCREATEDB", "NOCREATEROLE", "NOINHERIT"):
        assert prop in text, prop
    for helper in ("nlw_rls_bypass", "nlw_workspace_bootstrap"):
        assert f"CREATE ROLE {helper} NOLOGIN" in text, helper


def test_no_weak_password_literals_in_prod_bootstrap_sources() -> None:
    sources = [
        _INITDB / "00-roles.sh",
        ROOT / "docker-compose.prod.yml",
        ROOT / ".env.prod.example",
    ]
    for src in sources:
        text = src.read_text()
        for literal in _WEAK_LITERALS:
            assert literal not in text, f"{src.name} contains weak literal: {literal}"


def test_prod_postgres_requires_role_passwords_fail_fast() -> None:
    text = (ROOT / "docker-compose.prod.yml").read_text()
    for var in (
        "POSTGRES_PASSWORD",
        "NLW_APP_DB_PASSWORD",
        "NLW_WORKER_DB_PASSWORD",
        "NLW_SCHEDULER_DB_PASSWORD",
    ):
        assert f"${{{var}:?" in text, f"{var} must be required (:?) in prod compose"


def test_prod_worker_scheduler_have_no_app_role_fallback() -> None:
    compose = _load("docker-compose.prod.yml")
    text = (ROOT / "docker-compose.prod.yml").read_text()
    # No silent fallback to the app role for worker/scheduler.
    assert "WORKER_DATABASE_URL:-" not in text
    assert "SCHEDULER_DATABASE_URL:-" not in text
    assert "${WORKER_DATABASE_URL:?" in text
    assert "${SCHEDULER_DATABASE_URL:?" in text
    # Sanity: worker/scheduler read their own per-role URL var.
    assert "WORKER_DATABASE_URL" in compose["services"]["worker"]["environment"]["DATABASE_URL"]
    assert (
        "SCHEDULER_DATABASE_URL" in compose["services"]["scheduler"]["environment"]["DATABASE_URL"]
    )


def test_dev_compose_supplies_role_password_defaults() -> None:
    # Dev keeps local defaults so a fresh dev volume initializes without a secret
    # file; these match the dev DATABASE_URLs.
    env = _load("docker-compose.yml")["services"]["postgres"]["environment"]
    for var, default in (
        ("NLW_APP_DB_PASSWORD", "nlw_app"),
        ("NLW_WORKER_DB_PASSWORD", "nlw_worker"),
        ("NLW_SCHEDULER_DB_PASSWORD", "nlw_scheduler"),
    ):
        assert env[var] == f"${{{var}:-{default}}}", var


def test_env_prod_example_documents_required_vars() -> None:
    text = (ROOT / ".env.prod.example").read_text()
    for var in (
        "POSTGRES_PASSWORD=",
        "NLW_APP_DB_PASSWORD=",
        "NLW_WORKER_DB_PASSWORD=",
        "NLW_SCHEDULER_DB_PASSWORD=",
        "DATABASE_URL=",
        "DATABASE_MIGRATION_URL=",
        "WORKER_DATABASE_URL=",
        "SCHEDULER_DATABASE_URL=",
    ):
        assert var in text, var
    # Must document restrictive perms + explicit --env-file usage.
    assert "chmod 600 .env.prod" in text
    assert "chmod 600 docker/worker.secrets.env" in text
    assert "--env-file .env.prod" in text
    assert "openssl rand -hex 32" in text
