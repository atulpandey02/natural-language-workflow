"""M9 settings: docs/HSTS gating and hardening defaults."""

from nlw.core.config import Settings


def _s(**over: object) -> Settings:
    base: dict[str, object] = {"_env_file": None}
    base.update(over)
    return Settings(**base)  # type: ignore[arg-type]


def test_docs_on_outside_production_off_in_production() -> None:
    assert _s(app_env="local").docs_enabled is True
    assert _s(app_env="staging").docs_enabled is True
    assert _s(app_env="production").docs_enabled is False


def test_docs_explicit_override_wins() -> None:
    assert _s(app_env="production", enable_docs=True).docs_enabled is True
    assert _s(app_env="local", enable_docs=False).docs_enabled is False


def test_hsts_production_only_by_default() -> None:
    assert _s(app_env="local").hsts_active is False
    assert _s(app_env="production").hsts_active is True
    assert _s(app_env="local", hsts_enabled=True).hsts_active is True


def test_hardening_defaults() -> None:
    s = _s()
    assert s.rate_limit_enabled is True
    assert s.rate_limit_fail_open is False  # cost/mutating endpoints fail closed
    assert s.max_request_body_bytes == 1_000_000
    assert s.trusted_proxy_ips == []  # trust no forwarded headers by default
    assert s.max_connectors_per_tenant > 0
    assert s.scheduler_recovery_horizon_s == 86_400
    assert s.db_statement_timeout_ms > 0
