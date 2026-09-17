"""Settings load defaults and honor environment overrides."""

from nlw.core.config import Settings


def test_defaults() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.app_env == "local"
    assert settings.database_url.startswith("postgresql+psycopg://")


def test_env_override(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("APP_ENV", "staging")
    monkeypatch.setenv("LOG_LEVEL", "warning")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.app_env == "staging"
    assert settings.log_level == "warning"
