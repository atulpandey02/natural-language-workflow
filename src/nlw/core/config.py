"""Application configuration, loaded from the environment (12-factor).

A single ``Settings`` object is the only place environment variables are read.
Secrets are never hard-coded; they arrive via the environment / ``.env``.
"""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["local", "dev", "staging", "production"]


class Settings(BaseSettings):
    """Runtime configuration for every process role (api / worker / scheduler)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: Environment = "local"
    log_level: str = "info"

    # SQLAlchemy URL using the psycopg (v3) driver, valid for both the async
    # application engine and the sync Alembic engine.
    database_url: str = "postgresql+psycopg://nlw:nlw@localhost:5432/nlw"
    redis_url: str = "redis://localhost:6379/0"


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
