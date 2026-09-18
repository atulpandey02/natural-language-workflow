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

    # --- Authentication (Supabase; identity only) ---
    # Production target: asymmetric JWKS verification (RS256/ES256). See ADR-007.
    supabase_url: str = ""  # e.g. https://<project>.supabase.co
    supabase_jwks_url: str | None = None  # defaults to {supabase_url}/auth/v1/.well-known/jwks.json
    supabase_jwt_issuer: str | None = None  # defaults to {supabase_url}/auth/v1
    supabase_jwt_aud: str = "authenticated"
    # LEGACY/dev only: symmetric HS256 verification. Not the production design.
    supabase_jwt_secret: str | None = None

    @property
    def effective_jwks_url(self) -> str | None:
        if self.supabase_jwks_url:
            return self.supabase_jwks_url
        if self.supabase_url:
            return f"{self.supabase_url.rstrip('/')}/auth/v1/.well-known/jwks.json"
        return None

    @property
    def effective_issuer(self) -> str | None:
        if self.supabase_jwt_issuer:
            return self.supabase_jwt_issuer
        if self.supabase_url:
            return f"{self.supabase_url.rstrip('/')}/auth/v1"
        return None


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
