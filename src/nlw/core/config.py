"""Application configuration, loaded from the environment (12-factor).

A single ``Settings`` object is the only place environment variables are read.
Secrets are never hard-coded; they arrive via the environment / ``.env``.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["local", "dev", "staging", "production"]
LLMProviderName = Literal["stub", "anthropic"]


class Settings(BaseSettings):
    """Runtime configuration for every process role (api / worker / scheduler)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,  # allow construction by field name despite env aliases
    )

    app_env: Environment = "local"
    log_level: str = "info"

    # Application runtime connection: the RESTRICTED nlw_app role (no superuser,
    # no BYPASSRLS). RLS + SET LOCAL app.* GUCs enforce tenant isolation.
    database_url: str = "postgresql+psycopg://nlw_app:nlw_app@localhost:5432/nlw"
    # Migration/owner connection used by Alembic only (DDL + grants + policies).
    # Falls back to database_url when unset.
    database_migration_url: str | None = None
    redis_url: str = "redis://localhost:6379/0"

    # --- Authentication (Supabase; identity only) ---
    # Production target: asymmetric JWKS verification (RS256/ES256). See ADR-007.
    supabase_url: str = ""  # e.g. https://<project>.supabase.co
    supabase_jwks_url: str | None = None  # defaults to {supabase_url}/auth/v1/.well-known/jwks.json
    supabase_jwt_issuer: str | None = None  # defaults to {supabase_url}/auth/v1
    supabase_jwt_aud: str = "authenticated"
    # LEGACY/dev only: symmetric HS256 verification. Not the production design.
    supabase_jwt_secret: str | None = None

    # --- Natural-language planner (M6) ---
    # The planner runs API-side. `llm_api_key` (env NLW_LLM_API_KEY) is PLATFORM
    # config, NOT a tenant/connector secret; it is provided to the API process
    # only and must never reach worker/scheduler or model context.
    llm_provider: LLMProviderName = Field(default="stub", validation_alias="NLW_LLM_PROVIDER")
    llm_model: str = Field(default="claude-sonnet-5", validation_alias="NLW_LLM_MODEL")
    llm_api_key: str | None = Field(default=None, validation_alias="NLW_LLM_API_KEY")
    llm_timeout_s: int = 30  # hard-capped in the planner
    llm_max_output_tokens: int = 4096  # hard-capped in the planner
    # Hard cap on accepted prompt size; the API rejects longer prompts (422)
    # before any provider call.
    llm_max_prompt_chars: int = 8000

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
