"""Application configuration, loaded from the environment (12-factor).

A single ``Settings`` object is the only place environment variables are read.
Secrets are never hard-coded; they arrive via the environment / ``.env``.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
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

    # --- Scheduler (M8) ---
    scheduler_scan_interval_s: float = 30.0  # due-schedule scan cadence
    scheduler_reconcile_interval_s: float = 60.0  # stale-run reconciliation cadence
    scheduler_batch_limit: int = 100  # max schedules / runs handled per tick
    # Per-tenant fairness cap for one reconcile batch (M11.5 P1D): at most this
    # many stale runs per tenant are selected, so one noisy tenant with thousands
    # of stale rows cannot starve a quiet tenant's single eligible run. Must be
    # >= 1 and <= scheduler_batch_limit (validated below).
    scheduler_reconcile_per_tenant_limit: int = 20
    # Bounded catch-up: fire only the latest missed occurrence within this window.
    scheduler_catchup_window_s: int = 3600
    # A PENDING run older than this with no progress is considered un-enqueued.
    scheduler_pending_threshold_s: int = 60
    # Recovery horizon (M9, req 4): after this age we STOP repeatedly re-enqueuing
    # a recoverable PENDING/RUNNING run (a poisoned-run guard). The run is not
    # mutated to FAILED; it is surfaced via a gauge + operational warning for a
    # human to resolve. WAITING_APPROVAL is exempt (a human may take arbitrarily
    # long to decide). Default 24h.
    scheduler_recovery_horizon_s: int = 86_400

    # --- Worker (M9) ---
    # Bounded infrastructure retries for advance_run (Dramatiq default is 20).
    # Business step failures never raise; only infra faults (e.g. a failed
    # enqueue) retry. Exhaustion is safe: the reconciler re-drives from Postgres.
    worker_max_retries: int = 5
    worker_min_backoff_ms: int = 1_000
    worker_max_backoff_ms: int = 60_000

    # --- Database pool + timeouts (M9) ---
    db_pool_size: int = 5
    db_max_overflow: int = 5
    db_pool_timeout_s: int = 30  # wait for a pooled connection before erroring
    db_pool_recycle_s: int = 1_800  # recycle connections older than this
    db_statement_timeout_ms: int = 30_000  # server-side runaway-query cap
    db_lock_timeout_ms: int = 10_000  # bound time spent waiting on a lock
    db_idle_in_tx_timeout_ms: int = 60_000  # kill idle-in-transaction sessions

    # --- Readiness probes (M11) ---
    # Application-level bound on EACH readiness dependency check. Server-side
    # statement_timeout cannot fire when a dependency is black-holed (e.g. a
    # paused Postgres holding an open socket), so /health/ready wraps every probe
    # in this timeout and reports the dependency "down" (503) rather than hanging.
    readiness_probe_timeout_s: float = 3.0

    # --- Recovery-lock gate (M11.5 P2 addendum) ---
    # The API re-evaluates the authoritative DR recovery lock (dr_restore_events)
    # on a short bounded cache: a business request refreshes the state at most once
    # per TTL, under a bounded query timeout. A cached ALLOWED decision goes stale
    # (-> UNKNOWN, fail closed) once older than the TTL, so losing the DB after being
    # allowed does not keep serving. Liveness is never gated (no query).
    recovery_gate_ttl_s: float = 5.0
    recovery_gate_query_timeout_s: float = 2.0

    # --- Observability / metrics (M9) ---
    # Each process (api / worker / scheduler) serves Prometheus metrics on its own
    # INTERNAL port. This port is never published publicly (see docker-compose);
    # only the reverse proxy / API HTTP route is public.
    metrics_enabled: bool = True
    metrics_host: str = "0.0.0.0"  # noqa: S104 - bound inside the container only
    metrics_port: int = 9100

    # --- HTTP hardening (M9) ---
    # CORS is deny-by-default (empty => no cross-origin access granted).
    cors_allow_origins: list[str] = Field(default_factory=list)
    # TrustedHost allowlist; "*" disables the check (tighten in staging/prod).
    trusted_hosts: list[str] = Field(default_factory=lambda: ["*"])
    # Reverse-proxy IPs whose X-Forwarded-* headers we trust. Empty => trust none.
    trusted_proxy_ips: list[str] = Field(default_factory=list)
    # Hard cap on the actual streamed request body (bytes); enforced independently
    # of any client-supplied Content-Length.
    max_request_body_bytes: int = 1_000_000
    request_id_header: str = "X-Request-Id"
    # By default request IDs are server-generated. Only honor an inbound ID (still
    # strictly validated/bounded) when this is enabled AND traffic is trusted.
    trust_inbound_request_id: bool = False
    # OpenAPI/docs: None => on outside production, off in production. Explicit
    # bool overrides. HSTS: None => on in production only.
    enable_docs: bool | None = None
    hsts_enabled: bool | None = None

    # --- Rate limiting (M9) ---
    rate_limit_enabled: bool = True
    # Cost-bearing / mutating endpoints fail CLOSED (503) if the limiter backend
    # is unavailable — rate limits are non-durable control state, not business
    # truth, so a Redis outage must not open an abuse window.
    rate_limit_fail_open: bool = False
    rate_limit_window_s: int = 60
    rate_limit_plans_per_min: int = 20  # LLM-cost endpoint (tightest)
    rate_limit_writes_per_min: int = 60  # connector/schedule/approval mutations

    # --- Per-tenant durable-resource caps (M9) ---
    max_connectors_per_tenant: int = 50
    max_schedules_per_tenant: int = 100
    max_workflows_per_tenant: int = 200

    # --- PostgreSQL connector egress policy (M11.5 P1B) ---
    # In production/staging, external Postgres destinations must resolve to
    # global/public addresses only and connect with sslmode=verify-full. This is
    # an OPERATOR-owned exact-IP / CIDR allowlist for approved PRIVATE databases
    # (e.g. a staging DB on a private network). It never comes from a connector
    # field, API request, planner output or tenant setting. Empty by default;
    # non-production (local/dev) allows private fixtures via the app_env gate, not
    # via this list. See ADR-009 / docs/security.
    postgres_destination_allowlist: list[str] = Field(default_factory=list)
    # Approved non-default ports for external Postgres in production/staging.
    # 5432 is always allowed; this only widens it under explicit operator control.
    postgres_extra_allowed_ports: list[int] = Field(default_factory=list)
    # CA trust for the external Postgres verify-full connection. None -> libpq
    # "system" (the OS trust store / ca-certificates bundle), which trusts a
    # managed provider's publicly-rooted certificate. An operator MAY point this
    # at a specific CA bundle path inside the container; it is NOT tenant-supplied.
    postgres_ssl_root_cert: str | None = None

    @model_validator(mode="after")
    def _validate_reconcile_fairness(self) -> "Settings":
        """The per-tenant reconcile cap must be a positive share of the global
        batch: >= 1 and <= scheduler_batch_limit (P1D fairness invariant)."""
        if self.scheduler_reconcile_per_tenant_limit < 1:
            raise ValueError("scheduler_reconcile_per_tenant_limit must be >= 1")
        if self.scheduler_reconcile_per_tenant_limit > self.scheduler_batch_limit:
            raise ValueError(
                "scheduler_reconcile_per_tenant_limit must be <= scheduler_batch_limit"
            )
        if self.recovery_gate_ttl_s <= 0:
            raise ValueError("recovery_gate_ttl_s must be > 0")
        if self.recovery_gate_query_timeout_s <= 0:
            raise ValueError("recovery_gate_query_timeout_s must be > 0")
        return self

    @property
    def docs_enabled(self) -> bool:
        """OpenAPI/docs served? Off in production by default; explicit override wins."""
        if self.enable_docs is not None:
            return self.enable_docs
        return self.app_env != "production"

    @property
    def hsts_active(self) -> bool:
        """Send HSTS? Production HTTPS only by default; explicit override wins."""
        if self.hsts_enabled is not None:
            return self.hsts_enabled
        return self.app_env == "production"

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
