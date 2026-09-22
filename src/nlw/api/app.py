"""FastAPI control-plane application.

Operational endpoints:

- ``GET /health``        liveness  (process is up)
- ``GET /health/ready``  readiness (Postgres + Redis + schema compatibility)
- ``GET /version``       the running package version

Identity/tenancy endpoints are mounted from ``nlw.api.routers``. The control
plane never executes workflow steps; that is the worker's job.

M9 hardening: safe error handlers, a streamed request-body cap, correlation ids
+ HTTP metrics + security headers, CORS/TrustedHost, and production docs gating.
Prometheus metrics are served on a SEPARATE internal port (see
``nlw.observability.metrics``), never on this public app.
"""

import asyncio
from collections.abc import AsyncIterator, Awaitable
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from nlw import __version__
from nlw.api.errors import install_exception_handlers
from nlw.api.middleware import (
    BodySizeLimitMiddleware,
    ObservabilityMiddleware,
    RecoveryGateMiddleware,
)
from nlw.api.recovery_gate import RecoveryGate
from nlw.api.routers import (
    approvals,
    connectors,
    identity,
    members,
    plans,
    runs,
    schedules,
    workflows,
)
from nlw.auth.supabase import build_auth_provider
from nlw.core.config import Settings, get_settings
from nlw.core.logging import configure_logging
from nlw.db.schema import check_schema
from nlw.db.session import check_connection, create_engine, create_sessionmaker
from nlw.planner.provider import build_llm_provider
from nlw.ratelimit.limiter import RateLimiter
from nlw.worker.broker import check_redis

log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create shared resources on startup and dispose them on shutdown."""
    settings: Settings = app.state.settings
    configure_logging(settings)
    app.state.engine = create_engine(settings)
    # Authoritative recovery lock (M11.5 P2 addendum): the API stays ALIVE for
    # DB-independent liveness, but a LIVE gate re-evaluates the authoritative
    # dr_restore_events state and fail-closes readiness + all business routes until
    # the newest generation is operator-enabled. Never decides ALLOWED from a
    # boot-time connection failure; re-locks a running process when a later restore
    # generation appears. (Worker/scheduler stay boot-time fail-closed.)
    app.state.recovery_gate = RecoveryGate(
        app.state.engine,
        ttl_s=settings.recovery_gate_ttl_s,
        query_timeout_s=settings.recovery_gate_query_timeout_s,
    )
    # Best-effort initial evaluation; NEVER blocks boot (liveness must stay up).
    initial = await app.state.recovery_gate.check()
    log.info("api.recovery_gate_initial", state=initial)
    app.state.sessionmaker = create_sessionmaker(app.state.engine)
    app.state.auth_provider = build_auth_provider(settings)
    # Planner provider (M6). Built once; the platform LLM key (if any) lives only
    # in the API process env, never in worker/scheduler.
    app.state.llm_provider = build_llm_provider(settings)
    # Rate-limiter Redis client (control state; distinct use from the queue).
    app.state.redis = aioredis.from_url(settings.redis_url)
    app.state.rate_limiter = RateLimiter(
        app.state.redis,
        window_s=settings.rate_limit_window_s,
        fail_open=settings.rate_limit_fail_open,
    )
    # Capacity metrics (M11): expose the API DB pool at scrape time.
    from nlw.observability import metrics as _metrics

    pool = app.state.engine.sync_engine.pool
    _metrics.register_pool_provider(lambda: (pool.checkedout(), pool.overflow()))
    _metrics.register_capacity_collector()
    log.info("api.startup", app_env=settings.app_env, llm_provider=settings.llm_provider)
    try:
        yield
    finally:
        await app.state.engine.dispose()
        await app.state.redis.aclose()
        log.info("api.shutdown")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory. Pass explicit ``settings`` in tests."""
    settings = settings or get_settings()
    app = FastAPI(
        title="NLW Control Plane",
        version=__version__,
        lifespan=lifespan,
        # Docs are disabled in production by default (req 6).
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )
    app.state.settings = settings

    # Middleware order (outermost first): body cap -> observability/headers ->
    # trusted host -> CORS -> recovery gate. The body cap runs first so oversized
    # requests are rejected before any routing work; the recovery gate runs LAST
    # (innermost, just before routing) so gated 503s still carry a correlation id.
    app.add_middleware(RecoveryGateMiddleware)
    if settings.cors_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allow_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
    app.add_middleware(ObservabilityMiddleware, settings=settings)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)

    install_exception_handlers(app)

    app.include_router(identity.router)
    app.include_router(members.router)
    app.include_router(connectors.router)
    app.include_router(plans.router)
    app.include_router(approvals.router)
    app.include_router(schedules.router)
    app.include_router(workflows.router)
    app.include_router(runs.router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/version")
    async def version() -> dict[str, str]:
        return {"version": __version__}

    @app.get("/health/ready")
    async def ready() -> JSONResponse:
        settings_: Settings = app.state.settings
        timeout_s = settings_.readiness_probe_timeout_s
        checks: dict[str, str] = {}
        healthy = True

        async def probe(name: str, coro: Awaitable[None]) -> bool:
            """Run a dependency check under an application-level timeout.

            A frozen dependency (e.g. a black-holed/paused Postgres) cannot be
            bounded by server-side timeouts, so each probe is wrapped here; on
            timeout or failure the dependency is reported "down" (never raised,
            never leaking connection internals to the client).
            """
            nonlocal healthy
            try:
                async with asyncio.timeout(timeout_s):
                    await coro
                checks[name] = "ok"
                return True
            except TimeoutError:
                checks[name] = "down"
                healthy = False
                log.warning("readiness.check_timeout", dependency=name, timeout_s=timeout_s)
                return False
            except Exception as exc:  # readiness must never raise; report it
                checks[name] = "down"
                healthy = False
                log.warning("readiness.check_failed", dependency=name, error=str(exc))
                return False

        # Recovery lock is part of readiness: a locked/unknown generation is NOT
        # ready even if Postgres/Redis are up. This reads the live gate (bounded).
        recovery_state = await app.state.recovery_gate.check()
        checks["recovery"] = "ok" if recovery_state == "ALLOWED" else recovery_state.lower()
        if recovery_state != "ALLOWED":
            healthy = False

        postgres_ok = await probe("postgres", check_connection(app.state.engine))
        await probe("redis", check_redis(settings_))
        # Schema compatibility (req 10) also depends on Postgres. If the Postgres
        # probe already failed/timed out, mark schema down WITHOUT a second
        # blocking DB round-trip — otherwise a black-holed DB would incur a
        # second full probe timeout. The expected head is cached in-process.
        if postgres_ok:
            await probe("schema", check_schema(app.state.engine))
        else:
            checks["schema"] = "down"
            healthy = False
        return JSONResponse(
            status_code=200 if healthy else 503,
            content={"status": "ready" if healthy else "not_ready", "checks": checks},
        )

    return app
