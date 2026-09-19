"""FastAPI control-plane application.

Operational endpoints:

- ``GET /health``        liveness  (process is up)
- ``GET /health/ready``  readiness (Postgres + Redis reachable)
- ``GET /version``       the running package version

Identity/tenancy endpoints are mounted from ``nlw.api.routers``. The control
plane never executes workflow steps; that is the worker's job.
"""

from collections.abc import AsyncIterator, Awaitable
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from nlw import __version__
from nlw.api.routers import approvals, connectors, identity, plans, schedules
from nlw.auth.supabase import build_auth_provider
from nlw.core.config import Settings, get_settings
from nlw.core.logging import configure_logging
from nlw.db.session import check_connection, create_engine, create_sessionmaker
from nlw.planner.provider import build_llm_provider
from nlw.worker.broker import check_redis

log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create shared resources on startup and dispose them on shutdown."""
    settings: Settings = app.state.settings
    configure_logging(settings)
    app.state.engine = create_engine(settings)
    app.state.sessionmaker = create_sessionmaker(app.state.engine)
    app.state.auth_provider = build_auth_provider(settings)
    # Planner provider (M6). Built once; the platform LLM key (if any) lives only
    # in the API process env, never in worker/scheduler.
    app.state.llm_provider = build_llm_provider(settings)
    log.info("api.startup", app_env=settings.app_env, llm_provider=settings.llm_provider)
    try:
        yield
    finally:
        await app.state.engine.dispose()
        log.info("api.shutdown")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory. Pass explicit ``settings`` in tests."""
    settings = settings or get_settings()
    app = FastAPI(title="NLW Control Plane", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.include_router(identity.router)
    app.include_router(connectors.router)
    app.include_router(plans.router)
    app.include_router(approvals.router)
    app.include_router(schedules.router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/version")
    async def version() -> dict[str, str]:
        return {"version": __version__}

    @app.get("/health/ready")
    async def ready() -> JSONResponse:
        settings_: Settings = app.state.settings
        checks: dict[str, str] = {}
        healthy = True

        async def probe(name: str, coro: Awaitable[None]) -> None:
            nonlocal healthy
            try:
                await coro
                checks[name] = "ok"
            except Exception as exc:  # readiness must never raise; report it
                checks[name] = "down"
                healthy = False
                log.warning("readiness.check_failed", dependency=name, error=str(exc))

        await probe("postgres", check_connection(app.state.engine))
        await probe("redis", check_redis(settings_))
        return JSONResponse(
            status_code=200 if healthy else 503,
            content={"status": "ready" if healthy else "not_ready", "checks": checks},
        )

    return app
