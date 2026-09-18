"""FastAPI control-plane application.

M1a exposes only operational endpoints:

- ``GET /health``        liveness  (process is up)
- ``GET /health/ready``  readiness (dependencies reachable — Postgres in M1a)
- ``GET /version``       the running package version

The control plane never executes workflow steps; that is the worker's job.
"""

from collections.abc import AsyncIterator, Awaitable
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from nlw import __version__
from nlw.core.config import Settings, get_settings
from nlw.core.logging import configure_logging
from nlw.db.session import check_connection, create_engine
from nlw.worker.broker import check_redis

log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create shared resources on startup and dispose them on shutdown."""
    settings: Settings = app.state.settings
    configure_logging(settings)
    app.state.engine = create_engine(settings)
    log.info("api.startup", app_env=settings.app_env)
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
