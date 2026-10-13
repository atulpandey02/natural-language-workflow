"""Every request transaction commits BEFORE the response is sent.

``get_session`` is a yield dependency that commits on exit. FastAPI exits a
request-scoped yield dependency only after the response has been sent, so a
client could read stale state right after a 2xx, and a failed commit would
still have answered 2xx. Function scope commits (or fails, as a 500) before
the response exists. This walks every route of the real application, so a new
endpoint, or a new dependency that takes a session, cannot quietly reintroduce
the request scope. The behaviour itself is proven against Postgres in
tests/integration/test_commit_before_response.py."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from fastapi import FastAPI
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute

from nlw.api.app import create_app
from nlw.api.deps import get_session
from nlw.core.config import Settings


def _walk(
    dependant: Dependant, path: tuple[str, ...]
) -> Iterator[tuple[tuple[str, ...], Dependant]]:
    for sub in dependant.dependencies:
        name = getattr(sub.call, "__name__", repr(sub.call))
        yield (*path, name), sub
        yield from _walk(sub, (*path, name))


class _Route:
    def __init__(self, label: str, dependant: Dependant) -> None:
        self.label, self.dependant = label, dependant


def _session_uses(routes: list[_Route]) -> list[tuple[str, tuple[str, ...], str]]:
    uses: list[tuple[str, tuple[str, ...], str]] = []
    for route in routes:
        for path, dep in _walk(route.dependant, ()):
            if dep.call is get_session:
                # Unset means request scope (FastAPI's default for a yield dependency).
                uses.append((route.label, path, dep.scope or "request"))
    return uses


def _app_routes(app: FastAPI) -> list[_Route]:
    """Every route with its EFFECTIVE dependant (router-level dependencies
    included). FastAPI 0.141 registers included routers lazily."""
    out = []
    for r in app.routes:
        if isinstance(r, APIRoute):
            out.append(_Route(f"{sorted(r.methods or ())} {r.path}", r.dependant))
        elif hasattr(r, "effective_route_contexts"):
            for ctx in r.effective_route_contexts():
                if ctx.dependant is not None:
                    out.append(_Route(ctx.path, ctx.dependant))
    return out


def _routes(tmp_path: Path) -> list[_Route]:
    settings = Settings(  # type: ignore[call-arg]
        _env_file=None,
        datasets_api_enabled=True,
        dataset_storage_backend="local",
        dataset_storage_root=str(tmp_path),
    )
    return _app_routes(create_app(settings))


def test_every_session_dependency_commits_before_the_response(tmp_path: Path) -> None:
    routes = _routes(tmp_path)
    uses = _session_uses(routes)
    assert len(routes) > 50 and len(uses) > 50  # the walk really reaches every router
    wrong = [(route, path) for route, path, scope in uses if scope != "function"]
    assert wrong == []


def test_negative_control_a_request_scoped_session_is_reported() -> None:
    """The walk sees the scope FastAPI will actually use: a route taking the
    session in request scope is reported."""
    from fastapi import Depends
    from sqlalchemy.ext.asyncio import AsyncSession

    app = FastAPI()

    @app.post("/t")
    async def t(session: AsyncSession = Depends(get_session)) -> None:  # request scope
        return None

    assert [scope for _, _, scope in _session_uses(_app_routes(app))] == ["request"]
