"""HTTP hardening middleware + safe error handlers (M9), on a throwaway app."""

from collections.abc import Iterator

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel

from nlw.api.errors import install_exception_handlers
from nlw.api.middleware import BodySizeLimitMiddleware, ObservabilityMiddleware
from nlw.core.config import Settings


class _Body(BaseModel):
    value: str


def _app(**over: object) -> FastAPI:
    base: dict[str, object] = {"_env_file": None}
    base.update(over)
    settings = Settings(**base)  # type: ignore[arg-type]
    app = FastAPI()
    app.add_middleware(ObservabilityMiddleware, settings=settings)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    install_exception_handlers(app)

    @app.post("/echo")
    async def echo(body: _Body) -> dict[str, str]:
        return {"value": body.value}

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("super secret internal detail")

    @app.get("/nope")
    async def nope() -> None:
        raise HTTPException(404, "resource missing")

    return app


def _client(**over: object) -> TestClient:
    return TestClient(_app(**over), raise_server_exceptions=False)


def test_security_headers_and_request_id_generated() -> None:
    with _client() as c:
        r = c.post("/echo", json={"value": "x"})
    assert r.status_code == 200
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    rid = r.headers["X-Request-Id"]
    assert len(rid) == 32  # server-generated hex


def test_inbound_request_id_ignored_by_default() -> None:
    with _client() as c:
        r = c.post("/echo", json={"value": "x"}, headers={"X-Request-Id": "client-supplied"})
    assert r.headers["X-Request-Id"] != "client-supplied"


def test_inbound_request_id_honored_when_enabled_and_valid() -> None:
    with _client(trust_inbound_request_id=True) as c:
        ok = c.post("/echo", json={"value": "x"}, headers={"X-Request-Id": "good-123"})
        bad = c.post("/echo", json={"value": "x"}, headers={"X-Request-Id": "has spaces"})
    assert ok.headers["X-Request-Id"] == "good-123"
    assert bad.headers["X-Request-Id"] != "has spaces"  # invalid => regenerated


def test_hsts_only_when_active() -> None:
    with _client(app_env="local") as c:
        assert "Strict-Transport-Security" not in c.post("/echo", json={"value": "x"}).headers
    with _client(app_env="production") as c:
        assert "Strict-Transport-Security" in c.post("/echo", json={"value": "x"}).headers


def test_body_size_limit_content_length_fast_path() -> None:
    with _client(max_request_body_bytes=50) as c:
        r = c.post("/echo", json={"value": "z" * 500})
    assert r.status_code == 413
    assert r.json() == {"error": {"code": "payload_too_large", "message": "request body too large"}}


def test_body_size_limit_streamed_without_content_length() -> None:
    # A generator body makes httpx use chunked transfer (no Content-Length), so
    # the cap must be enforced on the actual streamed bytes.
    def gen() -> Iterator[bytes]:
        for _ in range(10):
            yield b"x" * 100

    with _client(max_request_body_bytes=50) as c:
        r = c.post("/echo", content=gen(), headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_within_limit_body_replayed_to_app() -> None:
    with _client(max_request_body_bytes=10_000) as c:
        r = c.post("/echo", json={"value": "hello"})
    assert r.status_code == 200 and r.json() == {"value": "hello"}


def test_unhandled_exception_is_opaque_500() -> None:
    with _client() as c:
        r = c.get("/boom")
    assert r.status_code == 500
    assert r.json() == {"error": {"code": "internal_error", "message": "internal server error"}}
    assert "secret" not in r.text


def test_http_exception_uses_safe_shape() -> None:
    with _client() as c:
        r = c.get("/nope")
    assert r.status_code == 404
    assert r.json() == {"error": {"code": "not_found", "message": "resource missing"}}


def test_validation_error_shape_without_values() -> None:
    with _client() as c:
        r = c.post("/echo", json={"wrong": "field"})
    assert r.status_code == 422
    body = r.json()
    assert body["error"]["code"] == "validation_error"
    assert "details" in body["error"]
