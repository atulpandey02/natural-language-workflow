"""HTTP hardening middleware (M9, req 6/12).

- ``BodySizeLimitMiddleware`` — rejects oversized requests based on the ACTUAL
  streamed body size (not a trusted ``Content-Length``), returning a safe 413.
- ``ObservabilityMiddleware`` — mints/validates a correlation id, binds it into
  the log context for the request scope (and clears it at the boundary), sets it
  on the response, records HTTP metrics by method + route template (low
  cardinality), and applies security headers.
"""

import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from nlw.core.config import Settings
from nlw.observability import metrics
from nlw.observability.correlation import (
    bind_request_context,
    clear_request_context,
    new_request_id,
    sanitize_inbound_id,
)

_413_BODY = b'{"error":{"code":"payload_too_large","message":"request body too large"}}'


def _content_length(scope: Scope) -> int | None:
    for name, value in scope.get("headers", []):
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


async def _send_413(send: Send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(_413_BODY)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": _413_BODY})


class BodySizeLimitMiddleware:
    """Request-body cap enforced on the ACTUAL byte count, not Content-Length.

    The body is drained up to the limit before the app runs: an honest oversized
    Content-Length is rejected immediately, and a chunked/streamed body is
    rejected as soon as the real byte total crosses the cap (so a lying or absent
    Content-Length cannot smuggle a large body). Within-limit bodies are buffered
    and replayed to the app unchanged. Draining here (rather than raising from a
    wrapped ``receive``) keeps the 413 from being swallowed by the app's inner
    ServerError/Exception handling.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Fast path: reject an honest oversized Content-Length before reading.
        declared = _content_length(scope)
        if declared is not None and declared > self.max_bytes:
            await _send_413(send)
            return

        buffered: list[Message] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                buffered.append(message)
                break
            total += len(message.get("body", b""))
            if total > self.max_bytes:
                await _send_413(send)
                return
            buffered.append(message)
            if not message.get("more_body", False):
                break

        index = 0

        async def replay() -> Message:
            nonlocal index
            if index < len(buffered):
                message = buffered[index]
                index += 1
                return message
            # Body already fully replayed; behave like an exhausted stream.
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay, send)


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """Correlation id + HTTP metrics + security headers."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        settings = self.settings
        request_id = None
        if settings.trust_inbound_request_id:
            request_id = sanitize_inbound_id(request.headers.get(settings.request_id_header))
        request_id = request_id or new_request_id()

        bind_request_context(request_id=request_id)
        start = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            elapsed = time.perf_counter() - start
            clear_request_context()

        route = request.scope.get("route")
        route_label = getattr(route, "path", None) or "unmatched"
        metrics.record_http(request.method, route_label, response.status_code, elapsed)

        response.headers[settings.request_id_header] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if settings.hsts_active:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
