"""Safe API error handling (M9, req 6/12).

Every error response has the same machine-readable shape:

    {"error": {"code": "<slug>", "message": "<safe text>"}}

Public responses never contain stack traces, raw driver/provider strings, secret
values, or SQL. Client errors (4xx) carry the author-controlled message we set
when raising ``HTTPException``. Unexpected server errors are logged INTERNALLY
with the correlation id and returned to the caller as an opaque 500.
"""

from typing import Any

import structlog
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from nlw.observability import metrics

log = structlog.get_logger(__name__)

# Map common status codes to a stable, safe error code slug.
_CODE_BY_STATUS = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    413: "payload_too_large",
    422: "unprocessable_entity",
    429: "rate_limited",
    500: "internal_error",
    502: "bad_gateway",
    503: "service_unavailable",
}


def _body(code: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message}}


def _error_response(
    status_code: int, message: str, headers: dict[str, str] | None = None
) -> JSONResponse:
    code = _CODE_BY_STATUS.get(status_code, "error")
    return JSONResponse(status_code=status_code, content=_body(code, message), headers=headers)


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def _http_exc(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        # The detail is author-controlled (we set it when raising) => safe to show.
        message = exc.detail if isinstance(exc.detail, str) else "request failed"
        headers = dict(exc.headers) if exc.headers else None
        return _error_response(exc.status_code, message, headers)

    @app.exception_handler(RequestValidationError)
    async def _validation_exc(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Do NOT echo submitted values; report field locations + messages only.
        details = [
            {"loc": list(e.get("loc", [])), "msg": str(e.get("msg", "")), "type": e.get("type", "")}
            for e in exc.errors()
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "request validation failed",
                    "details": details,
                }
            },
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Log internally with full type/context; return an opaque message.
        metrics.record_error(type(exc).__name__)
        log.error(
            "api.unhandled_exception",
            error_class=type(exc).__name__,
            path=request.url.path,
            method=request.method,
            exc_info=exc,
        )
        return _error_response(status.HTTP_500_INTERNAL_SERVER_ERROR, "internal server error")


# Re-exported for callers that raise directly.
__all__ = ["install_exception_handlers", "HTTPException"]
