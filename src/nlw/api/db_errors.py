"""Precise classification of database failures at the API boundary.

Only an EXACT, expected condition (a specific SQLSTATE and, where it matters, the
exact constraint name) is translated into a business response. Everything else
is an infrastructure failure and becomes a sanitized ``5xx``:

- connection loss / operator intervention / resource exhaustion / transient
  serialization failures -> ``503`` with ``Retry-After`` (the client may retry);
- anything unexpected -> re-raised, so the global handler logs it INTERNALLY (with
  the exception) and returns the opaque ``500``.

Nothing here reads or forwards driver text, SQL, connection strings or constraint
internals to a caller; only the 5-character SQLSTATE and the exception class name
are logged.
"""

from __future__ import annotations

import structlog
from fastapi import HTTPException, status
from sqlalchemy.exc import InterfaceError, OperationalError

from nlw.observability import metrics

log = structlog.get_logger(__name__)

# Migration 0015: partial unique index on (tenant_id, email) WHERE status='pending'.
PENDING_INVITATION_UNIQUE_INDEX = "uq_invitation_pending_email"

# SQLSTATE values / classes the API treats as "the database is unavailable right
# now" (transient; the caller may retry). Class 08 = connection exception,
# 53 = insufficient resources, 57 = operator intervention (admin shutdown, query
# cancelled / statement timeout); 40001 / 40P01 = serialization failure / deadlock.
_UNAVAILABLE_CLASSES = frozenset({"08", "53", "57"})
_UNAVAILABLE_CODES = frozenset({"40001", "40P01"})

UNAVAILABLE_MESSAGE = "service temporarily unavailable"
_RETRY_AFTER = {"Retry-After": "5"}

SQLSTATE_INSUFFICIENT_PRIVILEGE = "42501"
SQLSTATE_INVALID_PARAMETER_VALUE = "22023"
SQLSTATE_UNIQUE_VIOLATION = "23505"
SQLSTATE_CHECK_VIOLATION = "23514"


def sqlstate(exc: BaseException) -> str | None:
    """The DB-API SQLSTATE behind a SQLAlchemy error (or None)."""
    orig = getattr(exc, "orig", None)
    state = getattr(orig, "sqlstate", None) or getattr(exc, "sqlstate", None)
    return str(state) if state else None


def constraint_name(exc: BaseException) -> str | None:
    """The violated constraint/index name reported by the driver diagnostics."""
    orig = getattr(exc, "orig", None)
    diag = getattr(orig, "diag", None)
    name = getattr(diag, "constraint_name", None)
    return str(name) if name else None


def is_unique_violation_of(exc: BaseException, constraint: str) -> bool:
    """True only for a unique violation of EXACTLY ``constraint`` — never for any
    other integrity failure and never when the driver reports no constraint."""
    return sqlstate(exc) == SQLSTATE_UNIQUE_VIOLATION and constraint_name(exc) == constraint


def is_unavailable(exc: BaseException) -> bool:
    """Connection / operational / transient failures the caller may retry."""
    state = sqlstate(exc)
    if state is not None:
        return state[:2] in _UNAVAILABLE_CLASSES or state in _UNAVAILABLE_CODES
    if getattr(exc, "connection_invalidated", False):
        return True
    return isinstance(exc, OperationalError | InterfaceError)


def unavailable(exc: BaseException, operation: str) -> HTTPException:
    """Sanitized 503 for a transient database failure (logged by class + SQLSTATE)."""
    log.warning(
        "db.unavailable",
        operation=operation,
        error_class=type(exc).__name__,
        sqlstate=sqlstate(exc),
    )
    metrics.record_error("db_unavailable")
    return HTTPException(
        status.HTTP_503_SERVICE_UNAVAILABLE, UNAVAILABLE_MESSAGE, headers=dict(_RETRY_AFTER)
    )


def log_unexpected(exc: BaseException, operation: str) -> None:
    """Record an unexpected database failure (class + SQLSTATE only). The caller
    re-raises so the global handler returns the opaque 500 and logs the trace."""
    log.error(
        "db.unexpected_failure",
        operation=operation,
        error_class=type(exc).__name__,
        sqlstate=sqlstate(exc),
    )
