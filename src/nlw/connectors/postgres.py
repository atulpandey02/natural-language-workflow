"""Postgres connector: strict config, JSON credential secret, and a read-only,
timeout-bounded, row/byte-capped query path.

Defense in depth (ADR-009): sqlglot validation (elsewhere) + read-only
transaction/session (here) + a SELECT-only external role (tenant/test side).
All external-driver errors are sanitized to safe typed errors — raw psycopg
strings, connection strings, and credentials never surface.
"""

import datetime
import json
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, NoReturn

import psycopg
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

from nlw.connectors.base import (
    ConnectorConfigError,
    ConnectorContext,
    ConnectorType,
    ConnectorUnhealthyError,
    register_connector_type,
)
from nlw.registry.registry import ToolExecutionError
from nlw.secrets.store import SecretError

# Substrings that identify a connect-time authentication/authorization failure.
# psycopg does not populate SQLSTATE for connection-establishment errors, so we
# inspect the message INTERNALLY to classify it — the raw text never escapes.
_AUTH_MESSAGE_MARKERS = (
    "authentication failed",
    "no password supplied",
    "password supplied",
    "pg_hba.conf",
    'role "',  # e.g. role "x" does not exist / is not permitted to log in
)

# --- Hard platform caps (enforced independently of tenant config) ---
_STATEMENT_TIMEOUT_CAP_MS = 30_000
_LOCK_TIMEOUT_CAP_MS = 30_000
_CONNECT_TIMEOUT_CAP_S = 15
_MAX_ROWS_CAP = 10_000
_MAX_RESULT_BYTES_CAP = 10_000_000


class SecretFormatError(SecretError):
    """The credential payload is malformed (never echoes the payload)."""


class PostgresUnavailableError(Exception):
    """External Postgres is unreachable — RETRYABLE (not a business step failure)."""


class PostgresAuthError(ToolExecutionError, ConnectorUnhealthyError):
    """Authentication failed — deterministic; marks the connector unhealthy."""


class PostgresTimeoutError(ToolExecutionError):
    """The query exceeded the statement timeout — deterministic."""


class PostgresQueryError(ToolExecutionError):
    """The query failed to execute — deterministic."""


class ResultTooLargeError(ToolExecutionError):
    """The serialized result exceeded max_result_bytes — deterministic."""


class ResultUnsupportedTypeError(ToolExecutionError):
    """A column value has an unsupported type for JSON normalization."""


class PostgresConnectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str
    port: int = Field(default=5432, ge=1, le=65535)
    database: str
    sslmode: str = "prefer"
    allowed_schemas: list[str] = Field(default_factory=lambda: ["public"], min_length=1)
    allowed_tables: list[str] | None = None
    statement_timeout_ms: int = 5000
    lock_timeout_ms: int = 3000
    connect_timeout_s: int = 5
    max_rows: int = 1000
    max_result_bytes: int = 1_000_000

    @field_validator("sslmode")
    @classmethod
    def _valid_sslmode(cls, v: str) -> str:
        allowed = {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}
        if v not in allowed:
            raise ValueError(f"invalid sslmode: {v}")
        return v

    @field_validator("statement_timeout_ms")
    @classmethod
    def _cap_statement(cls, v: int) -> int:
        return max(1, min(v, _STATEMENT_TIMEOUT_CAP_MS))

    @field_validator("lock_timeout_ms")
    @classmethod
    def _cap_lock(cls, v: int) -> int:
        return max(1, min(v, _LOCK_TIMEOUT_CAP_MS))

    @field_validator("connect_timeout_s")
    @classmethod
    def _cap_connect(cls, v: int) -> int:
        return max(1, min(v, _CONNECT_TIMEOUT_CAP_S))

    @field_validator("max_rows")
    @classmethod
    def _cap_rows(cls, v: int) -> int:
        return max(1, min(v, _MAX_ROWS_CAP))

    @field_validator("max_result_bytes")
    @classmethod
    def _cap_bytes(cls, v: int) -> int:
        return max(1, min(v, _MAX_RESULT_BYTES_CAP))


class PostgresSecret(BaseModel):
    model_config = ConfigDict(extra="ignore")

    username: str = Field(min_length=1)
    password: SecretStr


@dataclass(frozen=True)
class QueryResult:
    columns: list[str]
    rows: list[list[Any]]
    truncated: bool


def parse_config(config: dict[str, Any]) -> PostgresConnectorConfig:
    try:
        return PostgresConnectorConfig.model_validate(config)
    except ValidationError as exc:
        raise ConnectorConfigError(
            f"invalid postgres config: {exc.error_count()} error(s)"
        ) from exc


def parse_secret(secret: str | None) -> PostgresSecret:
    if not secret:
        raise SecretFormatError("missing postgres credential payload")
    try:
        data = json.loads(secret)
        return PostgresSecret.model_validate(data)
    except (ValueError, ValidationError):
        # Never echo the payload or the underlying error detail.
        raise SecretFormatError("malformed postgres credential payload") from None
    finally:
        del secret  # avoid lingering references


def _normalize_cell(value: Any) -> Any:
    """Explicit Postgres -> JSON contract. Unsupported types are rejected."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime.datetime | datetime.date | datetime.time):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)  # lossless; avoids float precision loss
    if isinstance(value, dict):  # JSON/JSONB (already JSON-safe)
        return value
    if isinstance(value, list):  # arrays: normalize element-wise
        return [_normalize_cell(v) for v in value]
    if isinstance(value, bytes | memoryview):
        raise ResultUnsupportedTypeError("unsupported column type: bytea")
    raise ResultUnsupportedTypeError(f"unsupported column type: {type(value).__name__}")


def _classify_and_raise(exc: psycopg.Error) -> NoReturn:
    """Map a psycopg error to a safe typed error. No raw driver text escapes."""
    sqlstate = exc.sqlstate
    if sqlstate and sqlstate.startswith("28"):
        raise PostgresAuthError("postgres authentication failed") from None
    if sqlstate == "57014":
        raise PostgresTimeoutError("postgres query exceeded statement timeout") from None
    if sqlstate is None and isinstance(exc, psycopg.OperationalError):
        # Connect-time failure: psycopg leaves SQLSTATE unset. Inspect the message
        # internally to separate auth (deterministic) from unavailable (retryable).
        lowered = str(exc).lower()
        if any(marker in lowered for marker in _AUTH_MESSAGE_MARKERS):
            raise PostgresAuthError("postgres authentication failed") from None
        raise PostgresUnavailableError("external postgres database unavailable") from None
    if (
        isinstance(exc, psycopg.OperationalError)
        and sqlstate is not None
        and sqlstate.startswith("08")
    ):
        raise PostgresUnavailableError("external postgres database unavailable") from None
    raise PostgresQueryError("postgres query execution failed") from None


@contextmanager
def _read_only_connection(
    config: PostgresConnectorConfig, secret: PostgresSecret
) -> Iterator[psycopg.Connection[Any]]:
    idle_timeout = config.statement_timeout_ms + config.lock_timeout_ms
    options = (
        f"-c default_transaction_read_only=on "
        f"-c statement_timeout={config.statement_timeout_ms} "
        f"-c lock_timeout={config.lock_timeout_ms} "
        f"-c idle_in_transaction_session_timeout={idle_timeout}"
    )
    try:
        conn = psycopg.connect(
            host=config.host,
            port=config.port,
            dbname=config.database,
            user=secret.username,
            password=secret.password.get_secret_value(),
            sslmode=config.sslmode,
            connect_timeout=config.connect_timeout_s,
            options=options,
            autocommit=False,
        )
    except psycopg.Error as exc:
        _classify_and_raise(exc)
    try:
        yield conn
    finally:
        try:
            conn.rollback()
        finally:
            conn.close()


def run_read_only_query(
    config: PostgresConnectorConfig, secret: PostgresSecret, rendered_sql: str
) -> QueryResult:
    # Server-side cap independent of any LIMIT in the user's SQL.
    wrapped = f"SELECT * FROM ({rendered_sql}) AS _nlw_sub LIMIT {config.max_rows + 1}"
    try:
        with _read_only_connection(config, secret) as conn, conn.cursor() as cur:
            cur.execute(wrapped)
            fetched = cur.fetchmany(config.max_rows + 1)
            columns = [d.name for d in cur.description or []]
    except psycopg.Error as exc:
        _classify_and_raise(exc)

    truncated = len(fetched) > config.max_rows
    kept = fetched[: config.max_rows]
    rows = [[_normalize_cell(v) for v in row] for row in kept]

    serialized = json.dumps({"columns": columns, "rows": rows})
    if len(serialized.encode("utf-8")) > config.max_result_bytes:
        raise ResultTooLargeError("postgres result exceeded max_result_bytes")

    return QueryResult(columns=columns, rows=rows, truncated=truncated)


def health_check(ctx: ConnectorContext) -> None:
    config = parse_config(ctx.config)
    secret = parse_secret(ctx.secret)
    with _read_only_connection(config, secret) as conn, conn.cursor() as cur:
        try:
            cur.execute("SELECT 1")
            cur.fetchone()
        except psycopg.Error as exc:
            _classify_and_raise(exc)


POSTGRES_CONNECTOR = ConnectorType(
    name="postgres",
    config_model=PostgresConnectorConfig,
    secret_required=True,
    health_check=health_check,
)

register_connector_type(POSTGRES_CONNECTOR)
