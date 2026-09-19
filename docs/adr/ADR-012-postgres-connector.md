# ADR-012 — PostgreSQL connector (read-only query tool)

- Status: Accepted
- Date: 2026-09-19

## Context

M5 introduces the first real external connector on the ADR-006 capability layer:
a PostgreSQL integration exposing a single read-only `postgres.query` tool. It
must prove that database access is strictly read-only (ADR-009), that the
external credential never leaks, and that failures are classified so the durable
engine (ADR-010) retries infrastructure faults but records deterministic business
failures.

## Decision

- **Connector type `postgres`** (`nlw.connectors.postgres`) with a strict config
  (`extra="forbid"`): `host`, `port`, `database`, `sslmode`, `allowed_schemas`,
  optional `allowed_tables`, and the bounds `statement_timeout_ms`,
  `lock_timeout_ms`, `connect_timeout_s`, `max_rows`, `max_result_bytes`. Every
  bound is clamped to a **hard platform cap** by a validator, so tenant config can
  tighten but never exceed the platform limit. `secret_required=True`.
- **Credential** is a JSON secret `{"username", "password"}` resolved from the
  `SecretStore` (ADR-011), tenant-scoped, worker-side only. `password` is a
  Pydantic `SecretStr`; a malformed payload raises a typed error that **never
  echoes the payload**.
- **Tool `postgres.query`** (category `data`, `read_only=True`) takes `sql` only
  (no bind params in M5). It (1) validates + re-renders via ADR-009 against the
  connector's allowlist, then (2) runs the canonical SQL through the read-only
  driver path.
- **Read-only driver path.** A fresh connection per execution with
  `default_transaction_read_only=on`, `statement_timeout`, `lock_timeout`, and
  `idle_in_transaction_session_timeout`; the transaction is always rolled back.
  Results are row-capped by wrapping the query as
  `SELECT * FROM (<sql>) LIMIT max_rows+1` (a **server-side** cap independent of any
  user `LIMIT`), truncated to `max_rows` with a `truncated` flag, then
  byte-capped (`max_result_bytes`) on the serialized result. Values are converted
  to JSON by an **explicit per-type contract** (UUID/date/decimal→string, jsonb
  passthrough, arrays recurse); `bytea`/unknown types are rejected rather than
  coerced with a blanket `default=str`.
- **Health check.** `unchecked`/`error` connectors are probed (connect + `SELECT
  1`) before use and flip to `active`; `active` connectors skip the probe. An
  auth failure on an active connector flips it to `error` via the
  `ConnectorUnhealthyError` marker.
- **Error classification & sanitization.** All psycopg errors are mapped to typed
  errors carrying only safe, generic messages — raw driver strings, connection
  strings, and credentials never reach logs, `step_runs.error`, or output.
  Deterministic (→ step FAILED): `SqlSafetyError`, `PostgresAuthError`,
  `PostgresTimeoutError`, `PostgresQueryError`, `ResultTooLargeError`,
  `ResultUnsupportedTypeError`, bad config/secret. Retryable (→ propagate →
  Dramatiq retry): `PostgresUnavailableError` and other infrastructure faults.
  Connect-time auth failures (which psycopg reports without a SQLSTATE) are
  separated from unavailability by inspecting the message **internally**.
- **Transaction placement (M5 only).** The external query runs inside the M3
  locked advancement transaction. This is an explicit, bounded exception (hence
  the aggressive timeouts); it is **not** a general pattern for long/network tools
  and is revisited before any such tool ships.

## Alternatives considered

- **Connection pooling / a long-lived pool** — deferred: a fresh, bounded,
  read-only connection per execution is simpler and safer for M5.
- **Blanket `json.dumps(default=str)`** — rejected: silently stringifies unknown
  types (e.g. `bytea`); we require an explicit, auditable type contract.
- **Trusting the user `LIMIT`** — rejected: a huge/absent `LIMIT` must still
  return at most `max_rows`; the cap is applied server-side by the wrapper.
- **Storing the credential on the connector row** — rejected (ADR-011): only a
  `secret_ref` is stored.
- **Running the query outside the advancement transaction** — deferred to a
  future ADR alongside hard per-tool timeouts and network-tool patterns.

## Consequences

- A tenant can safely read its own database in a workflow, with read-only
  guaranteed by three independent controls and results bounded in rows and bytes.
- Credentials are structurally prevented from leaking across logs, DB, and errors.
- `schema.inspect`, bind parameters, additional dialects, pooling, and moving
  network I/O out of the advancement transaction are follow-ups that reuse this
  connector/validator/driver seam.
