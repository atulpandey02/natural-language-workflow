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

## Update (M11.5 P1B) — destination egress + TLS enforcement + address pinning

The connector now validates the destination and TLS posture BEFORE any
network/authentication bytes are sent (new `nlw.connectors.pg_destination`,
reusing the ADR-014 IP classifier). Governing rule: *validate first, pin the
validated address, then transmit credentials.*

**Destination policy (production/staging).** Every A/AAAA answer is resolved with
a bounded timeout and classified; the destination is rejected if ANY answer is
non-global and not in the operator CIDR allowlist (never "pick the one safe
answer" — mixed-answer / DNS-rebinding safe). Blocked classes: IPv4/IPv6 loopback,
RFC1918, IPv6 ULA, link-local incl. cloud metadata (169.254.0.0/16), CGNAT,
multicast, reserved, unspecified, IPv4-mapped-private IPv6, and platform-internal
service names (`postgres`, `redis`, `api`, `worker`, `scheduler`, `web`, `caddy`,
`prometheus`, `localhost`, `host.docker.internal`). Unix-socket and DSN/multi-host
`host` forms are rejected. Port policy: 5432 by default; non-default ports only via
an explicit operator allowlist. **No connector field, API request, planner output
or tenant setting can weaken this.**

**TLS.** Production/staging require `sslmode=verify-full`; `disable`/`allow`/
`prefer`/`require`/`verify-ca` are rejected — tenant config cannot weaken TLS. The
original hostname is preserved for certificate/SNI verification; the validated IP
is passed to libpq as `hostaddr` (the TCP target), so libpq performs no second,
unvalidated DNS resolution and there is no plaintext downgrade.

**Private-destination exception (env gate).** Non-production (`app_env` local/dev)
may target private fixtures and honour the connector `sslmode` — this seam is
dependency-injected / `app_env`-gated and **fails closed in production**. Staging
with a legitimately private approved DB uses the operator-owned CIDR allowlist
(`postgres_destination_allowlist`).

**Errors + retry.** Policy rejections are deterministic, stable codes
(`POSTGRES_DESTINATION_NOT_ALLOWED`, `POSTGRES_TLS_POLICY_VIOLATION`,
`POSTGRES_PORT_NOT_ALLOWED`) raised before any connection — they are
`ToolExecutionError`s (deterministic step failures), never treated as retryable
infrastructure outages, and never expose resolved internal addresses, DSNs,
credentials, or open/closed-port state.

**Limitations (pilot).** Public/global destinations by default; private requires
explicit operator approval; DNS + network controls reduce credential-exfiltration
risk but do not make an external database a trusted system; credentials remain
operator-managed. No tenant-supplied CA material in this package.

### Update (M11.5 P1B addendum) — exact libpq trust config + DNS bound

**TLS trust (verify-full).** The connector passes `sslmode=verify-full` plus
`sslrootcert`, resolved as: an operator-configured bundle path
(`postgres_ssl_root_cert`) if set, else libpq **`system`** (the OS trust store).
`sslrootcert=system` requires libpq ≥ 16; the worker bundles psycopg-binary's
libpq **18.6**, which supports it. The worker image installs `ca-certificates`,
so the OS bundle exists at `/etc/ssl/certs/ca-certificates.crt` — this is how a
managed PostgreSQL provider's publicly-rooted certificate is trusted. `host` is
the original hostname (SNI + certificate verification); `hostaddr` is the pinned
validated IP (TCP target). `sslrootcert` is **never tenant-supplied** and no
tenant-supplied arbitrary CA file is accepted. A production-equivalent integration
test (a TLS Postgres with a test CA + SAN-matched cert) proves verify-full
succeeds with the correct host + trusted CA + pinned hostaddr and fails closed on
an untrusted CA or a hostname/SAN mismatch — with no plaintext fallback.

**DNS wall-clock bound.** Resolution runs on a **daemon** thread joined for at
most `dns_timeout_s` (default 5s). On timeout the destination is rejected
(`POSTGRES_DESTINATION_NOT_ALLOWED`) and the daemon thread is **abandoned**: the
underlying `getaddrinfo` keeps running in the background but, being a daemon,
never blocks worker/process shutdown, and **no connection is attempted after the
timeout**. A `ThreadPoolExecutor` is deliberately not used (its context-manager
exit joins the still-blocked worker, which would defeat the bound). Repeated
timeouts spawn only daemon threads and leak no non-daemon/background threads.
