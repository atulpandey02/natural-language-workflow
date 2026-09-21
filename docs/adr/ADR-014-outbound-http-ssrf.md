# ADR-014 — Outbound HTTP / SSRF safety

- Status: Accepted
- Date: 2026-09-19

## Context

The `webhook.send` action makes outbound HTTP to a tenant/operator-configured
destination. Without strict controls this is a Server-Side Request Forgery (SSRF)
vector into internal networks and cloud metadata endpoints. The model must never
choose destinations, and the guard must resist DNS rebinding.

## Decision

- **Destination is connector-owned.** The URL lives only in `webhook` connector
  config (validated at create time); step args carry the JSON `payload` only. The
  model cannot supply or influence the URL.
- **HTTPS only.** Non-`https` schemes are rejected. URL **userinfo** and
  **fragments** are rejected.
- **IP policy (connect time).** The host is resolved once and **every** resolved
  address must be global unicast. Blocked: loopback, RFC1918, CGNAT `100.64/10`,
  link-local `169.254/16` (incl. the cloud metadata IP `169.254.169.254`), IPv6
  loopback/link-local/ULA, multicast, reserved/unspecified, and
  **IPv4-mapped-private IPv6** (`::ffff:10.x`, …). Any private result fails closed.
- **DNS-rebinding-safe pinning.** A custom `GuardedTransport` resolves + validates,
  then pins the connection to the validated IP while keeping TLS SNI and the
  `Host` header set to the original hostname (valid certificate). There is no
  re-resolution between validation and connect.
- **Redirects disabled.** Any 3xx is a deterministic failure (removes
  redirect-based SSRF entirely).
- **Bounds.** Hard-capped connect+read timeout, streamed max-response-bytes, and
  request-body size cap.
- **Headers.** Outbound headers are code-controlled (`Content-Type`,
  `Idempotency-Key`, `User-Agent`). No arbitrary operator headers. A single
  credential header may be configured **by name/scheme only**; its **value comes
  from the SecretStore** and never appears in config, logs, or audit.
- **Health check.** `webhook` health validates config + URL + DNS/public-IP policy
  + secret availability; it performs **no** side-effecting HTTP. Slack may use the
  read-only `auth.test`. Runtime delivery is the liveness proof.
- **No production bypass.** The guard's resolver/inner transport are injectable
  **for tests only** (dependency injection). There is no config/env switch that
  weakens SSRF protection in production; the strict guard is always constructed.

## Alternatives considered

- **Validate the URL pre-flight only** — rejected: a TOCTOU DNS rebinding window
  remains; connect-time pinning closes it.
- **Allow arbitrary operator headers** — rejected: enables smuggling of
  credential/host headers; code-controlled headers + a name-only credential slot
  are safer.
- **Follow redirects** — rejected: a redirect can point back at an internal IP.

## P1C amendment (M11.5 hardening, 2026-09-21)

The webhook and Slack connectors share one HTTP path (`nlw.connectors.http_action`)
that adds, on top of the SSRF guard above:

- **One total wall-clock budget (monotonic), not a per-op inactivity timer and
  not a fresh timeout per phase.** One budget (`TOTAL_ACTION_DEADLINE_S = 30s`)
  covers resolution → pool acquire → connect → TLS → write → response-head →
  streamed response consumption. Each httpx phase timeout is set to the budget
  **remaining** when the request starts (so no single phase blocks past the total,
  and **pool wait is inside the same budget** — a fresh single-use pool per call
  makes it trivial anyway), and the monotonic deadline is re-checked at every seam
  we control (after DNS, immediately after the response head, before every streamed
  chunk). A trickle response that stays under every inactivity timer is therefore
  still stopped at the total deadline, streaming can neither restart nor extend the
  budget, and no connection begins after the caller has already timed out — so a
  send can never outlive the action lease (`TOTAL + FINALIZE_MARGIN_S <
  LEASE_DURATION_S`, enforced at startup; see ADR-013). Residual: several
  sequential pre-response phases each blocking near the full remaining budget can
  reach ~2× the budget before the post-header check aborts (documented, bounded).
  The operation is fully synchronous — no background thread continues after the
  caller returns, and every resource is closed on exit.
- **Webhook: no body consumption; Slack: bounded body.** A webhook decides
  SUCCESS/UNKNOWN from the **status line alone**, so after the response head it
  **closes the stream without reading the body** — a slow/trickling/huge webhook
  body can neither delay the result nor be buffered. Slack must read the body to
  determine `ok`, so it streams under a hard `max_response_bytes` cap.
- **`Accept-Encoding: identity` + raw streaming cap (Slack).** The request
  advertises identity encoding and the consumed body is read as **raw wire bytes**
  (`iter_raw`) under the cap, enforced **while** reading. The body is never
  decompressed, so a compression bomb cannot expand in memory; at most one bounded
  chunk beyond the cap is ever held, and a breach closes the connection. No
  response body, header, or secret is persisted.
- **Conservative phase-aware classification (SSRF-preserving).** An `SsrfError`
  from the guard is a deterministic `ToolExecutionError` (policy rejection, no
  effect). A transient **DNS resolution failure** and a failure **provably before
  transmission** (`ConnectError`/`ConnectTimeout`/`PoolTimeout`) are retryable
  (nothing left the host). A failure once transmission may have started
  (`WriteError`/`WriteTimeout`/`ReadError`/`ReadTimeout`/`RemoteProtocolError`/
  total-deadline-at-or-after-head) is **ambiguous** → terminal UNKNOWN (ADR-013),
  never a silent retry. The connector layer maps HTTP status likewise (ADR-013
  matrix): 429 retryable, generic 5xx UNKNOWN.

## Consequences

- A tenant can deliver to a public webhook safely; internal/metadata destinations
  are unreachable, and rebinding is defeated. Slack's fixed public API host passes
  the same guard. A slow, oversized, or compressed response can neither exhaust
  memory nor outlive the lease. Broader outbound capability (arbitrary REST,
  per-tenant egress proxy) is deferred.
