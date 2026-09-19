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

## Consequences

- A tenant can deliver to a public webhook safely; internal/metadata destinations
  are unreachable, and rebinding is defeated. Slack's fixed public API host passes
  the same guard. Broader outbound capability (arbitrary REST, per-tenant egress
  proxy) is deferred.
