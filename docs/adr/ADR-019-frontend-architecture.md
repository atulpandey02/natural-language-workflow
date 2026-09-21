# ADR-019 — Frontend architecture (Next.js App Router + BFF)

- Status: Accepted
- Date: 2026-09-19

## Context

M10 adds the minimum product UI so a real user can operate the platform
end-to-end without curl/SQL. The backend authenticates via Supabase-issued JWTs
(Bearer) and is tenant-scoped by an `X-Workspace-Id` header + RLS. We need an
auth/session model that keeps access tokens out of `localStorage` and out of the
browser's direct FastAPI calls, a data layer that does not scatter fetches, and a
deployment that keeps the API internal.

## Decision

**Stack.** Next.js 16 (App Router) + React 19 + TypeScript. TanStack Query for
server-state + bounded polling; react-hook-form + zod for forms. Minimal plain
CSS (no design system).

**BFF.** The browser talks ONLY to the Next app (same origin). Server-side Route
Handlers under `/api/nlw/*` resolve the Supabase session, inject
`Authorization: Bearer` + the signed `X-Workspace-Id`, and forward to FastAPI.
The browser never calls FastAPI directly and never handles the bearer token.
The proxy is a strict allowlist of (method, path) pairs — not a generic tunnel —
and builds a fresh header set so the browser cannot override Authorization,
X-Workspace-Id, Host, or forwarded headers; only safe response headers are
returned.

**Auth/session.** `@supabase/ssr` cookie-based sessions; the Next 16 `proxy.ts`
boundary refreshes the session and enforces route protection (unauthenticated →
`/login`; authenticated without a workspace → `/select-workspace`).

**Session-cookie security posture (accurate).** Access tokens are NOT in
`localStorage`, and the browser never calls FastAPI directly — the BFF injects the
bearer server-side. However, `@supabase/ssr` (0.7.x) keeps the Supabase auth
cookies **readable by browser JavaScript** (not `HttpOnly`) because the browser
client reads the session; so these cookies are within XSS reach the same as any
JS-accessible cookie. The pilot controls are: nonce-based CSP + same-origin CSRF
on mutating routes + `SameSite=Lax` + **`Secure` in production** (set explicitly;
disabled only on the plain-HTTP e2e harness via `COOKIE_SECURE=false`). A move to
an `HttpOnly`/opaque server-owned application session (login/refresh/logout moved
fully server-side) is a **future customer-production hardening item**, not a P0
change.

**CSRF.** Cookie-authenticated mutating routes (POST/PATCH/DELETE) require a
same-origin Origin/Host match; auth cookies are `SameSite=Lax` + `Secure` in prod
(see the session-cookie posture above).

**Caching.** All authenticated reads are dynamic/no-store; no ISR/shared caching
of tenant-specific responses. Switching workspace clears the TanStack cache so no
stale previous-tenant data is shown.

**Workspace selection.** The selected workspace id is kept in a server-signed
(HMAC) httpOnly cookie; backend membership/RLS remains authoritative.

**Manual runs.** "Run now" posts to `POST /workflows/{id}/runs` with a
client-generated Idempotency-Key reused across a double-click/retry, so exactly
one durable run is created; the backend commits the run before enqueueing and a
failed enqueue leaves the run recoverable by reconciliation.

**Topology.** Caddy is the only public ingress and proxies to the internal `web`
container; the API, worker, scheduler, Postgres, Redis and all metrics ports stay
internal. Because the browser never calls the API, no public browser CORS is
needed. The `web` image runs non-root with a strict CSP.

**Backend support endpoints (read-only, no new grants/migration).**
`GET /workflows`, `GET /workflows/{id}`, `GET /workflow-versions/{id}`,
`GET /runs`, `GET /runs/{id}`, `GET /runs/{id}/steps`, `GET /runs/{id}/actions` —
all tenant/RLS-scoped and hard-paginated. Step output is a size-capped preview
only. Plus the idempotent `POST /workflows/{id}/runs`.

## Alternatives considered

- **Vite SPA calling FastAPI directly.** Smaller, but puts the token in browser
  JS and needs backend CORS. Rejected for the weaker token posture.
- **Redux / heavy state libs.** Unnecessary; TanStack Query + minimal context
  suffices.
- **WebSockets for live updates.** Deferred; bounded polling is enough for MVP.

## Consequences

- Tokens never touch browser storage; the API is never publicly reachable.
- One coherent, testable data layer; role-aware UI with the backend authoritative.
- Deferred: visual workflow builder, WebSockets, team invites, billing, advanced
  analytics — none are in M10.
