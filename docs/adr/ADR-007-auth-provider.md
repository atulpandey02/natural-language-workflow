# ADR-007 — Authentication provider (Supabase, identity only)

- Status: Accepted
- Date: 2026-09-18

## Context

We need to authenticate users without building auth ourselves, and the design
should follow the identity provider's recommended direction. Authentication must
establish **identity only** — tenant membership and roles are our own domain and
must never be read from a token claim.

## Decision

Use **Supabase Auth** for identity, behind an `AuthProvider` abstraction:

```
verify_token(raw) -> AuthedIdentity(sub, email)
```

- **Production target: asymmetric verification via JWKS (RS256/ES256).**
  `SupabaseAuthProvider` resolves the signing key by `kid` from the project's
  JWKS endpoint (PyJWT `PyJWKClient`), fetching lazily and caching on first use
  (no prewarming). Every token is checked for **signature, `exp`, `aud`, and
  `iss`**; the issuer is derived from the Supabase project URL
  (`{SUPABASE_URL}/auth/v1`).
- **Legacy/dev only: symmetric HS256** with a shared secret, scoped explicitly
  to local development and backward compatibility with older Supabase projects.
  It is not the production design; Supabase's recommended legacy-token path may
  instead validate against the Auth server. HS256 tokens are rejected unless a
  secret is explicitly configured.
- **V1 supports email-authenticated users only:** a missing `email` claim is
  rejected (`users.email` is `NOT NULL`).
- Tenant + role come from our `memberships` table. `X-Workspace-Id` is a
  non-authoritative *selector*; membership is authoritative.

## Alternatives considered

- **HS256 shared secret as the target** — rejected: symmetric secret
  distribution and not the provider's recommended direction.
- **Clerk / Auth0** — better hosted DX but weaker self-hosting story and more
  lock-in; Supabase Auth is open-source and self-hostable.
- **Hand-rolled auth** — explicitly out of scope; auth is not something we build.

## Consequences

- Robust key rotation via JWKS; the provider is swappable (self-hosted GoTrue,
  another IdP) without touching call sites.
- Verification is synchronous (cached JWKS + CPU) and is run in a threadpool from
  the async request path so a cold JWKS fetch never blocks the event loop.
- Dev may use HS256 transitionally; production uses JWKS.
- Authorization and tenant isolation are deliberately **not** the auth provider's
  job — they live in our DB (see ADR-003 for isolation, added in M2b).
