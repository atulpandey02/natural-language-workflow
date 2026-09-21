# ADR-011 — SecretStore abstraction & secret references

- Status: Accepted
- Date: 2026-09-19

## Context

Connectors need credentials, but secrets must never be stored as plaintext
business data, never reach the LLM, and never leak into logs/outputs/API
responses. The store must be swappable (dev env vars now; encrypted/Vault later).

## Decision

- **Only a `secret_ref` is persisted** on the connector row — a canonical name
  matching `^[A-Z][A-Z0-9_]{0,63}$`. Never a secret value.
- **Secret references are tenant-scoped namespaces.** A `secret_ref` names a
  secret *within one tenant's namespace*; **identical aliases across tenants
  never identify the same credential.** `SecretStore.resolve(tenant_id,
  secret_ref) -> str` resolves refs **only in the worker, at execution time**,
  using the **authoritative tenant from the M3 execution context** (never a
  tenant id from workflow args, connector config, or any user-provided message).
  `EnvironmentSecretStore` maps `(tenant, ref) → env
  NLW_SECRET_<TENANT_UUID_HEX>_<SECRET_REF>` for dev/self-hosted. RLS namespaces
  the connector row; this namespaces the external secret backend too.
- **Worker-only secret environment**: `NLW_SECRET_*` are injected into the
  `worker` service only (via a git-ignored `env_file`) — never into `api`,
  `scheduler`, or the shared Compose env. The API cannot resolve secrets and
  never calls `resolve`.
- **Non-leak guarantees**: the resolved value is passed only to a tool's
  `execute` via `ConnectorContext` (whose `secret` field is repr-suppressed),
  and is never persisted, logged, returned, or placed in error strings. A
  connector `type` may require a secret; the `static` type does, so creating a
  `static` connector without a `secret_ref` is rejected. Errors carry only the
  ref (which is not a secret).

## Alternatives considered

- **Secrets in the DB (plaintext)** — rejected outright.
- **Encrypted-DB / Vault backend now** — deferred; the abstraction lets us add
  it without touching call sites.
- **A `secrets` metadata table** — deferred; `secret_ref` on the connector is
  sufficient for M4.

## Consequences

- Secrets are out of the business dataset and the LLM path by construction.
- The dev store depends on process environment; the worker-only split keeps
  secrets off the API/scheduler surface.
- Encrypted-at-rest storage, rotation, and per-secret metadata are future work
  (pre-production hardening).

## Update (M11.5 P1A) — an alias is an identifier, not authority

P1A hardens the boundary around `secret_ref` without redesigning the
environment-backed, tenant-scoped store:

- **Only admin/owner may attach or supply a `secret_ref`** (connector creation is
  admin/owner-only in both the API and RLS — see ADR-006). Ordinary members can
  neither submit nor mutate `secret_ref`.
- **Knowledge of an alias never confers authority.** Tenant scoping is unchanged:
  the env key embeds the tenant hex (`NLW_SECRET_<TENANT_HEX>_<REF>`), so Tenant A
  and Tenant B may use the same alias string without resolving each other's
  credential.
- **`secret_ref` stays out of every member-facing surface.** Public connector
  responses expose only `has_secret` (never `secret_ref` or a value); it is also
  absent from planner capability context, workflow plans/versions, step
  input/output/error, approval previews, logs, and API errors. The internal
  worker resolution path (`nlw_worker` `SELECT` on `connectors.secret_ref` →
  `SecretStore.resolve`) is preserved.

Deferred (unchanged): cloud/envelope-encrypted storage, rotation, per-secret
metadata, self-service secret onboarding, and connector→credential-entity binding.
