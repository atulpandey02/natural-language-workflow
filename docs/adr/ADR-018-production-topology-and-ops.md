# ADR-018 — Production topology & operational readiness

- Status: Accepted
- Date: 2026-09-19

## Context

M9 makes the existing backend safe to run in staging on a small VPS with Docker
Compose (no Kubernetes). This ADR records the deployment topology, container and
HTTP hardening, database operational settings, backups, image delivery, secret
storage, and the readiness contract.

## Decision

**Topology (single VPS, Compose).** `docker-compose.prod.yml` runs api / worker /
scheduler / postgres / redis plus a **Caddy** reverse proxy. Caddy is the ONLY
publicly published service (HTTPS); everything else — including every metrics
port — is internal to the Docker network. The reverse proxy has a fixed address
and is the only trusted source of `X-Forwarded-*`.

**Container hardening.** One image runs as a **non-root** user
(`PYTHONDONTWRITEBYTECODE=1`). Stateless app services run `read_only` with a
`/tmp` tmpfs, `cap_drop: ALL`, `no-new-privileges`, a restart policy, and
CPU/memory/pids limits honored by plain `docker compose` (not only Swarm).
Postgres/Redis keep their writable volumes and are not made read-only.

**Database ops.** Engines use a bounded pool (`pool_size`/`max_overflow`/
`pool_timeout`/`pool_recycle`, `pool_pre_ping`) and per-connection server
timeouts: `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout`.

**HTTP hardening.** Safe machine-readable errors (no stack/DB/provider/secret
text), a request-body cap enforced on actual streamed bytes, CORS (deny by
default), TrustedHost, security headers, HSTS in production, and OpenAPI/docs
disabled in production by default.

**Readiness.** `GET /health/ready` checks Postgres, Redis, and **schema
compatibility** (DB `alembic_version` == the in-process cached expected head).
It excludes tenant external connectors and the LLM provider. Worker/scheduler
container healthchecks check Postgres + Redis + their own metrics port.

**Backups.** Nightly logical `pg_dump` (custom format), encrypted, shipped
off-host. Staging target **RPO ≤ 24h, RTO ≤ 1h**. At least one restore drill into
a fresh database before staging go-live. Redis is transport only and needs no
backup (recovery via the reconciler). Roles/bootstrap are restored from
version-controlled bootstrap/IaC, never from backed-up role passwords. PITR /
5-minute RPO is **not** claimed and remains pre-production work.

**Image delivery.** Merge to main builds ONE image, pushes it to GHCR, and
captures the digest; that exact digest is deployed to staging, smoke-tested, and
promoted UNCHANGED to production after a manual GitHub Environment approval.
Rollback = redeploy a previous schema-compatible digest. Image rollback NEVER
auto-downgrades DB migrations. Trivy scans the image; third-party actions should
be SHA-pinned before go-live.

**Secret storage.** `EnvironmentSecretStore` (worker-only, tenant-scoped env) is
accepted for staging. A cloud secret manager / envelope-encryption backend behind
the existing `SecretStore` abstraction is pre-production work. Rotation is
documented in the runbook (rotate the env value; connectors reference a stable
`secret_ref`).

## Alternatives considered

- **Kubernetes.** Rejected for staging: unnecessary operational surface on a VPS.
- **Publishing app/metrics ports directly.** Rejected: only the proxy is public.
- **Mutable `:latest` deploys.** Rejected: staging and prod run the same digest.

## Consequences

- A hardened, observable, recoverable single-VPS deployment suitable for staging.
- Same-digest promotion makes prod reproduce exactly what staging validated.

## Remaining pre-production risks (accepted for staging)

- Forgeable GUC DB context (ADR-003 update) — non-forgeable context before public prod.
- Env-only secret storage — cloud secret manager before public prod.
- No distributed tracing / Langfuse yet (ADR-016).
- `postgres.query` still runs in the run lock (bounded to 10s); out-of-lock reads
  are a fast-follow if longer queries are needed.
- No auto-FAIL-on-deadline for poisoned runs — the reconciler stops re-driving
  past the horizon and surfaces a gauge/warning for operator action.
- Audit-row retention unbounded; single-VPS (no HA/autoscaling); rate-limit
  counters non-durable (fail-closed).
