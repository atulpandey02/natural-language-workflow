# Architecture overview

_Living document. Reflects what is built; grows each milestone._

## Shape

```
Internet → HTTPS/reverse proxy → api (FastAPI control plane)
                                   │
                        ┌──────────┴───────────┐
                        ▼                       ▼
                   PostgreSQL              Redis (transport)
                 (system of record)            │
                                               ▼
                                  worker (durable executor)   [M1b+]
                                  scheduler (due → enqueue)    [M1b+]
```

## Roles (one image, selected by command)

| Role | Responsibility |
|------|----------------|
| `api` | Authn/authz, input validation, writes intent to Postgres, enqueues work. Never executes workflow steps. |
| `worker` | Dramatiq consumer. `advance_run(run_id)` loads durable state from Postgres and executes one step per advancement (M3). Connects as the execution-only `nlw_worker` role. |
| `scheduler` | Heartbeat-only for now; reads due schedules and enqueues runs from M8. |

## Boundaries (ADRs)

- **Postgres is the system of record** — [ADR-001](../adr/ADR-001-postgres-state-store.md).
  Losing Redis loses no workflow state.
- **Redis/Dramatiq is transport only** — [ADR-002](../adr/ADR-002-redis-dramatiq-queue.md).
- **Durable execution** — [ADR-010](../adr/ADR-010-durable-execution.md): one step per
  `advance_run`, `FOR UPDATE` serialization, commit-before-enqueue, idempotent replay;
  worker derives tenant via a worker-only SECURITY DEFINER resolver.
- The LLM proposes; deterministic code enforces every invariant
  (auth, tenancy, state, retries, idempotency, SQL safety, secrets, scheduling).

## Identity & tenancy (M2a)

- `nlw.auth` — `AuthProvider.verify_token → AuthedIdentity`; `SupabaseAuthProvider`
  verifies **JWKS (RS256/ES256)** as the production target, with legacy HS256 for
  dev; checks signature, `exp`, `aud`, `iss`. See [ADR-007](../adr/ADR-007-auth-provider.md).
- `nlw.db.models` — `users`, `workspaces`, `memberships` (Alembic `0002`).
- `nlw.tenancy` — `Role` + `TenantContext(user_id, tenant_id, role)`.
- `nlw.api` — `/me`, `/workspaces` (GET/POST), `/workspaces/current`. Tenant is
  selected by `X-Workspace-Id` but **membership is authoritative**; role gates
  actions. First-sight user provisioning is idempotent/race-safe.
- Isolation is enforced by the **database** (M2b): the app connects as a
  restricted `nlw_app` role (no `BYPASSRLS`); RLS policies on `workspaces` and
  `memberships` are keyed on two transaction-local GUCs (`app.user_id` set at
  auth, `app.tenant_id` set only after membership is confirmed). Migrations run
  as the `nlw` owner. See [ADR-003](../adr/ADR-003-multi-tenant-isolation.md).

## Built so far (through M1b)

- `nlw.core.config` — env-driven `Settings` (pydantic-settings).
- `nlw.core.logging` — structlog (console local, JSON elsewhere).
- `nlw.db` — async engine/session + declarative `Base`.
- `nlw.api` — FastAPI app with `/health`, `/health/ready` (checks Postgres +
  Redis), `/version`.
- `nlw.worker` — Dramatiq Redis broker, Redis readiness probe, and a `ping`
  actor proving enqueue → Redis → worker execution.
- `nlw.scheduler` — heartbeat loop (real scheduling in M8).
- Alembic initialized with an empty baseline; migration applied in CI.
- Docker image + compose with all five services (`api`, `worker`, `scheduler`,
  `postgres`, `redis`); CI pipeline.

### Proving the roundtrip locally

```bash
docker compose up -d --build
docker compose exec api python -c "from nlw.worker.actors import ping; ping.send('demo')"
docker compose logs worker   # -> worker.ping token=demo
```
