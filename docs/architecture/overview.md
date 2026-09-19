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
- **Capability layer** — [ADR-006](../adr/ADR-006-connector-tool-separation.md) +
  [ADR-011](../adr/ADR-011-secret-store.md): static Tool Registry (only registered tools
  run), tenant-owned connectors (RLS), and a SecretStore (refs in DB; values resolved
  worker-side only, never in the LLM path). Steps dispatch through the registry; a
  connector-backed step loads the tenant's connector, health-checks it, and resolves its
  secret before executing.
- **PostgreSQL connector (read-only)** — [ADR-012](../adr/ADR-012-postgres-connector.md) +
  [ADR-009](../adr/ADR-009-sql-safety.md): the `postgres.query` tool reaches a tenant's
  external database with read-only guaranteed by three independent controls
  (deterministic sqlglot validation against a schema/table allowlist, a
  `default_transaction_read_only` session with statement/lock/idle timeouts, and a
  SELECT-only external role). Results are row- and byte-capped; the JSON credential is a
  repr-safe `SecretStr`; all driver errors are sanitized so credentials/raw text never
  leak. The LLM does not generate SQL.
- **Planner + feasibility** — [ADR-004](../adr/ADR-004-planner-feasibility-separation.md) +
  [ADR-005](../adr/ADR-005-llm-provider-byok.md): an async `LLMProvider` (BYOK; Anthropic
  reference, keyless stub for CI) turns a prompt into a strict `PlannerOutput`; the pure
  `nlw.feasibility.engine` assigns `PASS`/`REJECT`/`NEEDS_CLARIFICATION`/`NEEDS_APPROVAL`
  from tool availability, connector ownership/type/status, argument models, the M5 SQL
  validator, the DAG (Kahn), and platform limits. Planning runs API-side and persists an
  immutable `plan_proposals` audit row (no raw prompt: only `prompt_len`; no raw provider
  response). `POST /plans/{id}/materialize` re-earns PASS against the current capability
  view (`FOR UPDATE`, idempotent) before creating a `workflow_version`. The platform LLM
  key lives in the API process only (never worker/scheduler, never in model context).
- **Action connectors + approvals** — [ADR-013](../adr/ADR-013-action-side-effect-safety.md) +
  [ADR-014](../adr/ADR-014-outbound-http-ssrf.md): `webhook.send` / `slack.send_message` are
  approval-gated side-effecting tools. An approval-gated action parks the run at
  `WAITING_APPROVAL`; admin/owner decide via `POST /approvals/{id}/approve|reject` (role +
  RLS admin/owner + `decided_by = app.user_id`), CAS and recovery-safe. Side effects run
  **outside** the run lock via a two-transaction pattern (claim + stable idempotency key +
  atomic lease → COMMIT → external call → lease-guarded finalize), with bounded retry and a
  secret-free `external_actions` audit. Outbound HTTP is HTTPS-only, redirect-disabled, and
  SSRF-guarded with connect-time IP validation + DNS-rebinding-safe pinning; the destination
  comes only from the connector. Delivery is **at-least-once** (no exactly-once claim).
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
