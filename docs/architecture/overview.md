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
| `worker` | Loads durable run state, executes one step, checkpoints, repeats. (M1b introduces the queue; M3 the engine.) |
| `scheduler` | Reads due schedules and enqueues runs. (Heartbeat-only until M8.) |

## Boundaries (ADRs)

- **Postgres is the system of record** — [ADR-001](../adr/ADR-001-postgres-state-store.md).
  Losing Redis loses no workflow state.
- **Redis/Dramatiq is transport only** — ADR-002 (M1b).
- The LLM proposes; deterministic code enforces every invariant
  (auth, tenancy, state, retries, idempotency, SQL safety, secrets, scheduling).

## Built so far (M1a)

- `nlw.core.config` — env-driven `Settings` (pydantic-settings).
- `nlw.core.logging` — structlog (console local, JSON elsewhere).
- `nlw.db` — async engine/session + declarative `Base`.
- `nlw.api` — FastAPI app with `/health`, `/health/ready` (checks Postgres),
  `/version`.
- Alembic initialized with an empty baseline; migration applied in CI.
- Docker image + compose (`api`, `postgres`, `redis`); CI pipeline.
