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
| `worker` | Dramatiq consumer. Runs actors (M1b: a `ping` actor); loads durable run state and executes steps from M3. |
| `scheduler` | Heartbeat-only for now; reads due schedules and enqueues runs from M8. |

## Boundaries (ADRs)

- **Postgres is the system of record** — [ADR-001](../adr/ADR-001-postgres-state-store.md).
  Losing Redis loses no workflow state.
- **Redis/Dramatiq is transport only** — [ADR-002](../adr/ADR-002-redis-dramatiq-queue.md).
- The LLM proposes; deterministic code enforces every invariant
  (auth, tenancy, state, retries, idempotency, SQL safety, secrets, scheduling).

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
