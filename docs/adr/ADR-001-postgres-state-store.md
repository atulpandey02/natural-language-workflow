# ADR-001 — PostgreSQL as the system of record

- Status: Accepted
- Date: 2026-09-17

## Context

The platform must survive process/container crashes and resume workflows
exactly where they stopped, keep every tenant's data isolated, and provide an
auditable history of runs, approvals, and actions. We need one authoritative,
transactional store for all durable state. We also want application containers
(`api`, `worker`, `scheduler`) to be stateless so they can be restarted or
scaled without data loss.

## Decision

Use **PostgreSQL** as the single system of record for all durable state:
tenants and memberships, connectors and secret references, workflows and
immutable versions, schedules, runs and step runs, approvals, and audit events.

- Access is via **SQLAlchemy 2.0** with the **psycopg (v3)** driver — an async
  engine for the application and a sync engine for Alembic, over one URL.
- All schema changes are **Alembic** migrations; the schema is never edited by
  hand. `alembic upgrade head` on a clean database is verified in CI.
- Application containers hold no durable state; only PostgreSQL (and its volume)
  and Redis are stateful, and Redis is transport only (see ADR-002).

## Alternatives considered

- **SQLite** — simplest, but no real concurrency for workers/scheduler and a
  weak multi-tenant/RLS story; unsuitable for a multi-process deployment.
- **A document store (e.g. MongoDB)** — weaker transactional guarantees for the
  state-machine transitions and idempotency this system depends on.
- **Splitting state across multiple stores now** — premature; one Postgres is
  sufficient at target scale and keeps invariants in one transactional place.

## Consequences

- Crash-safe, resumable execution: a worker can restart and rebuild run state
  from Postgres. Row-Level Security (M2) gives defense-in-depth tenant isolation
  on top of tenant-scoped repositories.
- Postgres is a hard dependency: if it is down, the platform correctly halts
  rather than executing without durable state (see the failure model).
- Migrations become part of the release pipeline (a gated step), not an
  afterthought.
