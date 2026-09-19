# ADR-017 — Rate limiting & per-tenant resource limits

- Status: Accepted
- Date: 2026-09-19

## Context

The control plane had no rate limiting and several unbounded per-tenant growth
paths (connectors, schedules, materialized workflows). `POST /plans` in
particular incurs LLM cost. Staging needs abuse/cost protection that is
deterministic, shared across API replicas, and safe under failure.

## Decision

**Rate limiting.** A Redis-backed **fixed-window** limiter. Increment, first-use
expiry, and TTL read execute in ONE atomic Lua script — no INCR-then-EXPIRE
crash window. Both a **per-tenant** and a **per-user** counter are enforced on
cost/mutating endpoints: `POST /plans` (tightest), `materialize`, connector
create, schedule create/update, and approval decisions. Over-limit → `429` with
`Retry-After`. The backend **fails closed** (`503`) when Redis is unavailable
(configurable) — a Redis outage must not open an abuse window. Counters are
non-durable control state; losing them only resets the current window.

**Durable-resource caps.** Per-tenant caps on connectors, schedules, and
materialized workflows are enforced **concurrency-safely**: within the create
transaction we take a transaction-scoped Postgres **advisory lock** keyed by
(resource, tenant), then count under RLS and enforce the cap before inserting, so
a count-then-insert race cannot overshoot. Over-cap → `409 Conflict`. No schema
change (M9 stays migration-free for quotas).

**Resource-limit audit.** Existing hard caps (prompt chars, plan steps, SQL
rows/bytes, action payload/response bytes, action attempts, scheduler batch) are
retained; the external `postgres.query` hard timeout is tightened to 10s;
`advance_run` infra retries are bounded (`worker_max_retries`). A streamed
request-body cap is enforced on actual bytes (ADR-018). Audit-row retention
(plan_proposals) remains deferred.

## Alternatives considered

- **In-memory limiter.** Rejected: not shared across API replicas.
- **DB-backed rate table.** Rejected: needs a migration and adds write load;
  Redis fixed-window is simpler and counter loss is acceptable.
- **Count-then-insert without a lock.** Rejected: races overshoot the cap.
- **429 for caps.** Rejected: a durable cap is a state conflict, not a
  rate condition; `409` is used (retrying later won't free space).

## Consequences

- Deterministic, replica-shared protection with honest failure semantics.
- Caps hold under concurrency without schema changes.
- Fail-closed means a Redis outage degrades control-plane availability for
  cost/mutating endpoints — an intentional safety trade recorded for staging.
