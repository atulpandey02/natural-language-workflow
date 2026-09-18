# ADR-002 — Redis + Dramatiq as the execution queue (transport only)

- Status: Accepted
- Date: 2026-09-17

## Context

The FastAPI control plane must not run long tasks in request handlers; work is
handed to background workers. We need a queue that gives us worker separation,
retries, and simple operations at small scale (~5 concurrent users, one VPS),
without introducing heavy infrastructure. Critically, the queue must **not**
become a second store of workflow state — PostgreSQL is the system of record
(ADR-001).

## Decision

Use **Dramatiq** with a **Redis** broker as the execution queue.

- Redis is **transport only**. Messages are lightweight instructions. The real
  message in later milestones is `advance_run(run_id)`; the worker loads
  authoritative state from Postgres by `run_id` rather than trusting the
  message payload.
- Delivery is **at-least-once**: Dramatiq acknowledges a message only after the
  actor returns, so a crash before ack causes redelivery. Handlers must
  therefore be **idempotent** (enforced with idempotency keys in the engine
  milestones). M1b's `ping` actor is idempotent by construction.
- The `worker` and `scheduler` are separate processes built from the **same
  image** as the `api`, selected by command.
- Any result/marker stored in Redis is ephemeral and never authoritative.

## Alternatives considered

- **Celery** — capable but heavier configuration and operational surface than
  this scale warrants.
- **RQ** — simpler, but weaker retry/middleware story and a fork-per-job model.
- **Temporal / Kafka** — powerful, but far more than needed now and against the
  "start simple" constraint; they would add operational complexity with no
  payoff at target scale.

## Consequences

- Simple to operate; the queue is swappable because durable state lives in
  Postgres, not in Redis.
- Losing Redis loses at most in-flight transport messages, never workflow state.
  Readiness reports Redis health; a reconciliation sweep (later) re-enqueues
  `advance_run` work from Postgres after an outage.
- The system depends on **idempotent handlers**; this is a first-class design
  constraint carried into the workflow engine, not an afterthought.
