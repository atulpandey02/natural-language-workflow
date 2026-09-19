# ADR-016 — Observability: correlation IDs & Prometheus metrics

- Status: Accepted
- Date: 2026-09-19

## Context

Before M9 the platform emitted structured logs but had no request/task
correlation and no metrics, making staging incidents hard to diagnose. We need
observability that is safe (no secrets/PII), low-overhead, and honest about what
it measures — without adopting heavy tracing infrastructure prematurely.

## Decision

**Correlation.** `run_id` is the durable end-to-end correlation key for workflow
execution. The control plane adds a per-request `request_id` (server-minted UUID;
inbound IDs are ignored unless explicitly trusted, and then strictly validated
and length-bounded). Correlation fields are bound into structlog contextvars and
**cleared at every request/task boundary**, so pooled threads/tasks never inherit
a previous scope. The `X-Request-Id` is echoed on responses. The Dramatiq message
still carries only `run_id` (no PII/secrets).

**Metrics.** Each process (api / worker / scheduler) serves Prometheus metrics on
its own **internal** port (`metrics_port`), never published publicly. The API
starts it in its entrypoint; the worker starts it via a Dramatiq
`after_worker_boot` middleware; the scheduler starts it in its loop entrypoint.
Metrics cover HTTP, planner, tool/action, engine advancement, scheduler lag /
reconcile / runs-beyond-horizon, errors, and rate-limit rejections.

**Label discipline.** Metric labels are **low-cardinality only** (method, route
template, tool, outcome, error class). Identifiers (`tenant_id`, `run_id`,
`step_id`, `connector_id`) are **never** labels — they live in logs and the
database.

**Deferred.** OpenTelemetry distributed tracing and Langfuse LLM tracing are
**not** implemented in M9. A `traceparent` message-option seam is left for future
OTel; Postgres remains the authoritative audit store.

## Alternatives considered

- **OpenTelemetry now.** Higher value long-term but adds collector/exporter infra
  and cost; deferred to post-staging.
- **Metrics on the public API port.** Rejected: metrics must be internal-only.
- **Push metrics (statsd).** Rejected: Prometheus pull is simpler on a single VPS.

## Consequences

- Diagnosable staging with joinable logs (`request_id` + `run_id`) and scrapeable
  metrics, at negligible overhead.
- Callers record through typed helper functions, keeping the strict-typed engine
  and scheduler modules clean and prometheus-object-free.
- No cardinality blow-up. Adding tracing later is a bounded, additive change.
