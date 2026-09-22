# Architecture Decision Records

Significant architectural decisions are recorded here as ADRs — one file per
decision, numbered and never deleted (supersede instead of removing).

## Process

- Create `ADR-NNN-short-title.md` from the template below.
- An ADR is required when a change introduces or alters an architectural
  boundary, a core dependency (queue, DB, auth, LLM provider), a security
  invariant, or a deployment strategy.
- Status flows: `Proposed → Accepted → (later) Superseded by ADR-XXX`.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [000](ADR-000-toolchain.md) | Engineering toolchain | Accepted |
| [001](ADR-001-postgres-state-store.md) | PostgreSQL as the system of record | Accepted |
| [002](ADR-002-redis-dramatiq-queue.md) | Redis + Dramatiq as the execution queue (transport only) | Accepted |
| [003](ADR-003-multi-tenant-isolation.md) | Multi-tenant isolation strategy (RLS + restricted role) | Accepted |
| [004](ADR-004-planner-feasibility-separation.md) | Planner / feasibility separation (LLM proposes, code decides) | Accepted |
| [005](ADR-005-llm-provider-byok.md) | LLMProvider abstraction & BYOK | Accepted |
| [006](ADR-006-connector-tool-separation.md) | Connector/Tool separation + deterministic Tool Registry | Accepted |
| [007](ADR-007-auth-provider.md) | Authentication provider (Supabase, identity only) | Accepted |
| [009](ADR-009-sql-safety.md) | Deterministic SQL safety for read-only database access | Accepted |
| [010](ADR-010-durable-execution.md) | Durable workflow execution: checkpointing, idempotency, concurrency | Accepted |
| [011](ADR-011-secret-store.md) | SecretStore abstraction & secret references | Accepted |
| [012](ADR-012-postgres-connector.md) | PostgreSQL connector (read-only query tool) | Accepted |
| [013](ADR-013-action-side-effect-safety.md) | Action side-effect execution, approvals & idempotency | Accepted |
| [014](ADR-014-outbound-http-ssrf.md) | Outbound HTTP / SSRF safety | Accepted |
| [015](ADR-015-scheduling-reconciliation.md) | Durable scheduling & unattended reconciliation | Accepted |
| [016](ADR-016-observability-and-correlation.md) | Observability: correlation IDs & Prometheus metrics | Accepted |
| [017](ADR-017-rate-and-resource-limits.md) | Rate limiting & per-tenant resource limits | Accepted |
| [018](ADR-018-production-topology-and-ops.md) | Production topology & operational readiness | Accepted |
| [019](ADR-019-frontend-architecture.md) | Frontend architecture (Next.js App Router + BFF) | Accepted |
| [020](ADR-020-staging-validation-and-capacity.md) | Staging validation, failure drills & capacity | Accepted |
| [021](ADR-021-scheduler-reconciler-correctness.md) | Scheduler & reconciler correctness (occurrence idempotency, fairness, progress, approval binding) | Accepted |
| [022](ADR-022-encrypted-offhost-backup-dr.md) | Encrypted off-host backup & disaster recovery (restic, verified success, guarded restore, post-restore quiescence) | Accepted |
| [023](ADR-023-membership-approval-sod.md) | Membership, invitations & approval separation of duties (hashed single-use invites, owner invariant, DB-enforced four-eyes) | Accepted |

## Template

```markdown
# ADR-NNN — <title>

- Status: Proposed | Accepted | Superseded by ADR-XXX
- Date: YYYY-MM-DD

## Context
What problem/forces are we responding to?

## Decision
What we chose to do.

## Alternatives considered
What else we weighed, and why we rejected it.

## Consequences
Trade-offs, follow-ups, and what this makes easy/hard later.
```
