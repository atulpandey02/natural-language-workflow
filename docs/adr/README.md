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
| [007](ADR-007-auth-provider.md) | Authentication provider (Supabase, identity only) | Accepted |

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
