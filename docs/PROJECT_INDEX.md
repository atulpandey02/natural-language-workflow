# Project Index — Natural Language Workflow Platform

Navigation and status document. A new engineer or agent should be able to read
this and know exactly where the project stands. Update it after each milestone.

## Status

| Field | Value |
|---|---|
| Current phase | M2 — Auth + tenant model + isolation |
| Current milestone | **M2a — Identity, tenancy model, auth context** (`feat/tenant-model`, in progress) |
| Completed milestones | M0 · M1a · M1b (M1 complete) |
| Next milestone | M2b — Database-enforced RLS isolation (`feat/tenant-rls`) |
| Release status | pre-alpha, nothing deployed |

M2 is delivered in two reviewable PRs: **M2a** (Supabase `AuthProvider`
[JWKS-first], `users`/`workspaces`/`memberships`, `X-Workspace-Id` tenant
context, membership-authoritative authorization, app-layer isolation tests —
ADR-007) and **M2b** (restricted `nlw_app` runtime role, role provisioning
bootstrap, `SET LOCAL app.tenant_id`, RLS policies, cross-tenant RLS probe —
ADR-003). M2a's isolation is app-layer; the DB-enforced guarantee lands in M2b.

## Milestone roadmap (revised ordering)

Durable engine is proven **before** the LLM planner and real connectors, using a
deterministic fake tool. Security and observability are cross-cutting, added with
the components they protect — not deferred to the end.

| ID | Goal | Branch | ADR |
|----|------|--------|-----|
| M0 | Repo init & toolchain skeleton | `chore/repo-skeleton` | ADR-000 |
| M1 | Foundation & walking skeleton (Docker, FastAPI health, worker roundtrip, Alembic) | `feat/foundation` | ADR-001, ADR-002 |
| M2 | Auth + tenant model + isolation (RLS, tenant-scoped repos) | `feat/tenant-model` | ADR-003, ADR-007 |
| M3 | Durable workflow engine with a fake tool (state, checkpoint, resume, idempotency) | `feat/workflow-engine` | ADR-004 |
| M4 | Tool registry + connector framework + SecretStore | `feat/tool-registry` | ADR-006 |
| M5 | Postgres source connector (read-only) + SQL safety | `feat/postgres-connector` | ADR-009 |
| M6 | Planner (LLM→Pydantic) + feasibility engine + LLMProvider (BYOK) | `feat/workflow-planner` | ADR-005 |
| M7 | Webhook → Slack action connectors + approvals | `feat/action-connectors` | (as needed) |
| M8 | Scheduler (explicit timezone, single-firing) | `feat/scheduler` | — |
| M9+ | Hardening & expansion (ClickHouse, Gmail, observability, rate limits) | tbd | tbd |
| M10 | Frontend (Vite + React) | `feat/frontend` | — |
| M11 | Staging + CD + load/failure testing | tbd | ADR-008 |
| M12 | Production deployment | tbd | — |

**First-release connector scope:** PostgreSQL (source), Webhook + Slack (actions).
Demonstration workflow target:
`Postgres → deterministic condition → optional LLM processing → Slack/Webhook`.

## Architecture docs

- [`docs/architecture/`](architecture/) — component & data-flow docs (pending)
- Target: FastAPI control plane · Postgres system of record · Redis/Dramatiq
  transport · stateless workers · one Docker image per role.

## Architecture Decision Records

See [`docs/adr/`](adr/). Accepted so far:

- [ADR-000 — Engineering toolchain](adr/ADR-000-toolchain.md)
- [ADR-001 — PostgreSQL as the system of record](adr/ADR-001-postgres-state-store.md)
- [ADR-002 — Redis + Dramatiq (transport only)](adr/ADR-002-redis-dramatiq-queue.md)
- [ADR-007 — Authentication provider (Supabase, identity only)](adr/ADR-007-auth-provider.md)

Planned: ADR-003 Multi-tenant isolation (M2b) · ADR-004 Planner/executor
separation · ADR-005 BYOK provider model · ADR-006 Connector/tool separation ·
ADR-008 Deployment strategy · ADR-009 SQL safety.

## Runbooks

[`docs/runbooks/`](runbooks/) — none yet; added alongside the failure modes they
cover (Redis down, Postgres down, worker not consuming, scheduler stopped,
provider 429, credentials expired, workflow stuck RUNNING, migration failed).

## Incidents

[`docs/incidents/`](incidents/) — real postmortems only. None.

## Open risks

- **Isolation is app-layer only until M2b.** M2a enforces tenancy via
  membership-checked repositories (tested), but the app still connects as the DB
  owner. Database-enforced isolation (restricted `nlw_app` role + RLS + the
  cross-tenant probe) lands in M2b.
- Action connectors (M7) have an unavoidable at-least-once send window on a
  crash between "side effect sent" and "state written." Mitigated with
  idempotency keys and required approvals; documented as a known limitation.

## Known technical debt

None (greenfield).
