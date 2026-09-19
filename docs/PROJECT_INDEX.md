# Project Index — Natural Language Workflow Platform

Navigation and status document. A new engineer or agent should be able to read
this and know exactly where the project stands. Update it after each milestone.

## Status

| Field | Value |
|---|---|
| Current phase | M3 — Durable workflow engine |
| Current milestone | **M3 — Durable workflow engine** (`feat/durable-workflow-engine`, in review) |
| Completed milestones | M0 · M1a · M1b · M2a · M2b (M1, M2 complete) |
| Next milestone | M4 — Tool registry + connector framework + SecretStore (`feat/tool-registry`) |
| Release status | pre-alpha, nothing deployed |

M3 makes execution durable: `advance_run(run_id)` (no state in the message) runs
one step per advancement inside a `FOR UPDATE`-locked transaction, commits, then
enqueues the next; committed steps are never re-executed under at-least-once
delivery. The worker derives tenant from Postgres via a worker-only SECURITY
DEFINER resolver (no GUC self-policy), preserving M2b isolation. See ADR-010.

M2 is delivered in two reviewable PRs: **M2a** (Supabase `AuthProvider`
[JWKS-first], `users`/`workspaces`/`memberships`, `X-Workspace-Id` tenant
context, membership-authoritative authorization, app-layer isolation tests —
ADR-007) and **M2b** (restricted `nlw_app` runtime role, role provisioning
bootstrap, two transaction-local GUCs `app.user_id`/`app.tenant_id`, RLS
policies, and a raw-SQL cross-tenant probe — ADR-003). With M2b, tenant
isolation is enforced by the database, not just the application.

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
- [ADR-003 — Multi-tenant isolation strategy (RLS + restricted role)](adr/ADR-003-multi-tenant-isolation.md)
- [ADR-007 — Authentication provider (Supabase, identity only)](adr/ADR-007-auth-provider.md)
- [ADR-010 — Durable workflow execution (checkpointing, idempotency, concurrency)](adr/ADR-010-durable-execution.md)

Planned: ADR-004 Planner/executor separation · ADR-005 BYOK provider model ·
ADR-006 Connector/tool separation · ADR-008 Deployment strategy · ADR-009 SQL safety.

## Runbooks

[`docs/runbooks/`](runbooks/) — none yet; added alongside the failure modes they
cover (Redis down, Postgres down, worker not consuming, scheduler stopped,
provider 429, credentials expired, workflow stuck RUNNING, migration failed).

## Incidents

[`docs/incidents/`](incidents/) — real postmortems only. None.

## Open risks

- **Forgeable GUC context (pre-production hardening).** RLS enforces isolation
  against mis-scoped app queries, but `app.user_id`/`app.tenant_id` are
  forgeable by arbitrary SQL under the shared runtime role. A non-forgeable /
  signed DB context (or per-request DB identity) is required for resistance to
  full request-identity forgery. Evaluate before public production. See ADR-003.
- Action connectors (M7) have an unavoidable at-least-once send window on a
  crash between "side effect sent" and "state written." Mitigated with
  idempotency keys and required approvals; documented as a known limitation.

## Known technical debt

None (greenfield).
