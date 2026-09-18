# Project Index — Natural Language Workflow Platform

Navigation and status document. A new engineer or agent should be able to read
this and know exactly where the project stands. Update it after each milestone.

## Status

| Field | Value |
|---|---|
| Current phase | M1 — Foundation & walking skeleton |
| Current milestone | **M1b — Worker roundtrip** (`feat/worker-roundtrip`, in progress) |
| Completed milestones | M0 — Repo init & skeleton · M1a — Runtime spine |
| Next milestone | M2 — Auth + tenant model + isolation (`feat/tenant-model`) |
| Release status | pre-alpha, nothing deployed |

M1 is delivered in two reviewable PRs: **M1a** (config, logging, FastAPI
health/version, Docker+compose api/postgres/redis, Alembic baseline, CI —
ADR-001) and **M1b** (Dramatiq broker + ping actor, worker & scheduler
containers, enqueue→worker roundtrip, integration tests — ADR-002). M1a is
merged to `main`; M1b completes the five-service walking skeleton.

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

- [ADR-000 — Engineering toolchain](adr/ADR-000-toolchain.md) — **Accepted**

Planned: ADR-001 Postgres state store · ADR-002 Redis/Dramatiq queue ·
ADR-003 Multi-tenant isolation · ADR-004 Planner/executor separation ·
ADR-005 BYOK provider model · ADR-006 Connector/tool separation ·
ADR-007 Auth provider (Supabase) · ADR-008 Deployment strategy ·
ADR-009 SQL safety.

## Runbooks

[`docs/runbooks/`](runbooks/) — none yet; added alongside the failure modes they
cover (Redis down, Postgres down, worker not consuming, scheduler stopped,
provider 429, credentials expired, workflow stuck RUNNING, migration failed).

## Incidents

[`docs/incidents/`](incidents/) — real postmortems only. None.

## Open risks

- Cross-tenant isolation is unproven until M2 introduces isolation tests.
- Action connectors (M7) have an unavoidable at-least-once send window on a
  crash between "side effect sent" and "state written." Mitigated with
  idempotency keys and required approvals; documented as a known limitation.

## Known technical debt

None (greenfield).
