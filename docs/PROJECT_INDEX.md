# Project Index — Natural Language Workflow Platform

Navigation and status document. A new engineer or agent should be able to read
this and know exactly where the project stands. Update it after each milestone.

## Status

| Field | Value |
|---|---|
| Current phase | M7 — Action connectors + approvals + side-effect safety |
| Current milestone | **M7 — Webhook + Slack action connectors + approval execution** (`feat/action-connectors-approvals`, in review) |
| Completed milestones | M0 · M1a · M1b · M2a · M2b · M3 · M4 · M5 · M6 |
| Next milestone | M8 — Scheduler (explicit timezone, single-firing) (`feat/scheduler`) |
| Release status | pre-alpha, nothing deployed |

M7 adds the first real external ACTION tools — `webhook.send` and
`slack.send_message` — with human approval and safe, bounded, idempotent
delivery. Approval-gated actions park the run at **WAITING_APPROVAL** and create
one durable approval; admin/owner decide via `POST /approvals/{id}/approve|reject`
(gated by role **and** an RLS admin/owner + `decided_by = app.user_id` check),
which is compare-and-set and recovery-safe (idempotent re-enqueue; enqueue
failure → 503). Side effects run **outside** the M3 run lock via a two-transaction
pattern (claim + durable stable idempotency key + atomic lease → COMMIT → external
call → finalize), with lease-guarded finalize, bounded retry (`next_attempt_at`
backoff, cap 5), and a secret-free `external_actions` audit. Outbound HTTP is
HTTPS-only, redirect-disabled, and SSRF-guarded with connect-time IP validation +
DNS-rebinding-safe pinning; the webhook URL comes only from the connector and
credential headers only from the SecretStore. **We do not claim exactly-once**:
non-idempotent receivers may see duplicates after a success-before-finalize crash
or an ambiguous post-transmission timeout. See ADR-013 and ADR-014.

M6 adds the natural-language planner and the deterministic feasibility engine.
An **async `LLMProvider`** (BYOK-ready; official Anthropic SDK as the reference,
a keyless stub for CI) turns a prompt into a strict `PlannerOutput`, which the
pure `nlw.feasibility.engine` judges — assigning `PASS`/`REJECT`/
`NEEDS_CLARIFICATION`/`NEEDS_APPROVAL` (precedence reject>clarify>approve>pass).
The LLM proposes; **code decides** — a parsed plan is not executable. Feasibility
checks tool availability (tenant-scoped registry projection), connector
ownership/type/status (RLS inventory; `error` recoverable, `disabled` rejects),
argument models, the M5 SQL validator (single source of truth), and the DAG
(Kahn). `POST /plans` runs planning API-side and persists an immutable
`plan_proposals` audit row that stores **no raw prompt** (only `prompt_len`) and
**no raw provider response**. `POST /plans/{id}/materialize` re-earns PASS against
the current capability view (`FOR UPDATE`, idempotent) before creating one
`workflow_version`. The platform LLM key is API-process-only (never worker/
scheduler, never in model context); safe planner schema context is an
operator-declared, non-secret `schema_hint`. See ADR-004 and ADR-005.

M5 ships the first **real** connector on the M4 capability layer: a `postgres`
connector type and a single read-only `postgres.query` tool. Read-only is
guaranteed by three independent controls — deterministic sqlglot validation
against a schema/table allowlist (layer 1), a `default_transaction_read_only`
session with statement/lock/idle timeouts (layer 2), and a SELECT-only external
role (layer 3). Results are row-capped (server-side, independent of any user
`LIMIT`) and byte-capped; column values use an explicit JSON type contract
(`bytea`/unknown rejected, not coerced). The JSON `{username,password}` credential
is a repr-safe `SecretStr` resolved worker-side via the SecretStore; all psycopg
errors are sanitized to typed errors so raw driver text and credentials never
reach logs, `step_runs.error`, or output. Failures are classified as retryable
(unavailable → Dramatiq retry) vs deterministic (→ step FAILED); an auth failure
flips the connector to `error`. The LLM does **not** generate SQL in M5. See
ADR-009 and ADR-012.

M4 adds the deterministic capability layer: a static **Tool Registry** (only
registered tools run), tenant-owned **connectors** (RLS role-specific), a
**SecretStore** (secret refs in DB; values resolved worker-side only, never in
the LLM path), and tenant-aware tool availability. The minimal `static`
connector + `static.echo`/`static.secret_check` prove the architecture end-to-end
through the M3 engine. See ADR-006 and ADR-011.

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
| M5 | Postgres source connector (read-only) + SQL safety | `feat/postgres-connector-sql-safety` | ADR-009, ADR-012 |
| M6 | Planner (LLM→Pydantic) + feasibility engine + LLMProvider (BYOK) | `feat/planner-feasibility` | ADR-004, ADR-005 |
| M7 | Webhook + Slack action connectors + approvals | `feat/action-connectors-approvals` | ADR-013, ADR-014 |
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
- [ADR-004 — Planner / feasibility separation (LLM proposes, code decides)](adr/ADR-004-planner-feasibility-separation.md)
- [ADR-005 — LLMProvider abstraction & BYOK](adr/ADR-005-llm-provider-byok.md)
- [ADR-006 — Connector/Tool separation + Tool Registry](adr/ADR-006-connector-tool-separation.md)
- [ADR-007 — Authentication provider (Supabase, identity only)](adr/ADR-007-auth-provider.md)
- [ADR-009 — Deterministic SQL safety for read-only database access](adr/ADR-009-sql-safety.md)
- [ADR-010 — Durable workflow execution (checkpointing, idempotency, concurrency)](adr/ADR-010-durable-execution.md)
- [ADR-011 — SecretStore abstraction & secret references](adr/ADR-011-secret-store.md)
- [ADR-012 — PostgreSQL connector (read-only query tool)](adr/ADR-012-postgres-connector.md)
- [ADR-013 — Action side-effect execution, approvals & idempotency](adr/ADR-013-action-side-effect-safety.md)
- [ADR-014 — Outbound HTTP / SSRF safety](adr/ADR-014-outbound-http-ssrf.md)

Planned: ADR-008 Deployment strategy.

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
