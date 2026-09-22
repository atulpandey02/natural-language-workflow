# Project Index — Natural Language Workflow Platform

Navigation and status document. A new engineer or agent should be able to read
this and know exactly where the project stands. Update it after each milestone.

## Status

| Field | Value |
|---|---|
| Current phase | M11.5 — Pre-M12 hardening (external review remediation) |
| Current milestone | **M11.5 P3A** — membership invitations + approval separation of duties: hashed single-use invites, owner-preservation invariant, DB-enforced four-eyes approvals, immutable requester provenance (migration `0015`, ADR-023). P3B (signed context) in progress. |
| Completed milestones | M0 · M1a · M1b · M2a · M2b · M3 · M4 · M5 · M6 · M7 · M8 · M9 · M10 · M11 |
| Next milestone | M12 — limited production launch (blocked; see ADR-020 + independent GPT-6/Fable reviews) |
| Release status | pre-alpha; real-VPS validated (CONDITIONAL GO); external review = NO-GO for customer data pending M11.5 |

M11.5 P0 (runtime credential isolation) closes the top verified review finding:
the privileged `DATABASE_MIGRATION_URL` (owner) is removed from every long-running
runtime service (api/worker/scheduler/web) and confined to a dedicated one-shot
`migrate` service (Compose `migration` profile). Also: `WORKSPACE_COOKIE_SECRET`
is now production-required (fail-fast), the worker gets `stop_grace_period: 60s`,
production auth cookies are explicitly `Secure` (`SameSite=Lax`), and ADR-019's
session-cookie claim is corrected (Supabase cookies are JS-readable; HttpOnly/
opaque session is future work). Remaining P1–P3 packages (connector authz/egress,
SQL-safety, action lease/UNKNOWN outcomes, scheduler/reconciler fixes, `users`
RLS, signed GUC, DR/PITR, membership/invites, alerting) are tracked from the
reviews. Secret rotation (Anthropic key + Supabase password exposed in setup)
remains a required operator action — see runbooks/rotate-exposed-secrets.md.

M11.5 P1A (identity & connector authorization, migration `0011`) closes two
verified authorization findings. **users:** RLS is now `ENABLE`+`FORCE`; `nlw_app`
loses its broad `SELECT/INSERT/UPDATE` and keeps only a self-scoped `SELECT` plus
a column-limited self `UPDATE(email)` (self-only RLS). First-login resolution uses
a *minimal* `SECURITY DEFINER` bootstrap `resolve_or_create_user` (owned by
`nlw_workspace_bootstrap`, `EXECUTE` for `nlw_app` only, never worker/scheduler/
PUBLIC) that returns **only the internal `uuid`** — never a row/email/provider id
— inserts a missing identity race-safely and does nothing to an existing one, so
it cannot read or rewrite another user's record. Email sync is a separate
self-scoped step after `app.user_id` is established (verified provider email only).
The stable `auth_provider_id` is never writable by the app role. So the runtime
role can no longer enumerate or rewrite unrelated identities. (Honest boundary: a
caller able to forge complete DB context stays in the deferred signed-GUC scope.)
**connectors:** creation + credential-alias attachment is now admin/owner-only in
both the API (`require_role(ADMIN)`) and RLS (`connectors_app_insert` now checks
`is_current_user_admin_or_owner`); members keep read-only, secret-free access.
`secret_ref` remains absent from all member-facing responses, planner context,
plans, step state, approvals, logs and errors. Deferred: signed/non-forgeable DB
context, cloud/encrypted secret storage, self-service secret onboarding,
connector→credential-entity binding, team invitations (see ADR-003/006/011).

M11.5 P1B (PostgreSQL connector trust boundary, no migration) closes the verified
SQL-safety and network-egress defects. **SQL:** the single `validate_select`
(shared by planner feasibility, materialization and runtime) now resolves table
authorization by real lexical scope (`sqlglot.optimizer.scope`) — a
schema-qualified physical table is always allowlist-checked even if it shares a
CTE name — and uses a default-deny function allowlist (schema-qualified/UDF/unknown
functions and unsafe builtins reject; casts restricted to safe target types).
**Network:** a new `pg_destination` policy validates every resolved A/AAAA answer
and pins the connection to a validated IP via libpq `hostaddr` while preserving the
hostname for TLS; production/staging block loopback/RFC1918/ULA/link-local+metadata/
CGNAT/multicast/internal-service-name/Unix-socket/DSN destinations, restrict ports,
and require `sslmode=verify-full` (tenant cannot weaken). Unsafe destinations fail
closed with stable codes BEFORE any auth bytes are sent (credential-exfiltration
proof: zero bytes). Private fixtures are allowed only via the `app_env` gate
(local/dev) or an operator CIDR allowlist (staging) — never a tenant/connector
field. Deferred: tenant-supplied CA material, connector→durable-credential binding.

M11.5 P1C (external-action delivery safety, migration `0012`) closes eight
verified action-delivery defects without expanding run/step states (the only new
persisted state is `external_actions.status = 'unknown'`). **Lease ordering:** on
resume a live foreign lease is authoritative BEFORE the attempt cap, so a
duplicate can no longer fail a legitimate live final attempt or steal/clear
another worker's lease; only the lease-token owner finalizes. **Ambiguous outcome
→ terminal UNKNOWN (`ACTION_OUTCOME_UNKNOWN`):** a failure once the request may
have been transmitted (write/read/reset/total-deadline, a truncated/garbled
response, or an expired unprovable final attempt) resolves to a terminal `unknown`
action with step/run FAILED under a distinguishing error class — persistent,
excluded from retry/reconciliation/redelivery, never auto-resent, no retry button;
classification is conservative (auto-retry only on a provable pre-transmission
failure or a connector contract — Slack 429 / `ok:false`; a generic webhook 429 or
5xx is UNKNOWN, not retried). **Total deadline:** one monotonic
wall-clock budget (30s) covering resolve/connect/TLS/write/response, with
`TOTAL + FINALIZE_MARGIN(10s) < LEASE(45s)`, stops a trickling response before it
can outlive the lease; no background thread survives the caller. **Streaming
caps:** `Accept-Encoding: identity` + raw `iter_raw` under a hard byte cap, so a
compression bomb never expands and no response/secret is persisted. **Approval
preview:** shows connector type/name, effective non-secret destination (webhook
host / Slack channel) and the complete bounded payload; an oversized payload
(>16 KB) is rejected at materialization and 422 at approve-time (never
truncate-and-approve); approval binds the immutable spec AND connector identity
(a post-approval connector swap fails "re-approval required"). The stable
`external_action_key`/`Idempotency-Key` is unchanged (still at-least-once, no
exactly-once claim). Operator recovery: runbooks/action-outcome-unknown.md.
Deferred (unchanged): signed GUC, HttpOnly sessions, invites, cloud secrets,
DR/PITR, M12.

M11.5 P1D (scheduler & reconciler correctness, migration `0013`, ADR-021) closes
six verified defects. **Scheduled-run idempotency:** a scheduled run's uniqueness
is the immutable occurrence identity `(schedule_id, scheduled_for)` (DB constraint
+ `ON CONFLICT DO NOTHING`); it stores NULL `idempotency_key`, so a client
`Idempotency-Key` can never collide with, suppress, or be mistaken for a scheduled
occurrence (three distinct namespaces: manual key / scheduler occurrence / P1C
external-action key; the API also rejects the reserved `sched:` prefix).
**Reconciler ordering:** all deterministic eligibility filters (incl. the recovery
horizon and P1C-UNKNOWN exclusion) run BEFORE `ORDER BY`/`LIMIT`, so beyond-horizon
rows can no longer crowd out eligible stale rows; a stable `progress_at, id` order.
**Progress:** new `workflow_runs.last_progress_at` (server-stamped only on genuine
state-machine advancement, never on a scan/read/no-op/stale-CAS) drives RUNNING
staleness/horizon instead of the mutable `updated_at`; backfilled conservatively.
**Fairness:** `row_number() OVER (PARTITION BY tenant_id ...)` caps each tenant at
`scheduler_reconcile_per_tenant_limit` (default 20, validated `1..batch`) under a
global `scheduler_batch_limit`, so a noisy tenant cannot starve a quiet one.
**Approvals:** the reconciler re-drives a WAITING_APPROVAL run only when the
CURRENTLY-blocked step's own approval is decided (bound via `approvals JOIN
step_runs` on `(run_id, step_id)` + `status='WAITING_APPROVAL'`), never "any
approval for the run". A new column-restricted `SELECT (id, tenant_id, run_id,
step_id, status)` grant lets `nlw_scheduler` read step status without step I/O.
Honest guarantee: exactly one run row per scheduled occurrence (DB uniqueness),
at-least-once processing, CAS/leases constrain DB ownership only; external effects
keep P1C's UNKNOWN + receiver-idempotency limits. Runbook: runs-beyond-horizon.md.

M11.5 P3A (membership, invitations & approval separation of duties, migration
`0015`, ADR-023) closes two authorization gaps. **Invitations:**
`workspace_invitations` stores only the sha256 hash of a high-entropy token (the
raw token is returned once for manual sharing, never logged/persisted); acceptance
is an atomic SECURITY DEFINER function that requires an authenticated identity whose
verified email matches, is single-use + concurrency-safe (one membership), and
returns a uniform non-enumerating error on any invalid case. **Owner invariant:** a
constraint trigger (advisory-locked per workspace) refuses any change leaving a
workspace with zero owners, so the final owner can't be removed/demoted even under
concurrency; admins can manage member/admin rows but not owner rows. **Approval
four-eyes:** `approvals.requested_by_user_id` (immutable, derived from run
provenance — manual creator or schedule creator, never request JSON) plus a DB
`WITH CHECK` that the decider is an admin/owner, stamps themselves, and is **not**
the requester; a legacy unknown-requester approval fails closed. Self-approval is
rejected even by an owner and even via direct SQL. Append-only `authz_audit_events`
records invite/membership/approval events without tokens/secrets. Honest boundary:
this does not yet close the **forgeable-GUC** threat (an SQL attacker as `nlw_app`
forging `app.user_id`) — that is **P3B (signed context)**, a launch gate. Docs:
runbooks/invitation-operations, approval-operations.

M11.5 P2 (encrypted off-host backup & disaster recovery, migration `0014`,
ADR-022) replaces the M9 gpg+`pg_dump` scripts (now deprecation stubs) with a
restic mechanism where **success = a verified off-host snapshot**, never
`pg_dump` exit 0. Backup config is isolated in its own fail-closed Pydantic model
(secrets `SecretStr`, passed via a sanitized child env, never argv; never
inherited by api/worker/scheduler/web/migrate); scheduling is a **systemd timer**,
not the app scheduler; freshness/dead-man + failure/verify metrics feed Prometheus
alerts. **Restore** is human-gated (destructive confirmation `NLW_RESTORE_CONFIRM
== NLW_RESTORE_TARGET_ID`, no-runtime-active + empty-target guards), preserves
object ownership (a drill caught that `--no-owner` silently turned the NOSUPERUSER
SECURITY DEFINER functions into a privilege-escalation vector), then runs
**mandatory post-restore quiescence** — the correctness core: in-flight
runs/steps → `FAILED`/`DR_RESTORE_UNCERTAIN`, ambiguous external actions →
`unknown` (P1C UNKNOWN semantics, so already-delivered side effects are never
blindly re-driven), stale schedules recomputed after the recovery cutoff;
idempotent and audited via `dr_restore_events` (outside RLS, non-forgeable). A
deep **validation** asserts the restored security posture (RLS+FORCE, roles
NOSUPERUSER/NOBYPASSRLS, SECURITY DEFINER owners + search_path, ownership) and
invariants before a runtime-start gate opens. A disposable MinIO drill
(`scripts/ops/dr-drill.sh`) proves the mechanism end-to-end. Honest boundaries:
**RPO ≤ 24h / RTO ≤ 4h are objectives, not guarantees**; **no PITR** (WAL-G/
pgBackRest is future work); ransomware resistance requires operator-configured
object-lock/isolated-credentials; **Supabase Auth is a separate DR dependency**.
Docs: runbooks/backup-operations, dr-fresh-host-restore, post-restore-quiescence,
backup-failure-troubleshooting, disaster-declaration-checklist, dr-real-vps-checklist;
ops/backup-systemd, backup-providers, rpo-rto, pitr-boundary. An
operational-safety addendum adds: an explicit `flock` single-execution lock around
the whole backup lifecycle (a second run exits 3, doing no work — restic's repo
lock is not relied on for this); a runtime-service guard that inspects Compose
state scoped to the exact restore project and fails closed (defence beyond the
DB-session check, rechecked pre-restore for TOCTOU); an enforceable restore-ready
**gate** written atomically only after quiescence+validation and bound to the
restore generation + DB `system_identifier` (verified by `nlw.backup gate-check`;
stale/cross-DB/tampered gates rejected; normal deploys need no gate); explicit
`simple`/`immutable` retention modes (immutable never prunes from the VPS —
a separate `nlw.backup prune` does; contradictory config fails closed); and an
extended drill proving startup is blocked pre-gate, a new post-restore run runs to
COMPLETED, no restored work is replayed, and the gate cannot be reused. A follow-up
correction makes the runtime-start gate **database-authoritative**: `dr_restore_events`
(migration `0014`, runtime roles have only column-scoped SELECT) carries a
validated→enabled state machine; api/worker/scheduler run a **mandatory** startup
preflight (API lifespan, scheduler main, worker `before_worker_boot`) that fails
closed unless the newest restore generation is operator-enabled — regardless of
`NLW_RESTORE_MODE`, profile, or file. A separate `nlw.backup enable-runtime`
operator command performs the audited, conditional enable; a later restore re-locks.
The file gate / `NLW_RESTORE_MODE` are now defense-in-depth only. Because the API
can stay alive for DB-independent liveness, it carries a **live** recovery gate
(three-valued ALLOWED/LOCKED/UNKNOWN, short bounded cache + query timeout) with a
**deny-by-default** middleware: liveness/version/readiness stay available, every
other route returns a sanitized 503 unless ALLOWED, and a running API re-locks on a
later generation / opens on enable / fails closed on DB loss without a restart.

M10 adds the minimum product UI (Next.js 16 App Router + TypeScript, in `web/`)
so a user can operate the platform end-to-end without curl/SQL: Supabase
cookie auth, workspace selection, dashboard, connector management, natural-language
planning + feasibility + materialization, workflow/run/step/action views,
approvals, and scheduling. The browser talks only to a same-origin BFF that
injects the bearer token + `X-Workspace-Id` server-side (tokens never in
`localStorage`); the API stays internal behind Caddy. Bounded polling (no
WebSockets), role-aware UI (backend authoritative), CSRF + CSP, and no secret
values ever reach the browser. Read-only backend support endpoints for
workflows/versions/runs/steps/actions plus an idempotent manual-run trigger were
added (no new grants/migration). See ADR-019.

M9 makes the existing backend safe to run in staging on a small VPS (Docker
Compose, no Kubernetes): correlation IDs + internal Prometheus metrics
(ADR-016); an atomic Redis fixed-window rate limiter + concurrency-safe
per-tenant caps (ADR-017); bounded DB pools/timeouts, safe API errors, a
streamed request-body cap, CORS/TrustedHost/security headers, production docs
gating, a schema-compat readiness check, a bounded reconciler recovery horizon
(poisoned-run guard), non-root hardened containers, a Caddy-fronted production
compose with GHCR immutable-digest delivery + Trivy, and backup/restore +
runbooks (ADR-018). Non-forgeable DB context, a cloud secret manager, and
OTel/Langfuse remain explicit pre-production items.

M8 makes the scheduler a durable, restart-safe system of record for recurrence.
Structured schedules (IANA timezone + hourly/daily/weekly, no cron) pin an
immutable `workflow_version`; a due-scan claims schedules with `FOR UPDATE SKIP
LOCKED` and creates **exactly one durable `workflow_run` row per occurrence
across scheduler concurrency and restart** (via `UNIQUE(schedule_id,
scheduled_for)`), advances `next_run_at` in the same transaction, and enqueues
after commit (queue delivery + execution stay idempotent/at-least-once, not
exactly-once). DST is handled by wall-clock `zoneinfo` (spring-forward shifts by
the gap; fall-back fires once, earlier); catch-up is bounded (latest missed
within 1h). A reconciler loop reconstructs recovery eligibility **entirely from
PostgreSQL** (Redis is only transport for the re-enqueued run_id) and re-enqueues
stuck runs (orphan PENDING, stale RUNNING/expired lease, ordinary stale RUNNING,
decided-but-parked WAITING_APPROVAL) — writing nothing, so the worker's M7
lease/retry/approval logic stays authoritative. A
least-privilege `nlw_scheduler` role (LOGIN, NOSUPERUSER, **NOBYPASSRLS**) reads
only schedules/runs/actions/approvals and never sees connectors, secrets, or step
I/O. Schedule mutation is admin/owner (role + RLS); `created_by` is server-owned.
See ADR-015.

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
| M8 | Scheduler (explicit timezone, single-firing) + reconciliation | `feat/scheduling-reconciliation` | ADR-015 |
| M9 | Production hardening + operational readiness (observability, rate/resource limits, container/HTTP/DB hardening, backups, runbooks, GHCR delivery) | `feat/production-hardening` | ADR-016, ADR-017, ADR-018 |
| M10 | Frontend / Product UX (Next.js App Router + BFF; read-only support endpoints + idempotent manual run) | `feat/frontend-product-ux` | ADR-019 |
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
- [ADR-015 — Durable scheduling & unattended reconciliation](adr/ADR-015-scheduling-reconciliation.md)
- [ADR-016 — Observability: correlation IDs & Prometheus metrics](adr/ADR-016-observability-and-correlation.md)
- [ADR-017 — Rate limiting & per-tenant resource limits](adr/ADR-017-rate-and-resource-limits.md)
- [ADR-018 — Production topology & operational readiness](adr/ADR-018-production-topology-and-ops.md)
- [ADR-019 — Frontend architecture (Next.js App Router + BFF)](adr/ADR-019-frontend-architecture.md)
- [ADR-020 — Staging validation, failure drills & capacity](adr/ADR-020-staging-validation-and-capacity.md)
- [ADR-021 — Scheduler & reconciler correctness (M11.5 P1D)](adr/ADR-021-scheduler-reconciler-correctness.md)
- [ADR-022 — Encrypted off-host backup & disaster recovery (M11.5 P2)](adr/ADR-022-encrypted-offhost-backup-dr.md)
- [ADR-023 — Membership, invitations & approval separation of duties (M11.5 P3A)](adr/ADR-023-membership-approval-sod.md)

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
