# Project Index — Natural Language Workflow Platform

Navigation and status document. A new engineer or agent should be able to read
this and know exactly where the project stands. Update it after each milestone.

## Phase 2B — O-2 D6 AWS proof package (branch `docs/o2-aws-proof-readiness`, awaiting review; NOT RUN)

Prepared for independent review; nothing was run against AWS:

- [D6 proof procedure](runbooks/dataset-s3-d6-proof.md): resource inventory,
  ordered staging-only steps P00–P18 with every command labelled READ-ONLY or
  MUTATING, stop conditions S1–S9, sanitized evidence, ledger-based cleanup and
  recovery.
- [Owner decisions E1–E10](runbooks/dataset-s3-d6-owner-decisions.md), all
  open.
- [Policy review](security/o2-aws-policy-review.md): findings F1–F7 fixed in
  the [templates](runbooks/dataset-s3-provisioning.md), residual risks R1–R6.
  F1: the key policy let the ingest and operator roles generate data keys.
- Contract tests with negative controls:
  `tests/unit/test_dataset_s3_d6_proof.py`.

## Phase 2B — S3 dataset store, O-2 implementation (merged as `eb42250`)

ADR-033 is implemented with no AWS contact:

- `nlw.storage.s3.S3BlobStore`:
  - conditional, SSE-KMS-explicit creation;
  - whole-file SHA-256 and a composite multipart checksum;
  - an abort on every failure;
  - version-aware operator purge.
- Pinned per-service credentials with an identity check.
- The `DATASET_S3_*` refusals.
- One immutable `versions/` object per version: the ingest runtime is
  read-only and the API never deletes.
- Migration `0028_dataset_object_layout`: key layout, a key-never-moves guard,
  `nlw_ingest` losing `UPDATE (storage_object_key)`, and reason
  `REJECTED_RETENTION`.
- Operator `rejected-pending` and `purge-rejected`.
- Two dormant alerts.

No AWS resource exists. The real-AWS proof awaits authorization, and uploads
stay refused in staging and production.

## Phase 2B — production dataset storage, O-2 (ADR-033 merged as `b83ae37`)

The owner decided O-2 on 2026-10-09: AWS S3 in us-east-1, separate staging
and production buckets, IAM roles and customer-managed KMS keys, and boto3.
[ADR-033](adr/ADR-033-s3-dataset-object-storage.md) records it, with D1–D6
approved:

- one immutable object per version under `versions/`;
- the ingest runtime is read-only;
- rejected files are purged by the operator within a provisional 7 days;
- narrow assumed roles, with per-container short-lived credentials and IMDS
  blocked;
- the existing `DATASET_S3_*` settings;
- the real-AWS proof only after explicit authorization.

[Provisioning templates](runbooks/dataset-s3-provisioning.md) are NOT RUN.
There is no code yet, and no AWS resource exists or is contacted.

## Phase 2B — unattended dataset dispatcher, O-7 (branch `feat/o7-ingest-dispatcher`, awaiting review)

Builds on the upload API (atulpandey02/natural-language-workflow#56, merged as
`53fe92c`). Migration `0027_dataset_ingest_dispatch`
([ADR-032](adr/ADR-032-dataset-ingest-dispatcher.md)) adds a dormant
`nlw_ingest_dispatch` role. It holds one read-only SECURITY DEFINER function
and no dataset-table access. The `nlw.ingest_dispatch` process re-sends lost
enqueues, bounded and oldest first, with pending-age alerts
(`datasets.rules.yml`, not yet wired into the deployed Prometheus). The signed
policy count is unchanged at 74. **Uploads remain disabled.**

Open owner decisions: O-2 storage, O-3 deletion log, O-4 object
backup/restore, O-5 retention, and O-6 enablement (which includes the
dispatcher).

## Phase 2B — dataset ingest runtime boundary, O-1 (branch `feat/dataset-ingest-runtime-role`, awaiting review)

Builds on the CSV profiling and storage foundation (atulpandey02/natural-language-workflow#52,
merged as `35bf765`, migration `0025`, [ADR-030](adr/ADR-030-csv-ingestion-and-profiling.md)).
Migration `0026_dataset_ingest_role` ([ADR-031](adr/ADR-031-dataset-ingest-runtime-boundary.md)):
a least-privilege `nlw_ingest` role, a `dataset_ingest` signed purpose and key
class, immutable processing requests anchoring the queue's work envelopes, and
the `nlw.ingest_service` runtime. The API no longer profiles. **Uploads remain
disabled**: no upload/processing route, no S3 (O-2), and the ingest runtime is
dormant in staging/production (NOLOGIN role, no key, no container) until O-6.
Open owner decisions: O-2 storage, O-3 deletion log, O-4 object backup/restore,
O-5 retention, O-6 enablement.

## Phase 2A — dataset lifecycle foundation (branch `feat/phase2-dataset-lifecycle`, awaiting review)

Branched from `main` at `9972830` (staging runs that release at revision
`0023`). Migration `0024_dataset_lifecycle` makes this a migration release
(`0023 → 0024`); the signed-policy inventory becomes **61** (53 + 8).
[ADR-029](adr/ADR-029-dataset-lifecycle-foundation.md) ·
[runbook](runbooks/dataset-metadata-deletion.md) ·
[evidence](evidence/phase2-dataset-lifecycle/README.md).

- Tenant-isolated `datasets`, immutable `dataset_versions` and append-only
  `dataset_events` with forced RLS on the signed context; explicit states
  enforced by database triggers (nothing leaves `DELETED`, one active version,
  pointer consistency, atomic version numbering).
- Admin/owner deletion **requests** (`DELETING`, idempotent); an operator-only
  tombstone (`DELETED`, names scrubbed, evidence kept).
- Metadata API behind `DATASETS_API_ENABLED`, **refused in staging and
  production**. **No upload, no customer file or object, no profiling table,
  no planner or model access, no query execution.** Customers still cannot
  upload data.

## Phase 2 foundations (merged; historical notes written before the push)

Implements the unblocked parts of the Phase 2 plan (Edition 2) on top of `main`
at `fcfd4d5`. Not pushed, not deployed; staging still runs `b1a3058` at
revision `0021`, so deploying this branch is a migration-requiring release
(`0021 → 0023`) through the gated rollout.

- **B01 — workspace-creation grants** (migration `0022`, [ADR-023 amendment 1](adr/ADR-023-membership-approval-sod.md#amendment-1--founding-a-workspace-requires-an-operator-grant-phase-2-b01-2026-09-29),
  [runbook](runbooks/workspace-creation-grants.md)): founding a workspace needs
  a single-use, email-bound operator grant enforced inside the SECURITY DEFINER
  bootstrap; 403 `WORKSPACE_CREATION_NOT_GRANTED`; `identity.provisioned` and
  `workspace.created` audit events; rollout and restore validator refuse an
  ungated bootstrap.
- **B02 — plan outcome events** (migration `0023`, [ADR-028](adr/ADR-028-plan-outcome-events.md)):
  redacted, append-only, codes-only measurement of every planning attempt; the
  signed-policy inventory is now **53**; operator report
  `python -m nlw.ops.outcomes report`; benchmark runs use the same taxonomy.
- **B03 — code parts:** staging/production refuse to start an anthropic planner
  without an explicit `NLW_LLM_MODEL`; `python -m nlw.ops.dr_evidence check`
  evaluates a real-provider DR drill record. The drill itself is **not run**.
- **B04 — library layer only:** tenant-scoped blob store and a bounded,
  deterministic CSV profiler (`profile-1`) with no planner, provider or query
  path ([development notes](development/datasets.md), including the pinned
  Starlette/FastAPI body-limit finding). No dataset tables, API or worker yet.
  **Customers cannot upload data**: ingestion is planned, not available.
- **Offboarding contract:** every table classified; read-only inventory;
  customer statement awaiting owner approval
  ([offboarding-and-deletion](security/offboarding-and-deletion.md)).

## Pilot launch closure (merged as `b1a3058`, PR #40; deployed to staging)

On `feat/staging-custom-domain`, after the unchanged custom-domain commits: a
discoverable Members page with invitations and safe acceptance, one friendly
error language (UNKNOWN never invites a blind retry), a polished sign-in and
first-use onboarding, plain-language plan/run states, a corrected typed Slack
connector form (plus a 409 for duplicate connector names instead of a 500), and
a readable approval review. Real-browser launch journeys run as a third step of
the isolated pilot harness job, still asserting exactly one mock delivery.
Co-member emails remain hidden pending a reviewed SECURITY DEFINER directory
function. (Historical note: this section was written before the push; the
work merged as `b1a3058` and is the release running on staging.)

- [Discovery, journeys, screenshots, demo script and limitations](evidence/launch-closure/README.md)

## M12C — pilot analytics experience and rollout correction

M12C merged to `main` as `549b19f` (#37), adding two deterministic synthetic datasets,
registered analytical tools, the bounded `analytics-1` result contract, authorized
results and an immutable two-proposal Slack journey. The responsive Next.js
interface renders KPIs, fixed Recharts charts, supporting tables and source-step
evidence. Migration `0021` adds handoff provenance only; migrations 0001–0020 and
protected execution/approval/authorization/recovery/release semantics remain
unchanged. The final frontend visual refinement adds a compact KPI strip,
consistent metric colors, asymmetric charts and collapsible execution evidence.
Real seeded browser captures cover desktop, laptop, tablet, mobile and failure
states. Independent review returned `READY WITH NON-BLOCKING NOTES`. The three
final corrections restore forbidden catalog-text test coverage, keep mobile
table identifiers on one line with an accessible scroll cue, and gate Slack
sharing on validated READY analytics. A local follow-up on
`fix/staging-demo-tool-enablement` addresses a deployment blocker: the reviewed
target now explicitly selects demo-tool visibility, stage-release writes it only
to the staged environment, and Compose forwards it only to API with a default
of false. A follow-up authority correction removes ambient shell overrides,
checks target/state/staged pins on every later phase, and verifies rendered and
running API values before reopening. Worker execution remains independent of
the visibility flag. This fix awaits review and a new Delivery-attested release;
`549b19f` must not be used for deployment. The `0020` → `0021` migration path and
the separate pilot-launch gates below are unchanged. No VPS was contacted.

- [Architecture, dataset grains, metric definitions and contract](development/pilot-analytics.md)
- [Golden workflows and demo script](runbooks/pilot-analytics-demo.md)
- [ADR-027: grounded analytics and immutable summary handoff](adr/ADR-027-grounded-pilot-analytics.md)
- [Inspection and implementation note](development/m12c-implementation-note.md)
- [Validation and browser evidence](evidence/m12c/validation.md)
- [Demo-tool rollout correction and local validation](evidence/m12c/demo-tool-enablement.md)

## Status

| Field | Value |
|---|---|
| Current phase | **Phase 2 foundations** (branch `feat/phase2-foundations`, local, awaiting review). The controlled staging pilot runs on synthetic data only; **customer-data ingestion is planned, not available** (only a library layer exists, reachable from no API, worker or planner). |
| Current milestone | Phase 2 prerequisites from the Phase 2 plan (Edition 2): B01 workspace-creation grants and B02 outcome events implemented locally; B03 code parts done, real-provider DR drill not run; B04 library layer only. See the *Phase 2 foundations* section above. |
| Completed milestones | M0 · M1a · M1b · M2a · M2b · M3 · M4 · M5 · M6 · M7 · M8 · M9 · M10 · M11 · M11.5 (P0 · P1A–P1D · P2 · P3A · P3B) · M12A-Prep · M12B · M12C (staging pilot rollout) |
| Deployed staging (historical fact) | Release `b1a3058` (PR #40, merged 2026-09-27) at schema `0021_analytics_handoff`, rolled out with `python -m nlw.ops.rollout` through `go-check`, which returned **M12 GO check: PASS** against the checks it implements. Alerting (reported operational evidence, owner, 2026-09-29): the operator-owned receiver `slack-ops` with a recorded, human-confirmed controlled delivery — not the committed null receiver. Planner (reported, owner, sanitised runtime inspection): provider `anthropic`, model `claude-haiku-4-5-20251001`. Backup timer (`nlw-backup.timer`) not installed at rollout time (needs root). |
| Configuration inconsistency | The source default `llm_model = "claude-sonnet-5"` (`core/config.py`) differs from the deployed model, which `docker-compose.prod.yml` supplies (`NLW_LLM_MODEL` default `claude-haiku-4-5-20251001`). On `feat/phase2-foundations`, staging/production refuse to start an anthropic planner without an explicit, non-blank `NLW_LLM_MODEL`, so the source default can no longer be used silently there. Under Compose that value always comes from `.env.prod` or, if unset there, the reviewed `docker-compose.prod.yml` pin; the reviewed rollout unsets `NLW_LLM_PROVIDER`/`NLW_LLM_MODEL`/`NLW_LLM_API_KEY` from the operator shell so neither can be replaced silently. |
| Not enforced by `go-check` | Post-rollout drills in [real-vps-checklist](staging/real-vps-checklist.md): key rotation, k6 and failure drills, the **real-provider isolated fresh-host DR drill** (not run; a Phase 2 prerequisite before any customer data, B03), reboot, real Slack delivery. |
| Release status | **Controlled pilot on staging, synthetic data, invitation-only** — not a launched production platform. See *Open risks* and *Known technical debt* below. |

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
self-scoped step after the identity context is established (verified provider
email only; since `0016` the self policy keys on the signed `ctx_user_id()`).
The stable `auth_provider_id` is never writable by the app role. So the runtime
role can no longer enumerate or rewrite unrelated identities. (Honest boundary at
the time: a caller able to forge complete DB context stayed in the signed-GUC
scope — now closed by P3B/ADR-024.)
**connectors:** creation + credential-alias attachment is now admin/owner-only in
both the API (`require_role(ADMIN)`) and RLS (`connectors_app_insert` now checks
`is_current_user_admin_or_owner`); members keep read-only, secret-free access.
`secret_ref` remains absent from all member-facing responses, planner context,
plans, step state, approvals, logs and errors. Deferred at the time: signed DB
context (delivered by P3B, ADR-024), team invitations (delivered by P3A,
ADR-023); still deferred: cloud/encrypted secret storage, self-service secret
onboarding, connector→credential-entity binding (see ADR-003/006/011).

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
Deferred at the time: signed GUC (delivered by P3B), invites (P3A), DR (P2);
still deferred: HttpOnly sessions, cloud secrets, PITR, M12.

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
rejected even by an owner and even via direct SQL. **DB-level immutability
(defence in depth):** `BEFORE UPDATE` triggers freeze `approvals.requested_by_user_id`,
`workflow_runs.initiated_by_user_id`, `schedules.created_by`, and the first terminal
approval decision — closing gaps where `nlw_worker`/`nlw_app` table-level UPDATE
could otherwise rewrite provenance or flip a decided approval. **Membership mutation
is function-only:** `nlw_app` has no direct UPDATE/DELETE on `memberships`; role
changes/removals go through the `manage_membership` SECURITY DEFINER function —
owned by a dedicated NOLOGIN `nlw_membership_admin` role whose only privileges are
memberships DML + audit INSERT (proven by direct grant tests) — which serializes on
the workspace identity FIRST then re-reads ownership under the lock, so the owner
invariant is correct by construction (no READ COMMITTED write skew), not merely
trigger-guarded. The P2 restore validation additionally verifies these P3A objects
(invitation/audit ownership + RLS + constraints + grants, provenance triggers, the
membership-admin least-privilege owner, hardened `search_path`, no PUBLIC EXECUTE)
survive an encrypted backup/restore. **Append-only `authz_audit_events`** records invite /
membership / approval events (requested/approved/rejected) in the same transaction as
each committed transition, with no tokens/secrets and no UPDATE/DELETE for runtime
roles (verified by the P2 restore validation). A minimal Next.js product flow
(members roster + role/remove, invitation create/revoke/accept, requester-aware
approvals) rides on top. Honest boundary at the time: P3A did not close the
**forgeable-GUC** threat (an SQL attacker as `nlw_app` forging `app.user_id`) —
that was **P3B (signed context)**, a launch gate, now implemented (next paragraph).
Docs: runbooks/invitation-operations, approval-operations.

M11.5 P3B (signed database context, migration `0016`, ADR-024) closes the
forgeable-GUC launch gate. Every tenant-aware transaction now carries a
**signed, purpose-bound, expiring** transaction-local context (`app.ctx_v`,
`ctx_kid`, `ctx_role`, `ctx_purpose`, `ctx_user`, `ctx_tenant`, `ctx_run`,
`ctx_iat`, `ctx_exp`, `ctx_nonce`, `ctx_mac`) whose HMAC-SHA256 tag PostgreSQL
recomputes inside the single SECURITY DEFINER verifier `app_ctx_claims()`
(owner: the NOLOGIN NOSUPERUSER NOBYPASSRLS `nlw_ctx_verifier`; pgcrypto;
canonical length-prefixed message; constant-time compare; checks version, active
key of the right class, `ctx_role = session_user`, purpose ↔ login role, claim
shape, ≤ 60 s skew, expiry, 1–600 s lifetime). RLS trusts **only** the verified
accessors `ctx_user_id()` / `ctx_tenant_id()` / `ctx_run_id()` / `ctx_purpose()`:
all 51 policies and the membership/bootstrap helpers were rewritten atomically,
scheduler policies require `ctx_purpose() = 'scheduler_reconcile'` (no more
`USING (true)`), worker policies bind tenant **and** run, `manage_membership`
also requires an `api_request` context for that workspace, and the dead
`is_current_user_owner` oracle was dropped. Four purposes bind each runtime to
one login role: `api_identity`/`api_request` → `nlw_app`, `worker_execution` →
`nlw_worker`, `scheduler_reconcile` → `nlw_scheduler`. Keys live in the
`ctx_keys` registry (owned by the verifier role, **no grants to any login
role**, lifecycle audited in `ctx_key_events` without material) and are
installed from mounted files by `python -m nlw.ctxkeys install|revoke|list|check`
with the owner credential; runtimes load their own key file (`NLW_CTX_KEY_ID`,
`NLW_CTX_KEY_FILE`, `NLW_CTX_TTL_S` ≤ 600, default 120) and prove at readiness
(`signed_context`) that the database verifies their key — fail closed in
staging/production. Pool reset clears context; there is no unsigned fallback
(until keys are installed every tenant query is denied). Backup validation
gained `pgcrypto_present`, `ctx_keys_registry_protected`,
`ctx_verifier_functions_hardened`, `no_policy_trusts_unsigned_context`. Honest
boundary: HMAC is **symmetric** — the registry material is signing-capable, and
"verify-only" describes the helper interface, not the key. Protected: SQL
injection or a stolen runtime DB credential *without* the key file. **Not**
protected: a runtime compromised together with its key, the owner/migration
credential, bypass roles, superuser, host root. Downgrading below `0016`
re-opens forgery; a runtime/DB version mismatch fails closed (outage, never open).
Tests: 27 adversarial integration tests + golden vectors + Compose key isolation.
Docs: ADR-024, runbooks/signed-context-keys.md.

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
idempotent and audited via `dr_restore_events` (outside RLS; runtime roles cannot
write it). A
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
preflight (API lifespan, scheduler main, worker `before_worker_boot` raising the
framework-fatal `WorkerBootRefused(MiddlewareError)` so Dramatiq aborts before any
consumer thread starts) that fails closed unless the newest restore generation is
operator-enabled — regardless of `NLW_RESTORE_MODE`, profile, or file; the
container healthcheck also fails on the lock, so a restart-looping worker is never
reported healthy. A separate `nlw.backup enable-runtime`
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
runbooks (ADR-018). A signed DB context (since delivered by M11.5 P3B,
ADR-024 — symmetric HMAC, deliberately not described as "non-forgeable"), a cloud
secret manager, and OTel/Langfuse (still not implemented) were recorded as
explicit pre-production items.

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
(gated by role **and** an RLS admin/owner + `decided_by = app.user_id` check —
since `0016`: `decided_by = public.ctx_user_id()`, the signed context, ADR-024),
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
`plan_proposals` audit row that stores **no raw provider response** (since
M12B-A / migration `0017` it does store the bounded natural-language request as
tenant-scoped, immutable, never-logged provenance — see
`architecture/ai-provenance-and-stale-plan.md`). `POST /plans/{id}/materialize` re-earns PASS against
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
bootstrap, two transaction-local GUCs `app.user_id`/`app.tenant_id` [replaced
in M11.5 P3B by the signed `app.ctx_*` context, ADR-024], RLS policies, and a
raw-SQL cross-tenant probe — ADR-003). With M2b, tenant isolation is enforced by
the database, not just the application.

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
| M11 | Staging + CD + load/failure testing | delivered | ADR-020 |
| M11.5 | Pre-M12 hardening from external reviews (P0 credential isolation · P1A–D authorization, SQL/egress, action delivery, scheduler · P2 encrypted off-host backup/DR · P3A membership/approval SoD · P3B signed DB context) | delivered | ADR-021, ADR-022, ADR-023, ADR-024 |
| M12A-Prep | Attested release manifests + phased, gated rollout tooling | delivered | ADR-025 |
| M12B | AI core production readiness (provenance, transmission boundary, connector binding, schedule authorization, deterministic summaries, eval v2) | delivered | ADR-026 |
| M12C | Controlled pilot launch (staging, synthetic data) | delivered (`b1a3058`, go-check PASS) | ADR-027 |
| Phase 2 | Customer-data platform (plan Edition 2) | in progress: `feat/phase2-foundations` (local) | ADR-023 amendment 1, ADR-028 |

**First-release connector scope:** PostgreSQL (source), Webhook + Slack (actions).
Demonstration workflow target:
`Postgres → deterministic condition → optional LLM processing → Slack/Webhook`.

## Architecture docs

- [`docs/architecture/`](architecture/) — `overview.md` (living shape + boundaries),
  the AI-core audit / recovery / observability matrices, `ai-provenance-and-stale-plan.md`,
  `schedule-authorization.md`, and the system diagram in `img/architecture.svg`
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
- [ADR-024 — Signed database context (M11.5 P3B, migration `0016`)](adr/ADR-024-signed-database-context.md)
- [ADR-025 — Release-manifest provenance (M12A-Prep)](adr/ADR-025-release-manifest-provenance.md)
- [ADR-026 — AI execution architecture (M12B-A): deterministic engine with an LLM planner](adr/ADR-026-ai-execution-architecture.md)
- [ADR-027 — Grounded pilot analytics](adr/ADR-027-grounded-pilot-analytics.md)
- [ADR-028 — Redacted plan outcome events (Phase 2 B02)](adr/ADR-028-plan-outcome-events.md)

Planned: ADR-008 Deployment strategy.

## M12B-A — AI core production readiness (evidence-first audit + bounded corrections)

Evidence-first audit and bounded hardening of the applied-AI core (the LLM
planner → deterministic feasibility → durable execution → grounded result path).
The architecture is a **deterministic workflow engine with an LLM planner**
(ADR-026): the model proposes one structured plan; deterministic code owns every
verdict and re-validates tools/args/connectors/approval at execution. Delivered:

- **Audit + findings**: [AI-core architecture & failure-mode audit](architecture/ai-core-audit.md)
  (severity-ranked, reproduced) and the [checkpoint/recovery matrix](architecture/ai-core-recovery-matrix.md).
- **Deterministic evaluation harness** (`nlw.eval`): a 34-case, versioned,
  synthetic corpus across all 20 planning/policy categories, graded against the
  real registry + feasibility engine; deterministic replay in CI + an optional
  credential-gated live-model mode. See [ai-evaluation](development/ai-evaluation.md).
- **Planner/feasibility hardening**: serialized plan/arg **byte bounds**
  (`PLAN_TOO_LARGE`/`ARGS_TOO_LARGE`), a deterministic **prompt/context budget**
  (`nlw.planner.budget`), and run/step **transition guards**
  (`assert_transition_*`) wired into the engine (which surfaced and fixed a
  missing `PENDING → FAILED` edge).
- **Prompt-injection & untrusted-data boundary**: an explicit
  [prompt-construction contract](security/planner-prompt-contract.md) plus
  adversarial tests proving untrusted content cannot add tools, alter
  authorization, bypass approval, or substitute a tenant/connector.
- **Grounded result synthesis** (`nlw.engine.summary`, `GET /runs/{id}/summary`
  + a run-detail UI panel): a deterministic, non-LLM summary that never reports
  FAILED/SKIPPED/UNKNOWN as success.
- **AI observability**: low-cardinality planner/feasibility/summary metrics.

Boundaries respected: no VPS/provider access, no production keys, no deployment,
restore, reboot, or real Slack/webhook delivery. No conversation memory was
added (single-shot planning is deliberate).

**M12B-A final-evidence addendum**: durable request→plan provenance
(`plan_proposals.request_text` + sha256 + contract version; RLS, immutable,
never logged/listed; [provenance + STALE doc](architecture/ai-provenance-and-stale-plan.md)),
a stable `STALE_PLAN`/`POLICY_DENIED`/`INVALID_PLAN` re-validation boundary
(`nlw.feasibility.revalidation`) gating run-creation + materialize fail-closed,
executed recovery-boundary evidence for all ten scenarios
(`tests/integration/test_recovery_boundaries.py`), a credential-gated live-model
benchmark (`nlw.eval.live_runner`; planning only), summary-endpoint
confidentiality (no raw output, tenant-scoped, frontend injection-safe), and an
[observability coverage matrix](architecture/ai-observability-matrix.md).
The live-model benchmark was executed on 2026-09-22 (claude-haiku-4-5, 34 cases
× 3 repeats = 102 planning-only calls); its sanitized, versioned evidence and the
independent-review caveats on what it does and does not measure live in
[docs/evaluation/](evaluation/README.md).

## Runbooks

- [staging-signed-context-rollout](runbooks/staging-signed-context-rollout.md) — **M12A**: the phased, gated upgrade of the staging VPS from schema `0010` to `0016` (`python -m nlw.ops.rollout --release <CI manifest>`; read-only default; verify-release, authorization, escrow and backup-before-mutation gates; the CI-generated, **attested** `release-manifest-<sha>` artifact + `deploy/staging/target.env` are the identity source — `deploy/staging/release.example.json` is a rejected template; provenance: [ADR-025](adr/ADR-025-release-manifest-provenance.md)). Rehearsal: `scripts/ops/rehearse-0010-to-0016.sh`. Alerting boundary: [docs/ops/alerting](ops/alerting.md).

- [workspace-creation-grants](runbooks/workspace-creation-grants.md) — **Phase 2 B01**: issue, list and revoke operator grants for founding a workspace; emergency `WORKSPACE_CREATION_MODE=closed`.

[`docs/runbooks/`](runbooks/) — see its [README](runbooks/README.md) for the
index. Security-sensitive: [signed-context-keys.md](runbooks/signed-context-keys.md)
(P3B key provisioning, deployment order, rotation, emergency revocation, rollback
warning).

## Incidents

[`docs/incidents/`](incidents/) — real postmortems only. None.

## Open risks

- **Forgeable GUC context — closed by M11.5 P3B (migration `0016`, ADR-024;
  merged to `main`).** RLS now trusts only the signed `app.ctx_*` claims;
  `app.user_id`/`app.tenant_id` grant nothing. Residual (documented, not claimed
  away): a runtime compromised together with its key file, the owner/migration
  credential, bypass roles, superuser, or host root can still mint or bypass
  context (HMAC is symmetric). Operational: keys must be installed before the
  runtimes start, and downgrading below `0016` re-opens forgery — see
  runbooks/signed-context-keys.md.
- Action connectors (M7) have an unavoidable at-least-once send window on a
  crash between "side effect sent" and "state written." Mitigated with
  idempotency keys and required approvals; documented as a known limitation.

## Known technical debt

Honest, current list (each item is either a documented limitation or a tracked
correction). "Correction pending" items are being fixed in dedicated commits.

- **No OpenTelemetry tracing / Langfuse.** Observability is structured logs
  (structlog) + Prometheus metrics + correlation ids only.
- **Audit log is append-only by grants/policies, not tamper-evident.**
  `authz_audit_events` has no UPDATE/DELETE for runtime roles, but it is not
  hash-chained or signed; the owner/superuser can rewrite it. It is a separate
  control from the signed database context (ADR-024).
- **At-least-once external delivery.** A terminal `UNKNOWN` stops *automatic*
  re-sends after an ambiguous transmission; it does not guarantee the receiver
  performed no duplicate effect (Slack `chat.postMessage` has no idempotency key
  at all) — ADR-013.
- **Symmetric signed context.** The HMAC key is signing-capable; a runtime
  compromised together with its key file, the owner credential, bypass roles,
  superuser or host root can mint context (ADR-024).
- **Legacy workflow versions predating `0019`** are name-resolved, not
  identity-pinned, until re-materialized (the rollout go-live report counts them).
- **Rollout tooling binds the active checkout by configuration.**
  `deploy/staging/target.env` names it explicitly — `/opt/nlw/current` since the
  first staging rollout completed (schema `0020`); every phase reads, stops and
  clones through `current`, fetches the release SHA from `NLW_STAGING_GIT_REMOTE`
  and re-points `current` on activation (rehearsed N → N+1). Mismatches between
  the target and the host layout fail closed. Code-only releases (no new
  migration, `expected_current_revision == target_revision`) are supported:
  `migrate` is a verified no-op and every other gate applies unchanged.
- **Operator Alertmanager authority is host-side, named in `target.env`.**
  The receiver config, its credential files (`root:65534 0750/0640` — Alertmanager
  runs as uid 65534) and the Compose override live outside every checkout;
  `reopen`/`go-check` evaluate the RUNNING container (mounts, mounted bytes,
  loaded config), never the committed null file. The delivery record stays a
  human-written file (`scripts/ops/record-alert-delivery.sh`, `root:nlwops 0640`).
- **Timer backups carry no release binding.** The rollout's `backup` phase binds
  instance/environment/release per run; systemd-timer backups bind only the
  instance/environment set in `.env.backup` (a static release would go stale).
- **`scripts/ops/verify-staging-deployment.sh` inspects `/opt/nlw/app`** and
  FLAGs the SHA/pins after activation; the rollout's `validate`/`go-check`
  evidence is authoritative until it is updated.
- **Deferred:** cloud/encrypted secret storage and self-service secret onboarding,
  HttpOnly/opaque sessions, PITR, typed step-output references, additional
  connectors.
