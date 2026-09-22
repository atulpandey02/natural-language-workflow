# AI-core architecture & failure-mode audit (M12B-A)

Evidence-first audit of the real request→result flow. Every claim cites
`file:line`. Companion decision: [ADR-026](../adr/ADR-026-ai-execution-architecture.md).
Findings are severity-ranked in the last section; corrections landed in M12B-A
are marked ✅, deliberate non-actions ⓘ, and deferred items ⏳.

## 1. The real flow, stage by stage

| stage | authoritative in/out schema | persisted vs transient | trust boundary | deterministic checks | LLM role | recovery boundary | tenant/actor context | failure/retry | observability |
|---|---|---|---|---|---|---|---|---|---|
| **Request intake** (`api/routers/plans.py:88`) | in: `PlanRequest.prompt` (str) | transient — prompt never persisted; only `prompt_len` (`plans.py:147`, `db/models.py:353`) | user input is untrusted | length ≤ `llm_max_prompt_chars=8000`, non-empty (`plans.py:100-107`) | none | n/a (no run yet) | `TenantContext` from JWT+workspace (`deps.get_tenant_context`) | 422 on oversize/empty | `nlw_plans_total`, `planner.request` log (no raw prompt) |
| **Context construction** (`planner/capabilities.py`, `planner/prompt.py`) | out: `CapabilityView` (tools+SafeConnector) | transient | registry+connector metadata are trusted; connector `name`/`schema_hint` are tenant-authored (semi-trusted) | secret-free projection by construction (`capabilities.py:1-12`, proven `test_planner_security.py`) | none | n/a | RLS-scoped connector list (`ConnectorRepository.list_for_tenant`) | n/a | `planner.request` |
| **Planning** (`planner/planner.py:34`, provider) | out: `PlannerOutput` strict, `extra=forbid`, bounded (`schema.py`) | transient (raw JSON parsed, never stored) | **the model boundary** — output is untrusted | strict Pydantic parse → `LLMInvalidOutputError` → deterministic `PLANNER_INVALID_OUTPUT` REJECT (`provider.py:parse_planner_output`, `planner.py:60-67`) | proposes plan only | n/a | platform LLM key is API-process only (`config.py:48-50`) | infra faults → 5xx (not REJECT); bad output → REJECT | `nlw_planner_latency_seconds`, token counts logged |
| **Feasibility** (`feasibility/engine.py:check_plan`) | in: `WorkflowPlan`+`CapabilityView`+`PlatformLimits`; out: `FeasibilityReport` | proposal persisted (`plan_proposals`) | deterministic verdict owner | tool availability, connector type/ownership/status, arg `input_model`, SQL `validate_select`, DAG/cycle, step/total timeout, approval, clarification (`engine.py:305-470`) | none (verdict is pure Python) | n/a | capability view is tenant-scoped | never raises on a bad plan | `feasibility.check` log (status, failure codes) |
| **Materialize** (`plans.py:206`) | out: immutable `WorkflowVersion.plan` | persisted | re-validation gate | **re-runs `check_plan` against current capabilities** (`plans.py:238-256`); PASS/NEEDS_APPROVAL only; per-tenant workflow cap | none | idempotent (returns existing version) | tenant-scoped; advisory-locked cap | 409 if no longer materializable | `plan.materialize` log |
| **Run creation** (`workflows.py:132`, scheduler) | out: `WorkflowRun` PENDING | persisted | commit-before-enqueue | idempotency-key unique; reserved `sched:` prefix; version pinned | none | durable PENDING recoverable if enqueue fails (503) | `initiated_by_user_id` from JWT (never request JSON) | 503 → reconciler re-drives | `run.manual_created` |
| **Durable execution** (`engine/execution.py`, `engine/actions.py`, `worker/actors.py`) | in: persisted plan+step states; out: `step_runs.output` | persisted (source of truth) | Redis = wake-up only; Postgres authoritative | run-row `FOR UPDATE`; per-step registry re-fetch + arg re-validate (`execution.py:582-583`, `actions.py:109-111`); connector tenant-scoped load; approval from registry; post-approval connector pinning (`execution.py:288-289`) | none | full state in Postgres; reconciler re-derives; SUCCESS steps never re-run | signed DB context per class (P3B) | infra retry (Dramatiq ×5) + business action retry (≤5, UNKNOWN terminal) | `nlw_advance_*`, `nlw_tool_*`, `nlw_action_attempts_total`, `nlw_run_completion_seconds` |
| **Approval wait** (`execution.py:436`, `approvals.py`) | `Approval` row | persisted | human gate; four-eyes SoD (P3A) | requester from run provenance; self-approval denied; decision CAS (`repositories.py:401-444`) | none | reconciler resumes decided-but-lost | admin/owner decides; requester ≠ decider | 503 if resume enqueue fails | `authz_audit` events |
| **Result presentation** (`runs.py`) | out: `RunOut`/`StepRunOut`/`ExternalActionOut` | reads persisted | secret-free previews | bounded output preview `_OUTPUT_PREVIEW_CAP=4000` (`runs.py:29,36-42`); secrets never exposed | none | n/a | tenant/RLS-scoped, paginated | n/a | — |
| **Grounded summary** (M12B-A, `engine/summary.py`) | out: deterministic `RunSummary` | derived on read | non-LLM, no state mutation | never converts FAILED/SKIPPED/UNKNOWN→success; bounded | none (deterministic) | n/a | tenant-scoped read | pure function | `nlw_run_summary_total{outcome}` |

## 2. The explicit questions, answered

- **Agent loop, planner/executor, or deterministic engine with an LLM planner?**
  A **deterministic workflow engine with an LLM planner.** One structured
  planning call; deterministic feasibility owns the verdict; a separate durable
  engine executes an immutable persisted plan. No tool-call/observe/re-plan loop.
- **Does any model dynamically call tools?** No. The model emits a data-only
  `PlannerOutput`; deterministic code executes. The Anthropic provider uses a
  single "emit plan" tool purely to force structured output
  (`anthropic_provider.py:_PLAN_TOOL_NAME`), not to invoke product tools.
- **Where can model output influence tool names/args/connectors/SQL/URLs/approvals/schedules/retry?**
  Only as a *proposal*, all re-validated deterministically (see ADR-026 table).
  URLs/webhook targets/Slack tokens live in connector config, not step args
  (`action_schemas.py`); approvals come from the registry; retry/idempotency
  policy is code+DB, never plan-authored; schedules are a separate structured
  API (`schedules.py`), not planner output.
- **What state suffices to reconstruct a run after process death?** The immutable
  `workflow_versions.plan` + `step_runs` + `external_actions` (lease + stable
  `external_action_key`) + `approvals` + `workflow_runs` (`status`,
  `last_progress_at`). No worker memory.
- **What cannot currently be resumed safely?** An `UNKNOWN` external action
  (terminal `FAILED`, never resent) and runs past the recovery horizon (operator
  action). Both are deliberate, documented, and tested.
- **Is there a final AI synthesis stage?** Not originally — only bounded step
  previews. M12B-A adds a *deterministic* grounded summary (no LLM).
- **Conversation memory?** None. Planning is single-shot; clarification
  questions have no feedback turn. Documented honestly; not added (Part G).

## 3. Severity-ranked findings

Reproductions are the tests named in each row (added in M12B-A unless marked
existing).

| # | sev | finding | evidence / reproduction | disposition |
|---|---|---|---|---|
| F1 | **Medium** | Plan/argument **serialized size was unbounded**. `PlannerStep.args`/`WorkflowStep.args` are `dict[str, object]`; `EchoArgs`/`static.echo` use `extra="allow"`; only SQL and webhook/slack bodies had size limits. A 50-step plan with multi-MB generic args passed schema and would be written to `workflow_versions.plan` and `step_runs.input`. Part C requires serialized bytes bounded. | `test_feasibility_limits.py::test_oversized_plan_bytes_rejected`, `::test_oversized_single_arg_rejected` | ✅ fixed: `MAX_PLAN_BYTES`/`MAX_STEP_ARGS_BYTES` bound in feasibility (`PLAN_TOO_LARGE`, `ARGS_TOO_LARGE`) |
| F2 | **Medium** | **No grounded run summary + no deterministic fallback.** Product exposed raw per-step previews only; nothing distinguished SUCCESS/FAILED/UNKNOWN/SKIPPED at run level. Part H requires at least a deterministic non-LLM grounded summary that never reports UNKNOWN/FAILED as success. | `test_run_summary.py` (hallucinated-success/partial-failure/UNKNOWN/oversized cases) | ✅ fixed: `engine/summary.py` + `GET /runs/{id}/summary` |
| F3 | **Medium** | **AI-specific observability gaps.** No counters for schema-invalid plans, feasibility outcome by stable reason, plan step-count/size, planner token usage, or synthesis outcome. Part I requires these (low-cardinality). | `test_ai_metrics.py` | ✅ fixed: metrics added (Part I) |
| F4 | **Low** | **Deterministic context budgeting incomplete.** User-request chars, output tokens and step count were bounded, but the number/total size of tool descriptions and the total serialized prompt were not. Part G. | `test_prompt_budget.py` | ✅ fixed: deterministic prompt/tool-description budget (never truncates security-critical schemas; rejects instead) |
| F5 | **Low** | **Domain transition guards unused as a gate.** `can_transition_run/step` were tested in isolation but never called from engine write paths; legality rested on code structure + DB CHECK constraints. Wiring the guard also revealed a genuinely missing table edge — `PENDING → FAILED` (a step can fail before it is marked RUNNING) — which the engine performs but the table omitted. | `test_transition_guard.py` + the existing engine/crash integration suite | ✅ fixed: `IllegalTransitionError` + `assert_transition_run/step` (self-edge allowed) routed through guarded setters at every engine status assignment; missing `PENDING → FAILED` edge added (behavior-preserving) |
| F6 | **Low/ⓘ** | **Indirect-injection surface via connector `schema_hint`/`name`.** These are tenant-authored strings placed in the planner prompt. Not a bypass (deterministic validation downstream), but the prompt contract should mark them untrusted and prove a malicious hint cannot change authorization or tool selection. Part D. | `test_injection_boundary.py::test_malicious_schema_hint_cannot_change_authorization` | ✅ fixed: explicit contract doc + adversarial tests |
| F7 | **Low/⏳** | **No unified `STALE_PLAN` outcome.** Execution re-validates against authoritative state, and a connector removed/disabled between materialize and run yields a clean deterministic REJECT/step-failure (no partial side effect), but there is no single stable `STALE_PLAN` status surfaced. Also note the app role cannot disable/delete a connector (no privilege), so the realistic stale path is operator-driven. Part E lists the enum as desired. | `test_stale_plan.py` | ✅ reproduced + deterministic clean re-validation proven (materialize + worker re-check); explicit `STALE_PLAN` enum surfacing deferred (documented) |
| F8 | **Info/ⓘ** | **No conversation memory.** Single-shot planning; clarification has no feedback loop. | audit §2 | ⓘ intentional — not added (Part G) |
| F9 | **Info/⏳** | **UI: original request not shown; no summary view.** The NL request is client-only; run detail listed raw JSON previews. | observability agent map | ✅ grounded summary endpoint + minimal run-detail summary panel added; ⏳ persisting/displaying the original NL request deferred (it is deliberately not stored today) |

## 4. What is already strong (verified, not rebuilt)

Confirmed by existing tests and re-read in the audit; M12B-A adds regression
coverage but changes nothing here:

- Strict, bounded planner schema; deterministic verdict; re-validation on
  materialize (`test_plans_api.py`, `test_feasibility_engine.py`).
- Execution-time re-fetch of the registry spec + arg re-validation; connector
  loaded by tenant-scoped SQL; approval from registry; post-approval connector
  pinning (`test_engine_execution.py`, `test_action_execution.py`,
  `test_connector_authz.py`).
- SQL allowlist safety; SSRF/URL guard; webhook/Slack destination validation
  (`test_planner_security.py`, `test_http_action.py`, `test_postgres_connector.py`).
- Durable recovery, crash windows, lease/idempotency, UNKNOWN semantics,
  scheduler fairness/horizon (`test_crash_windows.py`,
  `test_action_unknown_outcome.py`, `test_action_lease_safety.py`,
  `test_scheduler_reconcile.py`).
- Secret non-exposure to the model; raw prompt/response never stored
  (`test_planner_security.py`).
