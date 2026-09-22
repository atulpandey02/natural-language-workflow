# Request provenance & the STALE_PLAN boundary (M12B-A addendum)

## 1. Request-to-plan provenance (Part 1)

The natural-language request is the business input that caused a workflow to
exist, so it is durably bound to the plan it produced — on the **existing**
`plan_proposals` audit row (no new table), which already binds
request → proposed plan → feasibility decision → materialized version.

### Schema (migration 0017, additive to `plan_proposals`)

| column | type | notes |
|---|---|---|
| `request_text` | `text` (nullable) | the original request, bounded to `llm_max_prompt_chars` (8000) **before** persistence and before the model call |
| `request_sha256` | `varchar(64)` | sha256 of the request bytes (unnoticed-mutation detection) |
| `planner_contract_version` | `varchar` | the planner schema + prompt-contract version (`PLANNER_CONTRACT_VERSION`) that produced the plan |

Already on the row: `created_by`, `tenant_id`, `provider`, `model`, `status`
(feasibility outcome), `proposed_plan`, `normalized_plan`, `feasibility`,
`workflow_version_id`, `created_at`.

### Authorization & confidentiality

- **Tenant RLS** (unchanged from migration 0007): a proposal is visible only to
  members of its tenant; another tenant gets 404 on the detail and provenance
  endpoints.
- **Immutable after creation**: `nlw_app` holds only
  `UPDATE(workflow_version_id, updated_at)`, so `request_text` can never be
  updated after INSERT (the column-privilege check fires before RLS). A revised
  request is a NEW proposal → a NEW workflow version; history is never rewritten.
- **Never logged, metered, or listed**: logs record only `prompt_len`; no metric
  label carries request text; `GET /plans` (list) omits `request_text`. It is
  returned only on the single-proposal detail (`GET /plans/{id}`,
  `PlanProposalDetailOut`) and the version provenance
  (`GET /workflow-versions/{id}/provenance`) — both to an authorized member only.
- No system prompts, provider credentials, connector secrets, or signing keys
  are ever persisted here.

### Retention / deletion (honest)

`plan_proposals` rows are retained for the life of the tenant; there is no
automatic expiry today. `request_text` is deleted when the proposal row is
deleted, which happens via the tenant/workflow cascade (`workflows` FK
`ondelete=CASCADE` reaches versions; proposals are removed when the tenant's data
is purged). A per-proposal delete endpoint is **not** provided in M12B-A (out of
scope); a future retention policy would add a bounded TTL sweep. This is stated
so operators do not assume request text auto-expires.

### UI

The original request is shown on the workflow detail page (authorized member),
fetched from the version provenance endpoint. It is never shown in list views.

## 2. The STALE_PLAN boundary (Part 2)

A plan that was PASS/NEEDS_APPROVAL when materialized is **re-validated against
current authoritative state** before a run starts and when re-materializing. The
re-validation (`nlw.feasibility.revalidation`) classifies the plan into one
stable, product-level outcome — it is not a rename of connector errors; it is a
classification over the stable `FeasibilityCode` categories.

### Outcomes and the authoritative conditions

| outcome | meaning | conditions (stable reason codes) |
|---|---|---|
| `FRESH` | still executable | PASS or NEEDS_APPROVAL (a *strengthened* approval requirement pauses the run at execution — it never bypasses it) |
| `STALE_PLAN` | was executable, state changed | connector removed / disabled / type-changed / un-owned; tool removed; tool argument schema materially changed (`TOOL_NOT_AVAILABLE`, `UNKNOWN_TOOL`, `CONNECTOR_NOT_FOUND`, `CONNECTOR_TYPE_MISMATCH`, `CONNECTOR_UNUSABLE`, `CONNECTOR_REQUIRED`, `ARG_VALIDATION_FAILED`) |
| `POLICY_DENIED` | forbidden regardless of freshness | SQL-safety rejection (`SQL_REJECTED`) |
| `INVALID_PLAN` | structurally invalid | cycles, dangling refs, size — or a proposal that was never accepted |

### The transition matrix (what it is NOT)

| concept | when | retryable? | surfaced as |
|---|---|---|---|
| `INVALID_PLAN` | malformed when created | no — re-plan | 409 `{error.code: INVALID_PLAN}` |
| `POLICY_DENIED` | forbidden regardless of freshness | no — not permitted | 409 `{error.code: POLICY_DENIED}` |
| `STALE_PLAN` | previously valid; assumptions changed | **no — a new feasibility decision / new version is required** | 409 `{error.code: STALE_PLAN, message: "…re-plan…"}` |
| transient infrastructure fault | provider/DB/queue unavailable | **yes** | 5xx (503/502), never a STALE 409 |
| `ACTION_OUTCOME_UNKNOWN` | an external action may already have transmitted | no — terminal, never resent | run/step FAILED + `unknown` external action |

### Enforcement points (fail closed before any tool runs)

- **Run creation** (`POST /workflows/{id}/runs`): the pinned version's plan is
  re-validated against current capabilities; a non-`FRESH` result returns a
  sanitized 409 and **no run is created** — execution never starts on a stale
  plan.
- **Materialize** (`POST /plans/{id}/materialize`): re-validates the stored
  proposal (already the "never trust the stored PASS" gate), now with the
  classified outcome + reason.
- **Execution** (worker): still re-fetches the registry tool + re-validates args
  and re-loads the connector by tenant-scoped SQL per step, and pins an approved
  action to the approved connector id (P1C) — so even without the pre-run gate,
  a step fails closed rather than invoking an unsafe tool.

The reason exposed to the API/UI is sanitized (a member-safe sentence + a stable
low-cardinality code); connector secrets and internal DB details are never
included. `nlw_stale_plan_total{outcome,reason}` records the block.

The planner can never declare a plan fresh: `FRESH` is only ever the output of
the deterministic re-validation over current authoritative state.
