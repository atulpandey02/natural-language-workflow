# ADR-026 — AI execution architecture (planner/executor, not an agent loop)

Status: accepted (M12B-A) · Date: 2026-09-22 · Relates to: ADR-006 (tool registry), ADR-013 (at-least-once delivery), ADR-024 (signed database context), M6 planner, M7 approvals, M9 durability

## Context

The product's core is an applied-AI workflow engine:

```
natural-language request → safe context construction → structured planning
→ feasibility/policy validation → approval/scheduling → durable queue execution
→ tool invocation → checkpoints/recovery → (grounded result synthesis)
```

M12B-A audited the real implementation to answer, precisely, how the model
participates and where authority lives, so future work does not accidentally
turn a deterministic engine into an autonomous agent. This ADR records the
architecture as built and the invariants that must not regress.

## Decision — the architecture, stated precisely

**This is a deterministic workflow engine with an LLM *planner*. It is not an
agent loop and the model never dynamically calls tools.**

1. **One-shot structured planning.** `POST /plans` builds a deterministic,
   tenant-scoped capability view (Tool Registry filtered to the tenant's usable
   connectors, secret-free) and asks the provider for exactly one structured
   `PlannerOutput` (`src/nlw/planner/schema.py`), forced through the provider's
   structured-output path (`anthropic_provider.py` uses a single tool whose
   input schema *is* the `PlannerOutput` JSON schema). The model returns data,
   not actions. There is no tool-call/observe/re-plan loop, no scratchpad, no
   model-driven control flow.

2. **Deterministic feasibility owns the verdict.** `check_plan`
   (`src/nlw/feasibility/engine.py`) is pure Python. It assigns the final
   status — `PASS` / `REJECT` / `NEEDS_CLARIFICATION` / `NEEDS_APPROVAL` — with a
   machine-readable finding list. A parsed plan is never executable merely
   because it parsed. The model's `clarification_needed` is an advisory request,
   never the final status.

3. **Persist, then re-validate on materialize.** A `PlanProposal` is an
   immutable audit snapshot (no raw provider bytes — the parsed proposed plan,
   the normalized plan, the feasibility report and, since migration `0017`, the
   bounded natural-language request itself with its sha256 digest and planner
   contract version: tenant-scoped, immutable to the runtime role, never
   logged/metered/listed — see `ai-provenance-and-stale-plan.md`). `POST /plans/{id}/materialize` **re-runs feasibility
   against current tenant capabilities** ("never trust the stored PASS") before
   writing an immutable `WorkflowVersion`.

4. **Execution is a separate durable engine.** A run executes the persisted
   `WorkflowVersion.plan`. Postgres is the system of record; Redis/Dramatiq is a
   wake-up signal carrying only `run_id`. Every advancement re-loads
   authoritative state under `SELECT … FOR UPDATE` on the run row and, for each
   step, **re-fetches the `ToolSpec` from the registry by name and re-validates
   the arguments** (`engine/execution.py`, `engine/actions.py`). Connectors are
   loaded by tenant-scoped SQL; approval is derived from the registry spec, not
   the plan; side effects are pinned to the approved connector id.

### Where model output can and cannot reach

| Model may influence (as a *proposal*) | Re-validated deterministically by |
|---|---|
| tool name | capability view + feasibility `UNKNOWN_TOOL`/`TOOL_NOT_AVAILABLE`; registry re-fetch at execution |
| step args | tool `input_model` at feasibility **and** at execution |
| connector *name* | tenant-scoped connector load; type/ownership/status checks |
| SQL text (`postgres.query`) | `validate_select` (sqlglot allowlist) at feasibility **and** inside the tool |
| `depends_on` graph | DAG/cycle/reference checks |
| Slack `channel` | strict channel-id pattern + connector allowlist at send time |

**Model output can never**: add a tool outside the registry, choose a connector
outside the workspace, mark an approval-gated action approval-free (approval
comes from `ToolSpec.requires_approval`), set/alter retry or idempotency policy,
supply a secret value, or change a persisted plan after materialization
(versions are immutable; a new plan is a new version).

### Recovery boundary

Everything needed to reconstruct a run lives in Postgres: the immutable
`workflow_versions.plan`, `step_runs` (status/input/output/attempt), the
`external_actions` lease + stable `external_action_key`, `approvals`, and the
run row (`status`, `last_progress_at`). No in-memory conversation or agent state
is required to recover. The reconciler re-derives what to enqueue from SQL and
writes nothing. Completed (`SUCCESS`) steps are never re-run (`select_next_step`
only returns a `PENDING` step whose deps are all `SUCCESS`).

**What cannot be resumed automatically, by design:** an external action whose
outcome is `UNKNOWN` (it may have transmitted; it is terminal `FAILED` with the
`ACTION_OUTCOME_UNKNOWN` class and is never resent), and runs past the recovery
horizon (surfaced to an operator, never auto-failed, never blindly re-enqueued).

### Synthesis and memory (as built, then extended by M12B-A)

- **No LLM result-synthesis stage exists at execution time**; the product
  exposed only bounded per-step output previews. M12B-A adds a *deterministic,
  non-LLM* grounded run summary (never converts `FAILED`/`UNKNOWN` into success;
  no model call, no tool call, no state mutation). An optional LLM synthesis
  stage is explicitly out of scope here and, if ever added, must consume only
  persisted/bounded/redacted step outputs and keep the deterministic summary as
  the authoritative fallback.
- **No conversation memory exists and none is added.** Planning is single-shot;
  `clarification_questions` are surfaced but there is no answer-feedback turn and
  no chat history. This is a deliberate product decision, not an omission (see
  the audit, Part G). If iterative refinement is ever needed, memory must be
  workspace/user-scoped, bounded, retention-defined, deletion-capable, and
  treated as untrusted context when reinserted.

## Consequences

- The LLM is a **planning-time convenience**, not part of the trusted computing
  base. Turning off the provider (the default `stub`) degrades planning to
  "ask for clarification," never to an unsafe execution.
- New tools must declare `requires_approval`, `side_effecting`, `connector_type`
  and a strict `input_model`; execution authority stays in the registry and the
  connector validators, never in prompts or model output.
- Any future "agentic" feature (model choosing the next tool from a result) is a
  new architecture and a new ADR; it may not be introduced by widening the
  planner or by feeding tool output back into the model without a separate,
  reviewed untrusted-data boundary.
