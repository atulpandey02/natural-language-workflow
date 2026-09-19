# ADR-004 — Planner / feasibility separation (LLM proposes, code decides)

- Status: Accepted
- Date: 2026-09-19

## Context

M6 lets a user describe a workflow in natural language. An LLM must turn that
into a structured plan, but the model can never be trusted to authorize
execution: it must not grant permissions, bypass connector ownership or the Tool
Registry, execute code or SQL, decide tenant isolation, access secrets, or invent
tools. We need a hard boundary between *proposing* and *deciding*.

## Decision

- **The LLM only proposes.** It returns a strict `PlannerOutput`
  (`extra="forbid"`, bounded) which is parsed and converted to the executable
  `WorkflowPlan`. A parse success is **not** authorization.
- **Deterministic code decides.** `nlw.feasibility.engine.check_plan` (pure, mypy
  strict) assigns the final status from an explicit, machine-readable finding
  list. The model's `clarification_needed` is advisory input only.
- **Status enum:** `PASS | REJECT | NEEDS_CLARIFICATION | NEEDS_APPROVAL`, with
  fixed precedence **reject > clarify > approve > pass**.
- **Feasibility stages:** structural (bounds, unique ids, id format) → tool
  availability (Tool Registry projection for the tenant) → connector
  compatibility (ownership/type/status, RLS-scoped inventory) → argument
  validation (`ToolSpec.input_model`) → SQL safety (the **M5** `validate_select`,
  the single SQL-safety source of truth at plan- and run-time) → DAG (Kahn:
  unknown/self deps, cycles) → limits (step count, per-step/total timeout) →
  approval (from `ToolSpec.requires_approval` only) and clarification.
- **Capability projection is tenant-scoped and secret-free.** The planner sees a
  view built from `REGISTRY.all()` filtered to the tenant's **non-disabled**
  connectors, plus a secret-free connector list (name/type/status and, for
  postgres, the allowlist + optional `schema_hint`). The same view is the
  feasibility input, so the model and the validator reason over one surface.
- **Connector status follows M4 recoverability:** `active`/`unchecked` usable;
  `error` usable (recoverable — the worker re-health-checks at run; surfaced as an
  info `CONNECTOR_HEALTH_UNVERIFIED`); `disabled` → REJECT.
- **Materialization re-earns PASS.** `POST /plans/{id}/materialize` never trusts
  the stored status: it locks the proposal `FOR UPDATE`, re-runs feasibility
  against the *current* capability view, and only then creates one
  `workflow_version` (idempotent — a set `workflow_version_id` short-circuits).
- **Schema context (deferred-from-M5 evaluation):** M6 provides *safe* schema
  context via an operator-declared, non-secret, strict `schema_hint` on the
  postgres connector (Tier 1). A **live** `information_schema` inspection tool is
  **not** shipped: it would require the connector secret and force planning
  worker-side, breaching the "API holds no tenant secrets" boundary. `schema_hint`
  improves planning quality but is **not** authoritative proof a column exists;
  runtime SQL is still validated by M5 and executed read-only. Live introspection
  is deferred (Tier 2).

## Alternatives considered

- **Let the model return a status / self-approve** — rejected: violates the core
  invariant; status must be code-owned.
- **Trust a parsed plan as executable** — rejected: parsing proves shape, not
  ownership/safety/limits.
- **Run planning worker-side to allow live schema inspection** — deferred: keeps
  M6 simple and preserves the API-holds-no-tenant-secrets boundary; revisited for
  tenant BYOK / higher concurrency / Tier-2 introspection.
- **Value/output templating between steps** — deferred: `depends_on` is the only
  dependency mechanism in M6 and is validated rigorously.

## Consequences

- The model can be swapped or adversarial without weakening safety; every field
  is re-validated deterministically, and the same SQL validator guards plan- and
  run-time.
- Feasibility is pure and exhaustively unit-testable; the API only assembles its
  inputs (registry + RLS-scoped connectors) and persists the verdict.
- Planner outputs become executable only through revalidated, idempotent
  materialization — never implicitly.
