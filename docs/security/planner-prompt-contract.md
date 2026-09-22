# Planner prompt-construction & untrusted-data contract (M12B-A, Part D)

The planner is the only place a model participates, and it produces data, not
actions (ADR-026). This document states the one prompt-construction contract and
— more importantly — the invariants enforced **outside the model** so that no
prompt content, from the user or from tenant-authored data, can change
authorization or execution.

## The prompt layers

The planner prompt (`src/nlw/planner/prompt.py`) is built deterministically from
exactly these layers. Nothing else reaches the model.

| layer | source | trust | in the prompt as |
|---|---|---|---|
| system / developer instructions | `_SYSTEM` constant (`prompt.py`) | trusted (code) | the `system` string |
| tool catalog + JSON schemas | deterministic capability view from the Tool Registry (`capabilities.py`) | trusted (code + registry) | `capabilities.tools` |
| connector inventory (secret-free) | RLS-scoped connector rows projected to `SafeConnector` | **semi-trusted**: `name`, `allowed_schemas/tables`, `schema_hint` are tenant-authored | `capabilities.connectors` |
| platform limits | `PlatformLimits` (code) | trusted | `limits` |
| user request | the `POST /plans` body | **untrusted** | `user_request` (a JSON string field) |
| prior conversation / memory | — | n/a | **none exists** (single-shot planning) |

Untrusted and semi-trusted content is confined to named JSON fields
(`user_request`, connector `name`/`schema_hint`). It is data inside the payload,
never appended as instructions. The system prompt states that a separate
deterministic system decides validity/authorization; **safety does not depend on
the model honoring that.** Explicit delimiting (the JSON structure) distinguishes
instructions from data, but it is not the control — the controls are below.

## What is enforced outside the model (the real boundary)

Even if the model (or an injected fixture) returns a maximally malicious plan,
deterministic code guarantees:

1. **Untrusted content cannot add a tool.** Tool names are re-validated against
   the registry-derived capability view; an unknown or unavailable tool is a
   `UNKNOWN_TOOL` / `TOOL_NOT_AVAILABLE` reject at feasibility, and the executor
   re-fetches the `ToolSpec` by name (`UnknownToolError` otherwise). Data in the
   prompt cannot register a tool.
2. **It cannot alter authorization / bypass approval.** Approval is derived from
   `ToolSpec.requires_approval`, never from the plan (which has no approval
   field). A side-effecting tool always parks at `WAITING_APPROVAL`.
3. **It cannot choose another tenant/connector.** The plan supplies only a
   connector *name*; the connector is loaded by tenant-scoped SQL, type-checked,
   and (for approved actions) pinned to the approved connector id at execution.
4. **It cannot expand network policy.** Webhook/Slack/Postgres destinations live
   in connector config, not in step args (`action_schemas.py` forbid URLs/hosts);
   SSRF/URL and SQL-destination validation are connector-owned and re-run at
   execution.
5. **It cannot obtain secrets.** Secrets never enter the prompt (proven by
   `test_planner_security.py`); the model sees only a secret-free projection.
   Plan args cannot carry a secret value into anything privileged.
6. **It cannot mutate the persisted plan unnoticed.** A materialized
   `WorkflowVersion` is immutable; materialize re-validates against current
   capabilities ("never trust the stored PASS"); a changed plan is a new version.

## Why not a keyword "injection detector"

There is deliberately **no keyword-based prompt-injection filter** as the primary
defense. A denylist of phrases ("ignore previous instructions", "drop table") is
brittle and bypassable, and would give false confidence. Instead the model's
output is treated as an untrusted proposal and every security decision is
deterministic and re-validated at feasibility and again at execution. Injection
text inside data (a SQL string literal, a connector `schema_hint`, an action
payload) is validated as data and simply has no authority — see the corpus cases
`indirect_injection_in_data`, `malicious_action_content_needs_approval`, and the
unit tests in `tests/unit/test_injection_boundary.py`.

## Trust boundary

Tenant admins author connector `name`/`schema_hint`; a malicious workspace member
can therefore place injection-looking text into the prompt. This cannot change
authorization (enforced above), but it is why those fields are marked
semi-trusted and why feasibility never consults `schema_hint` for anything but
the SQL allowlist it already validates. Compromise of the platform LLM key or the
registry/connector-validation code is outside this boundary.
