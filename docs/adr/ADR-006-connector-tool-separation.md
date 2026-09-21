# ADR-006 — Connector/Tool separation and the deterministic Tool Registry

- Status: Accepted
- Date: 2026-09-19

## Context

Workflow execution must reach external systems without ever letting the LLM run
arbitrary code, and tenants must only use integrations they own. We need a clear
seam between *what we authenticate to* and *what capability runs*.

## Decision

- **Connector** = a tenant-owned integration instance (a `connectors` row):
  `type`, non-secret `config`, a `secret_ref` (pointer, never a secret),
  `status`. Tenant-scoped by RLS (role-specific: nlw_app membership-bound;
  nlw_worker tenant-only).
- **Tool** = a capability declared by a `ToolSpec` in a **static Tool Registry**
  (`name`, `category`, `connector_type | None`, strict Pydantic `input_model`,
  `read_only`, `requires_approval`, `timeout_seconds`, `execute`). Tools are
  code; the registry is a static Python catalog. **Only registered tools run;
  unknown tool ⇒ deterministic failure.** The LLM can only name existing tools.
- **Connector types** each declare a strict Pydantic config model
  (`extra="forbid"`) and whether a secret is required. Unknown type or unknown
  config field is rejected at creation. M4 ships only the deterministic
  `static` type (no network/DB I/O).
- **Tenant-aware availability**: `available_for(owned_types)` returns
  connector-less tools plus connector-backed tools whose type the tenant owns.
- **Execution** runs inside the M3 locked advancement transaction (M4 tools are
  pure/local — no external I/O). The worker loads the tenant's connector under
  RLS, health-checks it, resolves the secret via the SecretStore (worker only),
  and calls `execute(args, connector_ctx)`. Connector-backed rules: missing
  `step.connector` ⇒ FAIL; type must match; must be tenant-owned; disabled/error
  ⇒ FAIL; unresolved secret ⇒ FAIL.
- `timeout_seconds` is **metadata only in M4** — not enforced as a hard timeout.

## Alternatives considered

- **Tools as DB rows / dynamic dispatch** — rejected: invites dynamic code paths
  and weakens the "only registered tools run" invariant.
- **One connector type = one tool** — rejected: many tools legitimately share a
  connector (e.g. `postgres.query` + `schema.inspect`).
- **Storing secrets on the connector** — rejected: see ADR-011; only a
  `secret_ref` is stored.

## Consequences

- Deterministic, auditable capability layer; the LLM never executes code.
- Tenant isolation for tools is enforced by connector ownership (RLS) + explicit
  filters, not by the model.
- Real connectors (Postgres M5, Slack/Gmail/Webhook M7) and hard timeout
  enforcement plug into this seam later without changing the model.

## Update (M11.5 P1A / migration 0011) — connector mutation authority

Originally, creating a connector required only workspace **membership**, so any
member could create a connector and attach a credential alias (`secret_ref`).
A secret alias identifies a secret; it must never, by itself, confer authority to
attach it. P1A makes connector creation + credential attachment **admin/owner
only**, enforced in two layers that agree:

- **API:** `POST /connectors` now depends on `require_role(Role.ADMIN)` (admits
  admin and owner), mirroring `schedules`/`approvals`. `GET /connectors` and
  `GET /tools` stay member-level (read-only, secret-free).
- **PostgreSQL:** the `connectors_app_insert` RLS policy's `WITH CHECK` now
  requires `is_current_user_admin_or_owner(tenant_id)` instead of
  `is_current_user_member(tenant_id)`. A direct member request that bypasses the
  API still fails at the database.

`nlw_app` continues to hold **no** `UPDATE`/`DELETE` on `connectors` (there is no
connector update/disable/delete endpoint; the worker retains its
`UPDATE(status, updated_at)` for health transitions). Connector config/destination
mutation and hard delete as first-class admin operations, and binding a connector
to a durable credential entity, are deferred to later self-service-secret work.
