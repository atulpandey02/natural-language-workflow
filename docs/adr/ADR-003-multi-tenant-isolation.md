# ADR-003 — Multi-tenant isolation strategy

- Status: Accepted
- Date: 2026-09-18 (revised 2026-09-19 — role-specific, membership-bound policies; see “Update (M3 / migration 0005)”)

## Context

Tenant isolation is the platform's most important invariant: tenant A must never
read, modify, or discover tenant B's data. Application-layer checks alone are one
bug (a missing `WHERE tenant_id = …`, an injection, a new query path) away from a
cross-tenant leak. We want the **database itself** to be the last line of defense,
and the LLM to have no part in enforcement.

## Decision

Defense in depth, enforced below the application:

1. **Restricted runtime role.** The app connects as `nlw_app` —
   `NOSUPERUSER NOBYPASSRLS` — with only `SELECT/INSERT/UPDATE(/DELETE)` on the
   app tables. It cannot bypass RLS. Migrations run as the owner role (`nlw`)
   via a separate `DATABASE_MIGRATION_URL`. The runtime app never connects as
   owner.
2. **Role provisioning is bootstrap, not migration.** The role is created by the
   environment (docker `initdb` script locally; an explicit step in CI/infra),
   never by Alembic. Alembic (migration `0003`) owns table grants, `ENABLE` +
   `FORCE ROW LEVEL SECURITY`, and the policies.
3. **Row-Level Security keyed on two transaction-local GUCs.**
   - `app.user_id` — set right after authentication (identity).
   - `app.tenant_id` — set only after membership is confirmed (active tenant).
   Both are set with `SET LOCAL` (`set_config(..., true)`) inside a per-request
   transaction, so pooled connections never leak tenant context. Policies read
   `NULLIF(current_setting('app.*', true), '')::uuid` — empty/unset → NULL →
   **deny by default** (empty because a prior `SET LOCAL` leaves the reset value
   as `''`).
4. **Per-table policies** (permissive, OR'd), reflecting each table's tenancy:
   - `users`: global identity, no tenant RLS.
   - `workspaces`: SELECT if a member (via `memberships`) OR `id = app.tenant_id`;
     INSERT `WITH CHECK (true)` (any authed user may create a workspace).
   - `memberships`: SELECT own (`user_id = app.user_id`) OR tenant
     (`workspace_id = app.tenant_id`); INSERT own (`user_id = app.user_id`).
   The **self** policy (`app.user_id`) resolves the auth bootstrap and
   `GET /workspaces`; the **tenant** policy activates only after membership is
   confirmed, so a non-member cannot widen access by choosing `X-Workspace-Id`.
5. **Application-layer scoping remains** (membership-checked repositories) as the
   first layer; RLS is the backstop.

## Alternatives considered

- **App-layer checks only** — rejected: one missed filter leaks across tenants.
- **Schema- or database-per-tenant** — stronger isolation but heavy operationally
  at our scale and for BYO-connector growth; revisit only if required.
- **Single tenant GUC** — insufficient: the membership model needs a self policy
  for the auth bootstrap and for listing a user's workspaces without leaking.
- **Timestamps via server defaults with ORM RETURNING** — rejected under RLS:
  `INSERT ... RETURNING` re-checks the SELECT policy and a just-created workspace
  is not yet member-visible, so timestamps are set client-side.

## Consequences

- Cross-tenant access is impossible at the storage layer, proven by a raw-SQL
  probe (connect as `nlw_app`, set `app.tenant_id=A`, tenant B's rows return
  zero; no GUC → zero; `nlw_app` has no `BYPASSRLS`).
- A small operational contract: the runtime role must exist (bootstrap) before
  migrations grant to it; the app must set the GUCs each request (centralized in
  the session/deps layer).
- Future business tables adopt the tenant policies uniformly.

## Update (M3 / migration 0005) — role-specific, membership-bound policies

The original `0003` tenant-only SELECT policies (`id = app.tenant_id` /
`workspace_id = app.tenant_id`) were **forgeable**: because any connectable role
can `SET LOCAL app.tenant_id`, `nlw_app` could read another tenant's rows by
setting the GUC. A raw-SQL reproduction confirmed this. Additionally,
`memberships` INSERT `WITH CHECK (user_id = app.user_id)` allowed a user to
insert **themselves** (as `owner`) into an **existing** workspace — a direct
privilege-escalation into any tenant.

Hardened design (M3 tables in `0004`; M2 tables in `0005`):

- **Role-specific policies, no PUBLIC.** Every policy is `TO nlw_app` or
  `TO nlw_worker`.
- **`nlw_app` visibility is membership-bound** via a read-only SECURITY DEFINER
  helper `is_current_user_member(tenant_id)` (owner `nlw_rls_bypass`, minimal
  `search_path`, returns boolean only, executable only by `nlw_app`). A row is
  visible only when the current user is a member of that tenant — not merely
  because `app.tenant_id` was set.
- **`nlw_worker` policies are tenant-only** (`tenant_id = app.tenant_id`); the
  worker obtains the tenant from the worker-only `resolve_run_tenant` bootstrap
  (see ADR-010) and has no user identity.
- **No direct membership/workspace writes for `nlw_app`.** Those grants are
  revoked. A workspace and its **single** owner membership are created only by
  the narrow, atomic `create_workspace_for_current_user(name, slug)` — a
  SECURITY DEFINER function owned by the write-only, non-login
  `nlw_workspace_bootstrap` role. It always creates a **new** workspace, so it
  cannot add the caller to an existing one, and exposes no general membership
  mutation.
- `nlw_rls_bypass` stays **read-only** (authorization/routing helpers only);
  `nlw_workspace_bootstrap` holds the only membership-write capability, confined
  to that one function.

## Threat model (accurate guarantee)

**Guarantee.** With `FORCE` RLS, role-specific membership-bound policies, and the
SECURITY DEFINER helpers, the database enforces tenant isolation against
**missing or mis-scoped application queries once the authenticated request
context is correctly established**: an `nlw_app` row is visible only when the
current user is a member of that tenant, and `nlw_app` cannot self-escalate into
a tenant (no membership-write path, and workspace creation cannot target an
existing workspace).

**Non-guarantee.** `app.user_id` and `app.tenant_id` are transaction-local GUCs
and are **forgeable by arbitrary SQL executing under the shared runtime role**.
This design does **not** claim resistance to an attacker who can run arbitrary
SQL as `nlw_app`/`nlw_worker` and forge the full request identity/context (e.g.,
set `app.user_id` to an existing member of a target tenant). Achieving that
stronger guarantee requires **non-forgeable / signed DB context** or a
per-request DB identity model. This is recorded as a **pre-production
security-hardening item** and is intentionally **not** implemented in M3.

## M9 update — staging decision on the forgeable-GUC risk

For M9 (staging), the GUC-based request context (`app.user_id` / `app.tenant_id`)
is **kept as-is** and the residual risk above is **explicitly accepted for
staging**, on the following honest basis:

- **No untrusted-SQL path currently targets platform DB roles.** All platform
  queries run through parameterized SQLAlchemy / bound-parameter `text()`; there
  is no endpoint or tool that executes attacker-controlled SQL as
  `nlw_app` / `nlw_worker` / `nlw_scheduler`. The `postgres.query` tool runs
  against the **tenant's own external database** on a separate SELECT-only role —
  never the platform database — so it cannot forge platform GUCs.
- **Regression control, not a proof.** A guard test asserts repository/engine SQL
  is not built by string interpolation. This is a *regression control* that keeps
  the "no untrusted SQL" property true as code changes; it is **not** a proof that
  SQL injection is impossible.
- **Non-forgeable context remains required before public production.** Signed DB
  context or a per-request DB identity model (options A/B) must be implemented and
  reconsidered before public production. This stays a pre-production hardening item
  (see ADR-018 §remaining risks). M9 does not implement it.
