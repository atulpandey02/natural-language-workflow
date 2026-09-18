# ADR-003 — Multi-tenant isolation strategy

- Status: Accepted
- Date: 2026-09-18

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
- Future business tables adopt the `tenant_id = app.tenant_id` policy uniformly.
