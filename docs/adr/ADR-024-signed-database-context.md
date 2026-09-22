# ADR-024 — Tamper-evident (signed) database context (M11.5 P3B)

- Status: **Proposed — design accepted, implementation is a launch gate** (see §Status)
- Date: 2026-09-21
- Relates to: [ADR-003](ADR-003-multi-tenant-isolation.md) (which defers signed
  context), [ADR-023](ADR-023-membership-approval-sod.md) (P3A, which explicitly
  leaves the forgeable-GUC threat to P3B).

## Context & threat model

Tenant/user context is carried in two transaction-local GUCs, `app.user_id` and
`app.tenant_id`, set with `set_config(..., is_local=true)`; RLS reads them via
`current_setting`. They are **forgeable by any SQL executing under a runtime role**:
`nlw_app` can call `set_config('app.user_id', <victim>)` and the RLS helpers will
then resolve the victim's memberships. This is the open risk ADR-003 records.

Distinguish five compromise domains and state honestly what a signed context does:

1. **Accidental context omission** — a code path that forgets to set context. Signed
   context fails closed (no valid signature → no access). ✅ protected.
2. **SQL injection / attacker-controlled SQL as a runtime role** — the reported
   defect. The attacker can set GUCs but cannot mint a valid MAC (they cannot read
   the signing key). ✅ protected — this is the primary goal.
3. **Direct possession of an `nlw_app`/worker/scheduler DB credential** — same as (2)
   for what they can do via SQL: they still cannot forge a signed context without the
   signing key. ✅ protected against context forgery (they retain their own role's
   legitimate, RLS-scoped access).
4. **Full compromise of the API/worker process and its environment** — the attacker
   obtains the process's signing key and can mint arbitrary contexts for that
   purpose. ❌ **NOT protected.** Per-runtime keys limit blast radius (a worker
   compromise cannot mint an API/human context), but a compromised signer within a
   purpose can forge that purpose.
5. **Database owner/superuser compromise** — can read the key table and bypass RLS
   entirely. ❌ **NOT protected** (nothing at the DB layer can).

**We therefore do not claim "non-forgeable."** We claim: signed context provides
**tamper evidence and authorization binding within the runtime-role / SQL-injection
threat (domains 1–3)**; it does not protect against compromise of a runtime holding
the corresponding key (4) or of the database owner/superuser (5). Supabase remains
responsible for authentication; NLW for membership and authorization.

## Cryptographic design (chosen after evaluating alternatives)

### Why not asymmetric (the preferred design), and why HMAC is the pilot floor
The strongest design keeps the private signing key out of the database entirely
(API/worker hold private keys; Postgres holds only public keys and verifies).
**Stock PostgreSQL 16 + pgcrypto cannot verify an asymmetric signature** (pgcrypto
exposes PGP and digests/HMAC, not a generic Ed25519/RSA `verify`), and this pilot
must not add a crypto extension, an untrusted PL (plpython/plperl), or a network
call from Postgres, nor implement home-grown crypto. So asymmetric verification in
the database is **not implementable within the constraints** — an honest
architectural finding, not a preference.

The implementable floor that still materially closes domains 1–3 is **HMAC-SHA256
via pgcrypto**, with the verification key held in a table readable **only** by a
privileged non-login role and a **verify-only** SECURITY DEFINER helper. `nlw_app`
cannot read the key, cannot compute a MAC, and cannot use the helper as a signing
oracle (it only *verifies* a MAC the caller already possesses). This is not security
theater: it genuinely blocks a forged-GUC attack by an SQL-injected `nlw_app`.

### Mechanism (validated by a spike — see §Status)
- Keys live in `ctx_keys(purpose, key_id, secret bytea)` **owned by `nlw_rls_bypass`**
  (BYPASSRLS, NOLOGIN), with **no grant to any runtime role**. The key is a secret
  loaded operationally (like the DR restic password) — never in a migration.
- The application signs, per transaction, a **domain-separated** message:
  `v1 | session_user (DB login role) | purpose | user_id | tenant_id | issued_at |
  expiry | nonce`, with `HMAC-SHA256(key[purpose], msg)`, and sets the claims + MAC
  as transaction-local GUCs (`app.ctx_*`).
- Verify-only SECURITY DEFINER helpers `app.current_user_id()` / `app.current_tenant()`
  (owned by `nlw_rls_bypass`, `search_path=pg_catalog`, no PUBLIC EXECUTE) read the
  GUCs, reject a missing/expired/wrong-purpose context, look up the key by purpose,
  recompute `encode(hmac(convert_to(msg,'UTF8'), key, 'sha256'),'hex')`, and return
  the typed id **only** on an exact match — else NULL (fail closed). Binding to
  `session_user` (the login role, unaffected by SECURITY DEFINER) means a token
  minted for `nlw_app` (purpose `api_request`) cannot be replayed by `nlw_worker`.
- **Purpose separation** — distinct keys/purposes per runtime class
  (`api_request`, `worker_execution`, `scheduler_reconcile`, `identity_bootstrap`).
  A worker token cannot decide approvals or administer membership; a scheduler token
  cannot impersonate an owner/admin. Approval decisions require an `api_request`
  (human) context.
- **Revocation & lifetime** — sign per request/transaction with a **short expiry**;
  the RLS helper additionally confirms active membership/current role where needed,
  so a removed/demoted membership loses access within a request. `key_id` supports
  rotation with an overlapping current+previous verification key; an unknown/revoked
  `key_id` fails closed.
- **Pool & transaction hygiene** — context is `set_config(..., true)`
  (transaction-local); a pool check-in listener also clears `app.*` as defense in
  depth; a missing/malformed/expired/wrong-purpose/wrong-role context fails closed.
  No signing/verification material appears in SQL, logs, metrics, or exceptions.

## Status — why this is a launch gate, not a committed change

The **cryptographic mechanism is validated** (a throwaway-DB spike proved: valid
signed context → tenant id; wrong MAC → NULL; `nlw_app` `SELECT` on the key table →
permission denied; pgcrypto `hmac(convert_to(msg,'UTF8'), key, 'sha256')` matches the
application's HMAC-SHA256; `session_user` binding gives per-role separation).

The **full integration is a dedicated effort** and was intentionally **not committed
in this session** rather than ship a partially-migrated RLS change (a half-migrated
policy set that still trusts an unsigned GUC would be a security regression — worse
than the status quo). It requires, coherently and atomically:
- migration `0016`: pgcrypto, `ctx_keys`, the verify helpers, and rewriting **every**
  RLS policy + `is_current_user_member/admin_or_owner/owner` from `current_setting`
  to the verified helpers, with the bootstrap boundary (`resolve_or_create_user`,
  `create_workspace_for_current_user`, invitation acceptance) handled explicitly;
- application signing in `nlw.tenancy.session` (API) and sync signers for
  worker/scheduler, keys via per-runtime secret files (isolated in rendered Compose:
  API lacks worker/scheduler keys, etc.);
- key bootstrap into `ctx_keys` + a test fixture, and rotation runbook;
- migrating the ~43 direct-SQL context set-ups across 13 integration test files to
  sign, plus ~22 new adversarial tests (unsigned/tampered/expired/wrong-role/
  cross-purpose/pool-leak/revocation/rotation/oracle-resistance);
- backup/restore validation of the new helpers/owners/keys.

**Launch gate:** until P3B lands, the forgeable-GUC risk from ADR-003 remains — an
SQL-injected `nlw_app` can forge `app.user_id`/`app.tenant_id`. P3A's four-eyes and
membership invariants stand, but an attacker who forges identity at the GUC layer
could still defeat tenant isolation. **P3B must be completed before public production
with real customer data.**

## Consequences
- Materially closes domains 1–3 once implemented; domains 4–5 remain out of scope
  (documented, not claimed away).
- Adds a signing-key lifecycle (generation, per-runtime storage, rotation, emergency
  revocation) to operations — a runbook is part of the P3B deliverable.
- No home-grown crypto: pgcrypto (an established, shipped extension) only.
