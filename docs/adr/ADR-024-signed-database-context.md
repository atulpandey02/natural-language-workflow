# ADR-024 — Tamper-evident (signed) database context (M11.5 P3B)

- Status: **Accepted — implemented** (migration `0016_signed_database_context`,
  branch `feat/pre-m12-signed-database-context`, 2026-09-22; see §Implementation)
- Date: 2026-09-21 (design); 2026-09-22 (implemented)
- Relates to: [ADR-003](ADR-003-multi-tenant-isolation.md) (superseded in part:
  its `app.user_id`/`app.tenant_id` GUCs and "Non-guarantee" are now historical),
  [ADR-023](ADR-023-membership-approval-sod.md) (P3A, whose residual forgeable-GUC
  risk this closes). Operator procedure:
  [runbooks/signed-context-keys.md](../runbooks/signed-context-keys.md).

## Context & threat model

Before `0016`, tenant/user context was carried in two transaction-local GUCs,
`app.user_id` and `app.tenant_id`, set with `set_config(..., is_local=true)`; RLS
read them via `current_setting`. They were **forgeable by any SQL executing under a
runtime role**: `nlw_app` could call `set_config('app.user_id', <victim>)` and the
RLS helpers would then resolve the victim's memberships. This is the open risk
ADR-003 recorded. Since `0016` no live policy or helper reads those settings; a
bare `set_config('app.user_id', ...)` grants nothing (asserted by
`test_no_live_policy_or_helper_trusts_unsigned_gucs`).

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
via pgcrypto**, with the key held in a table owned by a dedicated non-login role
(`nlw_ctx_verifier`, no grants to any login role) and a SECURITY DEFINER helper
whose *interface* is verify-only (`app_ctx_claims()` returns verified claims or
NULL — never key material, never a tag over caller-supplied data). `nlw_app` cannot
read the key, cannot compute a MAC, and cannot use the helper as a signing oracle.
This is not security theater: it genuinely blocks a forged-GUC attack by an
SQL-injected `nlw_app`. "Verify-only" describes that helper interface, not the key:
see the correction below.

> **Correction — the `ctx_keys` secret is signing-capable, not a "public
> verification key."** HMAC is **symmetric**: the exact same key both signs and
> verifies. Anyone who can read a `ctx_keys` row can *mint* valid contexts for that
> purpose, not merely check them. So the material we protect is **signing-capable
> secret material**, and the whole design rests on `ctx_keys` being unreadable by
> every runtime role — it must never be described, granted, or reasoned about as a
> public key. The "verify-only" property belongs to the **SECURITY DEFINER helper's
> interface** (it returns a boolean/typed id, never the key and never a fresh MAC),
> not to the key itself. This is precisely why domain 4 (a runtime that legitimately
> holds its purpose's key) is **not** protected: that runtime can forge. A design
> where Postgres holds only truly non-signing (asymmetric public) material is the
> stronger goal but, as above, is not implementable on stock PG16 + pgcrypto.

### Mechanism (as built in migration `0016`)
- Keys live in `ctx_keys(key_id, key_class, secret bytea, secret_sha256, status,
  activated_at, retired_at, revoked_at)` **owned by the dedicated NOLOGIN
  NOSUPERUSER NOBYPASSRLS role `nlw_ctx_verifier`**, with **no grant to any login
  role** (protection is ownership + absence of grants + a verifier that never
  returns material; no RLS on the registry, since FORCE RLS would blind the
  owner-run verifier). `key_class` is `api` / `worker` / `scheduler`. Material is
  installed operationally from mounted secret files (`python -m nlw.ctxkeys
  install`, owner credential) — never in a migration, argv, or env value. Every
  install/activate/retire/revoke is appended to `ctx_key_events` (no material).
- The application signs, per transaction, one **canonical, versioned,
  length-prefixed** message (byte-identical in Python and SQL, `app_ctx_canon`):
  `"nlwctx1"` followed by `<octet_length>:<value>` for each of `version`, `key_id`,
  `db_role`, `purpose`, `user_id`, `tenant_id`, `run_id`, `issued_at`, `expires_at`,
  `nonce` (absent ids encode as the empty string; all fields ASCII), with
  `HMAC-SHA256(key, msg)`, and sets the eleven claims + MAC as transaction-local
  GUCs via `set_config(..., true)`: `app.ctx_v`, `app.ctx_kid`, `app.ctx_role`,
  `app.ctx_purpose`, `app.ctx_user`, `app.ctx_tenant`, `app.ctx_run`,
  `app.ctx_iat`, `app.ctx_exp`, `app.ctx_nonce`, `app.ctx_mac`.
- The single SECURITY DEFINER verifier `public.app_ctx_claims()` (owner
  `nlw_ctx_verifier`, `search_path=pg_catalog`, `REVOKE ... FROM PUBLIC`, EXECUTE
  only for the platform roles) recomputes the tag with pgcrypto `hmac(...,
  'sha256')` and compares it in constant time, and additionally checks: version
  `1`; field formats; key present, `active`, not revoked/retired and of the class
  the purpose requires; `app.ctx_role = session_user` (the login role, unaffected
  by SECURITY DEFINER — a context minted for `nlw_app` cannot be replayed by
  `nlw_worker`); purpose ↔ login role; the claim shape of the purpose; `iat ≤
  now + 60 s` skew; `exp > now`; `1 s ≤ exp − iat ≤ 600 s` (independent of the
  application's cap). ANY failure returns NULL and RLS denies. Typed,
  purpose-gated SECURITY INVOKER accessors wrap it: `ctx_purpose()`,
  `ctx_user_id()` (`api_identity` / `api_request` only), `ctx_tenant_id()`
  (`api_request` / `worker_execution`), `ctx_run_id()` (`worker_execution`).
- **Purpose separation** — four purposes, each bound to exactly one login role and
  a fixed claim shape: `api_identity` (`nlw_app`; verified human, no workspace —
  self rows + membership discovery), `api_request` (`nlw_app`; human + the
  workspace whose membership was confirmed), `worker_execution` (`nlw_worker`;
  tenant + run, no human), `scheduler_reconcile` (`nlw_scheduler`; no ids). A
  worker context has no user, so it cannot decide approvals or administer
  membership; a scheduler context cannot impersonate a human. Scheduler policies
  are `ctx_purpose() = 'scheduler_reconcile'` instead of the former `USING (true)`;
  worker policies bind tenant **and** the claimed run (`ctx_run_id()`).
- **Revocation & lifetime** — contexts are signed per transaction with a short
  TTL (`NLW_CTX_TTL_S`, default 120 s, cap 600 s); the helpers
  `is_current_user_member` / `is_current_user_admin_or_owner` re-check live
  membership on every call, so a removed/demoted membership loses access at once.
  `key_id` supports rotation with an overlapping current+previous key (each
  signing-capable, per the correction above); an unknown/revoked/retired key id
  fails closed. Emergency revocation is immediate.
- **Pool & transaction hygiene** — context is transaction-local; the pool reset
  (rollback → `RESET ALL` → commit) clears it on check-in as defence in depth;
  a missing/malformed/expired/wrong-purpose/wrong-role context fails closed. No
  signing material appears in SQL, logs, metrics, or exceptions.
- **Deploy/rollback semantics** — until keys are installed every tenant query is
  denied (no unsigned fallback). Downgrading below `0016` re-installs the legacy
  unsigned-GUC policies and **re-opens forgery**; a runtime/database version
  mismatch in either direction fails **closed** (outage, never an open door).

## Status — implemented (was: launch gate)

The design above was first validated by a throwaway-DB spike (valid signed
context → claims; wrong MAC → NULL; `nlw_app` `SELECT` on the key table →
permission denied; pgcrypto's HMAC matches the application's; `session_user`
binding gives per-role separation) and then implemented **atomically** in one
migration rather than as a partial cutover — a half-migrated policy set that still
trusted an unsigned GUC would have been a regression. The launch gate recorded in
the original proposal (an SQL-injected `nlw_app` could forge
`app.user_id`/`app.tenant_id`) is closed by `0016`; what remains out of scope is
domains 4–5 above.

## Implementation

- **Migration:** `migrations/versions/0016_signed_database_context.py` —
  pgcrypto (schema `public`), `ctx_keys` + `ctx_key_events`, `app_ctx_canon`,
  `app_ctx_claims`, the four accessors, helpers rewritten onto `ctx_user_id()`
  (`is_current_user_member`, `is_current_user_admin_or_owner`,
  `create_workspace_for_current_user`, `accept_workspace_invitation`;
  `manage_membership` additionally requires purpose `api_request` and
  `ctx_tenant_id() = workspace`), `is_current_user_owner(uuid)` dropped (dead and
  an unsigned-GUC oracle), and all **51** live RLS policies dropped and recreated
  to trust only verified claims. The legacy definitions are retained in the file
  for `downgrade()` only.
- **Roles:** `nlw_ctx_verifier` (NOLOGIN NOSUPERUSER NOBYPASSRLS; owner of the
  registry and verifier functions; provisioned by `00-roles.sh` / bootstrap, never
  by Alembic). Login roles unchanged: `nlw_app`, `nlw_worker`, `nlw_scheduler`.
- **Modules:** `nlw.tenancy.signing` (canonical message, `ContextSigner`,
  `SignedContext`, key-file loader), `nlw.tenancy.session`
  (`set_identity_context`, `set_request_context`, `set_worker_context_sync`,
  `set_scheduler_context_sync`), `nlw.tenancy.keys` (signer construction from
  `NLW_CTX_KEY_ID` / `NLW_CTX_KEY_FILE` / `NLW_CTX_TTL_S`; process signer
  registry for worker/scheduler), `nlw.tenancy.readiness` (`signed_context`
  readiness probe: the runtime proves the DB verifies a context signed with its
  key; the API fails closed at startup in staging/production).
- **CLI:** `python -m nlw.ctxkeys install | revoke | list | check` (owner
  credential from `DATABASE_MIGRATION_URL`; secrets read from files only).
- **Backup validation** (`nlw.backup.validate`) gained `pgcrypto_present`,
  `ctx_keys_registry_protected`, `ctx_verifier_functions_hardened` and
  `no_policy_trusts_unsigned_context`.
- **Runbook:** [runbooks/signed-context-keys.md](../runbooks/signed-context-keys.md)
  — deployment order, key generation/installation, rotation, emergency
  revocation, rollback warning, local/test provisioning.
- **Tests:** `tests/integration/test_signed_context.py` (27 adversarial tests:
  unsigned-GUC forgery grants nothing; a valid `api_request` context is scoped to
  its workspace; changing any of the 11 signed fields invalidates; expired /
  future-issued / over-long; wrong login role and wrong purpose; unknown /
  revoked / retired keys fail while rotation overlap works; runtime roles cannot
  read or mutate the registry; no signing oracle; worker/scheduler contexts are
  never human; commit / rollback / pool reuse clear the context; missing or
  malformed context fails closed without leakage; golden vectors verify in
  Postgres; no live policy or helper trusts unsigned GUCs);
  `tests/unit/test_signed_context_signing.py` (pinned golden vectors for the
  canonical message + MAC, claim shapes, key/TTL validation);
  `tests/unit/test_ctx_compose_isolation.py` (rendered Compose gives each runtime
  only its own key; backup/restore receive none; key files git-ignored).

## Consequences
- Materially closes domains 1–3; domains 4–5 remain out of scope (documented, not
  claimed away).
- Adds a signing-key lifecycle (generation, per-runtime storage, rotation, emergency
  revocation) to operations — see the runbook.
- Deployment is order-sensitive (stop runtimes → migrate → install keys → start),
  and rollback below `0016` is a security event, not a routine downgrade.
- No home-grown crypto: pgcrypto (an established, shipped extension) only.
