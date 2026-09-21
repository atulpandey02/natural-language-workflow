# Failed / partial migration

**Symptoms:** deploy step `alembic upgrade head` failed; `/health/ready` →
`schema: down` (DB revision ≠ expected head).

**Do:**
1. Do NOT switch traffic to the new image. Readiness will keep it out of rotation.
2. Inspect: `alembic current`, `alembic history`, and the migration error.
3. Fix forward where possible (correct the migration, re-run `upgrade head`).
4. If you must roll back the image, redeploy the previous **schema-compatible**
   digest. Image rollback does NOT auto-downgrade the DB; only run a deliberate
   `alembic downgrade` if that specific migration is safely reversible.
5. Re-verify readiness returns `schema: ok` before restoring traffic.

## ⚠️ Security-sensitive downgrades

Some migrations are reversible but their downgrade **re-opens a closed security
defect**. Treat these as security changes, not routine rollbacks.

- **`0011_identity_connector_authz` (M11.5 P1A).** Downgrading below `0011`
  restores the **old unrestricted `nlw_app` `SELECT/INSERT/UPDATE` on `users`
  with no RLS** (the runtime role can again enumerate and rewrite unrelated
  identities, including `auth_provider_id`) and the **member-level
  connector-insert policy** (any member can create a connector and attach a
  credential alias). Do **NOT** downgrade below `0011` on the live pilot without
  explicit security review and compensating controls. Prefer fixing forward.

More generally: before any production `alembic downgrade`, check whether the
target migration's `downgrade()` restores a weaker authorization posture (RLS
disabled, broadened grants, relaxed policies). If so, get security sign-off first.
