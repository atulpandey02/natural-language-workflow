# Rotate exposed secrets (required before customer data)

This is a **human/operator** checklist. Claude/automation must NOT generate,
print, retrieve, rotate, or commit real credentials. Do each step on the host,
keep `.env.prod` at `chmod 600`, and never paste a secret into chat, Git, a
command that logs it, or documentation.

Rotate at least these (the staging report flagged the first three as exposed in
plaintext during setup):

1. **Privileged migration / DB-owner password** (`POSTGRES_PASSWORD`, and the
   `nlw` owner used by `DATABASE_MIGRATION_URL`).
2. **Anthropic API key** (`NLW_LLM_API_KEY`).
3. **Supabase** DB password / any exposed Supabase secret from the staging report.
4. **Every derived connection URL** that embeds a rotated DB password
   (`DATABASE_URL`, `WORKER_DATABASE_URL`, `SCHEDULER_DATABASE_URL`,
   `DATABASE_MIGRATION_URL`).

## Procedure (per secret)

1. **Rotate at the provider.** Anthropic Console → new key (`sk-ant-api03-…`);
   Supabase dashboard → rotate DB password; Postgres owner → `ALTER ROLE nlw
   PASSWORD '<new>'` (owner rotation is a live `ALTER ROLE`; see
   [rotate-db-role-password.md](rotate-db-role-password.md) for the runtime roles).
2. **Update `/opt/nlw/app/.env.prod`** with the new value(s), editing in place;
   keep `chmod 600`. Update any connection URL that embeds a rotated DB password.
   Never echo the value (edit with `$EDITOR`, or pipe on stdin — never argv).
3. **Recreate only the affected containers** (no volumes touched, no downgrade):
   - Anthropic key → `docker compose --env-file .env.prod -f docker-compose.prod.yml -f docker-compose.staging.yml up -d --no-deps --force-recreate api`
   - DB URLs / passwords → recreate `api worker scheduler` (and re-run migrations
     via the `migrate` service if the owner password changed).
4. **Prove old credentials fail.** Old Anthropic key → Anthropic API returns
   `401`; old DB password → connection refused/auth failed.
5. **Prove new credentials work.** Anthropic → `HTTP 200` on
   `/v1/models/claude-haiku-4-5-20251001`; DB → role connects and
   `/health/ready` is `ready`.
6. **Verify no leakage.** Confirm the secret does NOT appear in: Git
   (`git grep`, history), process args (`ps`), container/service logs
   (`docker compose logs | grep`), rendered Compose (`config`), or any doc.
7. **Re-run the smoke checks:** host-local `curl -fsS http://127.0.0.1:8000/health/ready`;
   public `https://<staging-host>/login` (200, TLS-valid); a real UI plan
   (planner returns real reasoning); migration head unchanged.

## Notes
- The migration/owner credential now lives ONLY in the one-shot `migrate` service
  (M11.5 P0) — rotate it there and in `DATABASE_MIGRATION_URL`; runtime services
  never hold it.
- Do NOT claim rotation is complete on anyone's behalf — it is an operator action.
- A key shared in plaintext (chat, ticket, screenshot) is compromised; rotate it
  even if "it still works".
