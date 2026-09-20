# Rotate a PostgreSQL runtime role password

The runtime roles (`nlw_app`, `nlw_worker`, `nlw_scheduler`) get their passwords
from the environment at **fresh-volume bootstrap only**
(`docker/postgres/initdb/00-roles.sh`). Changing `NLW_*_DB_PASSWORD` afterwards
does **NOT** rotate an existing role's password — the init script never re-runs.
Rotation on a live database is an explicit `ALTER ROLE` operation.

**Do (per role, one at a time):**

1. Generate a new strong, URL-safe password:
   ```bash
   openssl rand -hex 32
   ```
2. Rotate the role on the live DB as the owner (never logs the value; run it so
   the password is not left in shell history):
   ```bash
   docker compose --env-file .env.prod \
     -f docker-compose.prod.yml -f docker-compose.staging.yml \
     exec -T postgres \
     psql -v ON_ERROR_STOP=1 -U nlw -d nlw \
     -c "ALTER ROLE nlw_worker PASSWORD '<NEW_PASSWORD>'"
   ```
3. Update the matching value(s) in `.env.prod`:
   - the role's `NLW_*_DB_PASSWORD` (keeps bootstrap consistent for any future
     fresh volume), and
   - the password embedded in that role's connection URL
     (`DATABASE_URL` / `WORKER_DATABASE_URL` / `SCHEDULER_DATABASE_URL`;
     `DATABASE_MIGRATION_URL` + `POSTGRES_PASSWORD` for the owner).
4. Recreate the affected service so it reconnects with the new value:
   ```bash
   docker compose --env-file .env.prod \
     -f docker-compose.prod.yml -f docker-compose.staging.yml \
     up -d --force-recreate --no-deps worker
   ```
5. Verify readiness from the VPS host (loopback seam, never public):
   ```bash
   curl -fsS http://127.0.0.1:8000/health/ready
   ```
   and confirm the role connects (e.g. `pg_stat_activity.usename`). The old
   password must no longer authenticate.

**Notes**
- Keep `.env.prod` at `chmod 600`. Never commit it; never echo passwords.
- The owner (`nlw`) password is `POSTGRES_PASSWORD`; rotating it also requires
  updating `DATABASE_MIGRATION_URL`.
- This is separate from **connector-secret** rotation (worker env
  `NLW_SECRET_*`), which is [rotate-secret.md](rotate-secret.md).
