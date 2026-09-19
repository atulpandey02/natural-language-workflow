# Postgres unavailable

**Symptoms:** `/health/ready` → 503 with `postgres: down`; API 5xx; worker/
scheduler healthchecks failing; `nlw_errors_total` rising.

**Impact:** Postgres is the system of record — no state changes progress. Redis
messages persist; recovery is automatic once Postgres returns.

**Do:**
1. Confirm the container/host: `docker compose -f docker-compose.prod.yml ps`,
   `docker logs <postgres>`. Check disk space and connection saturation.
2. Restore service (restart container / failover / free disk). Do NOT delete the
   `pgdata` volume.
3. When Postgres is back, readiness returns to 200. The scheduler reconciler
   re-enqueues any runs stranded during the outage (bounded by the recovery
   horizon — see runs-beyond-horizon).
4. If data loss is suspected, follow restore-from-backup.
