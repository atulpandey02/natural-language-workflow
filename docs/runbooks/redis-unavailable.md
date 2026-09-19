# Redis unavailable

**Symptoms:** `/health/ready` → 503 with `redis: down`; cost/mutating endpoints
return 503 (rate limiter fails CLOSED); `advance_run` enqueues fail.

**Impact:** Redis is transport + rate-limit control state only. No workflow state
is lost. Rate limiting fails closed to avoid an abuse window.

**Do:**
1. Restore Redis (restart container/host). No data restore needed.
2. Rate-limit counters reset (acceptable — non-durable control state).
3. The scheduler reconciler re-enqueues runs whose messages were lost, rebuilding
   eligibility entirely from Postgres.
4. If fail-closed is causing an outage during a known-safe window, temporarily
   set `rate_limit_fail_open=true` — but prefer restoring Redis.
