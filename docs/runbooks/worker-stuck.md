# Worker not consuming / stuck

**Symptoms:** `nlw_advance_total` flat while runs sit PENDING/RUNNING; queue
depth rising; worker healthcheck failing.

**Do:**
1. Check the worker: `docker compose ps`, `docker logs <worker>`. Confirm the
   metrics port is up (the healthcheck covers DB + Redis + metrics port).
2. Confirm Postgres and Redis reachable from the worker (healthcheck output).
3. Restart the worker. Dramatiq redelivers in-flight messages; the M7 two-phase
   lease + idempotency make redelivery safe on OUR side: an ambiguous send becomes
   a terminal `UNKNOWN` that is never automatically re-sent. Delivery is
   at-least-once — a receiver that ignores the idempotency key may still have
   performed a duplicate effect (ADR-013).
4. Stranded runs are re-driven by the scheduler reconciler. Bounded infra retries
   (`worker_max_retries`) prevent tight failure loops.
5. If one run repeatedly fails to advance, see runs-beyond-horizon /
   inspect-failed-run.
