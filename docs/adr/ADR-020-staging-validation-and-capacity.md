# ADR-020 — Staging validation, failure drills & capacity (M11)

- Status: Accepted
- Date: 2026-09-20

## Context

Before a limited production launch we must prove the M0–M10 system behaves
correctly under failure, restart, concurrency, and load, and state a concrete
capacity envelope. M11 adds no product features; it adds validation tooling,
bounded capacity observability, and executed drills.

## Decisions

- **Load tool: k6** (D1) — single binary / official image, JS scenarios, native
  p50/p95/p99 + thresholds. Capacity and rate-limit scenarios are kept SEPARATE:
  capacity runs raise limits to find the knee; rate-limit runs use normal limits.
- **Capacity metrics (D2):** added `nlw_queue_ready_depth` (best-effort Redis
  transport depth — NOT authoritative outstanding state), `nlw_db_pool_checked_out`,
  `nlw_db_pool_overflow`, `nlw_db_pool_checkout_wait_seconds`,
  `nlw_scheduler_lag_seconds`, `nlw_run_completion_seconds` (emitted only on the
  actual terminal transition, never on replay). No unsupported `db_pool_waiters`.
  Labels stay low-cardinality.
- **Staging profile (D3):** prod-shaped Compose overlay (`docker-compose.staging.yml`,
  APP_ENV=staging) + internal Prometheus, used for ephemeral CI evidence. A
  real-VPS pass (real Supabase, ACME TLS, real Slack/webhook) is SEPARATE and
  REQUIRED before M12.
- **TLS (D4):** ephemeral CI uses an HTTP edge (no false TLS claims); real TLS is
  validated on the VPS with clients that trust the CA.
- **at-least-once honesty:** generic delivery is at-least-once; tests assert a
  stable `external_action_key` + durable recovery. Exactly-once is only achievable
  by an idempotency-aware receiver (tested both ways).

## Known-risk dispositions (D5)

| Risk | Disposition |
|---|---|
| A forgeable GUC context | Acceptable for limited invite-only M12 launch; revisit before broader external access. |
| B EnvironmentSecretStore | Acceptable for limited single-VPS launch IF file/host perms hardened and rotation drill passes. |
| C no OTel/Langfuse | Optional later. |
| D postgres.query in-lock | Acceptable ONLY if load scenario F shows no unacceptable contention; else return with an out-of-lock design before implementing. |
| E unbounded audit retention | Acceptable for limited launch WITH disk-growth monitoring / operational threshold (added in M11). |
| F single VPS / no HA | Acceptable for limited launch with documented availability expectation. |
| G no auto stale-run terminalization | Acceptable; horizon + runbook sufficient initially. |
| H unpinned third-party Actions | FIXED in M11 (all pinned to immutable SHAs). |

## Consequences

CI produces ephemeral validation evidence on every nightly/dispatch run; the VPS
pass produces the authoritative capacity envelope. ADRs 003–019 are NOT rewritten;
this ADR records the M11 decisions and the accepted risks for first launch.
