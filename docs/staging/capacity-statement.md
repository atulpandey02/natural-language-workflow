# Capacity Statement (M11 → real-VPS pass)

Authoritative envelope from the real-VPS staging run (2026-09-21). Capacity was
measured with the **stub** planner so the numbers reflect the *control-plane*
knee (DB pool, queue, rate limiting), not Anthropic latency. The real Anthropic
planner is validated end-to-end separately (see the validation report) and its
latency is provider-bound.

    Validated staging envelope (single VPS: AWS EC2, 2 vCPU / ~8 GiB / 40 GiB,
    Ubuntu 24.04; backend @sha256:fef5464… web @sha256:57276f04…; config 5151a2c):
    - Concurrent interactive users: 5              (initial target; 0% errors, knee not reached)
    - Control-plane throughput:     22.4 req/s     (2490 reqs over 1m50s at 5 VUs)
    - p50 / p95 API latency:        7.6 / 18.6 ms  (max 108 ms; read+write mix)
    - Error rate (capacity):        0.00 %         (0 / 2490)
    - DB checkout wait:             ≈ 0            (no pool saturation at 5 VUs; nlw_db_pool_checkout_wait_seconds)
    - Container restarts:           0
    - Rate limiting (normal):       20 plans/min enforced → 20 allowed + 40×429,
                                    every 429 carries Retry-After, fails closed.

## Method
- `tests/load/control-plane.js` (capacity: ramping 1→5 VUs, limits raised) and
  `tests/load/rate-limit.js` (normal limits) run via `grafana/k6` against the
  host loopback API seam (`127.0.0.1:8000`), with the planner temporarily set to
  `stub` and restored to `anthropic` afterward (no Anthropic tokens spent).
- Metrics exported and scraped: `nlw_http_request_duration_seconds`,
  `nlw_db_pool_checked_out/overflow`, `nlw_db_pool_checkout_wait_seconds`,
  `nlw_planner_latency_seconds`, `nlw_advance_latency_seconds`,
  `nlw_scheduler_lag_seconds`, `nlw_scheduler_runs_beyond_horizon`.

## Interpretation
- At the initial target of **~5 concurrent interactive users** the single VPS is
  comfortably below its knee (p95 18.6 ms, 0% errors). Headroom is ample for a
  limited invite-only launch; the next scaling signal is DB pool checkout wait
  rising (currently ≈ 0).
- Do not claim scale beyond what this run measured. Higher concurrency, real
  connector execution, and real-planner latency have not been load-tested.

## Safe operating thresholds (alerts) — unchanged from M11
- p95 API read latency < 800 ms; p95 plan < 5 s
- DB checkout wait p95 ≈ 0 (rising ⇒ pool saturation → scale pool/instances)
- queue_ready_depth sustained high ⇒ add worker capacity
- scheduler_lag_seconds > (scan interval × 2) ⇒ investigate
- runs_beyond_horizon > 0 ⇒ operator action (runbook)
- disk usage > 75% ⇒ audit-retention/backup action (risk E monitoring)
