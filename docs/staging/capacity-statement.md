# Capacity Statement (M11)

Fill from a real staging run (CI ephemeral numbers are indicative only; the
authoritative envelope comes from the real-VPS pass). Do not claim scale beyond
what the run measured.

    Validated staging envelope (single VPS, <vCPU>/<GB>, <image digest>):
    - Concurrent interactive users: <X>            (initial target ~5)
    - Workflow runs/min:            <Y>
    - Concurrent worker executions: <Z>            (processes × threads)
    - Active schedules:             <N>
    - p50 / p95 / p99 API latency:  <..>/<..>/<..> ms
    - p95 run-completion:           <..> s
    - Queue ready depth (p95):      <..>            (nlw_queue_ready_depth)
    - DB pool checked_out (max):    <..> / <pool+overflow>
    - DB checkout wait p95:         <..> ms         (nlw_db_pool_checkout_wait_seconds)
    - Scheduler lag (max):          <..> s          (nlw_scheduler_lag_seconds)
    - Error rate:                   <..> %
    - Container restarts:           <..>            (expect 0)

## Safe operating thresholds (alerts)
- p95 API read latency < 800 ms; p95 plan < 5 s
- DB checkout wait p95 ≈ 0 (rising ⇒ pool saturation → scale pool/instances)
- queue_ready_depth sustained high ⇒ add worker capacity
- scheduler_lag_seconds > (scan interval × 2) ⇒ investigate
- runs_beyond_horizon > 0 ⇒ operator action (runbook)
- disk usage > 75% ⇒ audit-retention/backup action (risk E monitoring)
