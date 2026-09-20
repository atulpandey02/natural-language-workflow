# M11 — Staging Validation Report

M11 adds no product features. It adds validation tooling, bounded capacity
observability, executed regression drills, and the accepted-risk decisions
(ADR-020). Evidence is split into two tiers, kept separate (D3):

## Tier 1 — implemented & validated in this environment
- **Capacity metrics (D2):** `nlw_queue_ready_depth`, `nlw_db_pool_checked_out`,
  `nlw_db_pool_overflow`, `nlw_db_pool_checkout_wait_seconds`,
  `nlw_scheduler_lag_seconds`, `nlw_run_completion_seconds` (terminal-only).
  Wired into api/worker/scheduler; unit tests in `test_capacity_metrics.py`.
- **Historical crash windows:** M3 (commit→enqueue, checkpointed step not
  re-executed on redelivery), M7 W1/W2/W3, M8 orphan recovery, M10 Run-Now
  enqueue-failure — all covered by the existing integration suite.
- **at-least-once honesty (correction #1):** `test_crash_windows.py` proves an
  idempotency-aware receiver dedupes to ONE effect and a non-idempotent receiver
  MAY duplicate — both with a stable `external_action_key` and durable recovery.
  No exactly-once claim.
- **SHA-pinning (risk H):** every third-party GitHub Action pinned to an immutable
  commit SHA across all workflows.
- **Backend gates:** ruff/format/lint, mypy, full pytest green.
- **Config validity:** staging Compose profile, all workflow YAML, k6 script
  syntax, drill-script syntax.

## Tier 2 — wired, executed in CI/VPS (not runnable in this sandbox)
Reason: no Supabase CLI, no real VPS/TLS, no real Slack/webhook, and k6/Playwright
sustained runs require the live stack.
- `staging-validation.yml` (nightly + dispatch): staging profile up → migrate →
  seed → failure drills (A/B/C/D) → k6 capacity (raised limits) + rate-limit
  (normal limits) → required Playwright against staging → backup/restore drill →
  migration drill → artifact upload.
- Drills G/H/I/J/K and the capacity envelope require real providers/host — see
  `real-vps-checklist.md`. A real-VPS pass remains REQUIRED before M12.

## Capacity
See `capacity-statement.md` — filled from the authoritative real-VPS run.

## Accepted risks & M12 blockers
See ADR-020 (D5 matrix). M12 blockers: real-VPS pass, any drill-surfaced
correctness bug, real-backup off-host + PITR decision, wiring the deploy
placeholders, and capacity sign-off vs launch demand. Risk H is closed in M11.
