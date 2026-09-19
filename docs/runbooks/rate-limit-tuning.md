# Rate-limit tuning

Limits (per tenant AND per user, fixed window) are config (ADR-017):
`rate_limit_window_s`, `rate_limit_plans_per_min`, `rate_limit_writes_per_min`,
`rate_limit_enabled`, `rate_limit_fail_open`.

**Symptoms of too-tight limits:** legitimate `429`s; `nlw_rate_limit_rejected_total`
rising for an endpoint.

**Do:**
1. Identify the endpoint from `nlw_rate_limit_rejected_total{endpoint=...}`.
2. Adjust the relevant per-minute setting and redeploy (same digest, config
   change). Keep `POST /plans` tightest (LLM cost).
3. Leave `rate_limit_fail_open=false` in production so a Redis outage cannot open
   an abuse window; flip only for a deliberate, time-boxed reason.
