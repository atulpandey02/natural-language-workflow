# Real-VPS Staging Validation Report (Pre-M12)

**Date:** 2026-09-21 · **Host:** AWS EC2 · **Result: CONDITIONAL GO** for a
limited, invite-only launch (see conditions).

This is the authoritative real-host evidence required before M12 (ADR-020, D3).
CI/ephemeral evidence proves the logic; this records the real deployment.

## 1. Host specification
| Field | Value |
|---|---|
| Provider / type | AWS EC2 (x86_64) |
| OS | Ubuntu 24.04 LTS |
| vCPU / RAM / disk | 2 / ~8 GiB / 40 GiB |
| Public IPv4 (Elastic) | 32.197.83.193 |
| Hostname | 32-197-83-193.sslip.io |
| IPv6 | not enabled (IPv4-only; no AAAA) |
| Operator | nlwops (non-root, key-only SSH, password sudo) |

## 2. Immutable deployment references
| Ref | Value |
|---|---|
| Deployment config Git SHA | `5151a2cc54cfb63b276bd3b30cf0e683263525ac` (main; #20) |
| Backend image digest | `ghcr.io/atulpandey02/natural-language-workflow@sha256:fef5464b674695050ad4b1ca2e80ca7f03bfdd3b03a6519352e52c8377d7728e` |
| Web image digest | `ghcr.io/…/web@sha256:57276f04e27e350a8eb8044349346af0f426274e9d27750bec904c203a007228` |
| Compose | `docker-compose.prod.yml` + `docker-compose.staging.yml` (NO e2e overlay) |
| Migration head | `0010_readiness_schema_grant` |

## 3. Stages executed
| Stage | Result | Evidence |
|---|---|---|
| Host baseline + hardening (Stage 0/1) | ✅ | Ubuntu 24.04, non-root operator, key-only SSH, UFW, Docker, unattended-upgrades (auto-reboot off), /opt/nlw layout |
| DNS + TLS | ✅ | `https://32-197-83-193.sslip.io/login` → 200, `ssl_verify_result=0` (Caddy ACME, no bypass) |
| Real Supabase auth | ✅ | dedicated staging project; sign-in → SSR → BFF → JWKS (ES256) → workspace selection works |
| DB roles + migrations | ✅ | roles `nlw_app/worker/scheduler = tff`, `rls_bypass/workspace_bootstrap = fft`; schema at head |
| **A — Real Anthropic planner** | ✅ | `provider=anthropic`, `model=claude-haiku-4-5-20251001`, key valid (Anthropic HTTP 200); planner produced real tool-aware reasoning in the UI (correctly `NEEDS_CLARIFICATION` — only demo tools registered) |
| **B — Failure drills (A/B/C/D)** | ✅ | Redis kill, Postgres pause (bounded 503), worker SIGKILL, scheduler restart — `ALL DRILLS PASSED`, readiness recovers each time |
| **C — Host reboot recovery** | ✅ | Elastic IP preserved; Docker + all 8 services auto-started healthy; `/login` 200 TLS-valid; readiness `ready`; schedules resume |
| **E — Load / capacity + rate-limit** | ✅ | 5 VUs, 0% errors (0/2490), p95 18.6 ms, 22.4 req/s; rate-limit 20/min enforced (20 allowed + 40×429 with Retry-After, fail-closed). See `capacity-statement.md`. |
| **F — Observability** | ✅ | per-request `X-Request-Id`; safe error contract (no stack/DB/secret); full `nlw_*` metric surface exported + scraped; **0 secret occurrences** in any service log (Anthropic key / anon key / cookie secret / password) |
| **G — Rollback drill** | ✅ | api rolled to prior digest `…ec0f3383…` → healthy; restored current `…fef5464…` → healthy; **DB never downgraded** (schema `ok` throughout) |

## 4. Not fully validated (gaps)
| Item | Status | Impact |
|---|---|---|
| **D — Off-host backup / restore DR** | ⏭️ **SKIPPED** | No backup provider chosen; RPO/RTO **unproven**. **Durability is not guaranteed** — blocker for anything beyond a limited, disposable-data launch. |
| Tenant isolation **under load** on the real host | ⚠️ partial | RLS isolation covered by CI integration tests (`test_rls_isolation`, `test_resolver_security`) + the E2E workspace-switch test; explicit concurrent A/B-under-load on the real host not run (needs a 2nd seeded tenant). |
| Real external-provider smoke (Slack/webhook) | ⏳ not run | Only demo tools (`fake.echo`/`fake.fail`) registered on staging; no real connector executed. |
| Deep request-log correlation | minor | `request_id` returned per response and metrics rich, but a plain 401 was not captured in the structured request log during the quick check (log-level dependent). |

## 5. Security posture
- Secrets model: env-only in `.env.prod` (chmod 600, git-ignored) — accepted risk (ADR-018); cloud secret manager is pre-production work.
- LLM key is **API-only** (verified: worker/scheduler/web do not receive it; not in `x-app-env`).
- No secret leakage in logs (verified, 0 occurrences).
- Public surface: only Caddy 80/443; API loopback-only (`127.0.0.1:8000`); web/pg/redis/metrics unpublished.

## 6. MUST-DO before / at launch (conditions on GO)
1. **Rotate exposed secrets NOW** — the Anthropic API key and a Supabase user password were shared in plaintext during setup. Revoke + reissue both.
2. **Configure + drill off-host backup/restore (Stage D)** and record real RPO/RTO **before onboarding any real customer data.** Until then, treat staging data as disposable.
3. Run a **real-host concurrent A/B tenant-isolation** check before scaling beyond the first tenants.

## 7. Accepted risks for limited invite-only launch (from ADR-018/020)
- Env-only secret storage; single-VPS (no HA/autoscaling); forgeable GUC DB context; unbounded audit-row retention (disk-growth monitoring required); rate-limit counters non-durable (fail-closed). Supabase Auth DR is a separate dependency from NLW Postgres DR.

## 8. Recommendation
**CONDITIONAL GO** for a **limited, invite-only launch with disposable/low-value
data**, contingent on condition #1 (rotate secrets) immediately and #2 (DR
drill + RPO/RTO) before any real customer data. The control plane is healthy,
hardened, observable, recoverable across process crashes and a full reboot, and
rolls back cleanly. The single open **durability** gap (unproven backup/restore)
is the reason this is not an unconditional GO.
