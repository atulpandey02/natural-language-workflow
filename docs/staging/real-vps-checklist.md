# Real-VPS staging validation checklist (required before M12)

CI ephemeral evidence (staging-validation.yml) proves the LOGIC. This checklist
produces the AUTHORITATIVE staging evidence on a real host. Keep this evidence
separate from CI (D3).

Prerequisites:
- A VPS (record vCPU/RAM/disk). The real-VPS Compose stack is
  **`docker-compose.prod.yml` + `docker-compose.staging.yml` ONLY**. Do NOT
  include `docker-compose.e2e.yml` on a real VPS (it wires a local Supabase + an
  HTTP-only edge). Run the exact GHCR image digests intended for production.
- A git-ignored **`.env.prod`** (`chmod 600`) built from
  [`.env.prod.example`](../../.env.prod.example): `POSTGRES_PASSWORD` +
  `NLW_APP_DB_PASSWORD` / `NLW_WORKER_DB_PASSWORD` / `NLW_SCHEDULER_DB_PASSWORD`
  (each `openssl rand -hex 32`, URL-safe) and the four per-role connection URLs
  (each embedding its own role's password; no worker/scheduler fallback).
- A real Supabase project (JWKS/asymmetric) + `PUBLIC_HOSTNAME` with DNS.
- Caddy ACME TLS; verify clients TRUST the cert (no ignoreHTTPSErrors).
- Real Slack workspace + a real webhook receiver (idempotency-aware) for actions.
- Off-host encrypted backup destination configured.

Compose invocation (Compose does NOT auto-load `.env.prod` — pass it explicitly
to config / pull / migrations / up / down / drills / restore):

    docker compose --env-file .env.prod \
      -f docker-compose.prod.yml -f docker-compose.staging.yml <command>

Health-check model:
- **Public** edge validation is `https://<staging-host>/login` (proves DNS, TLS,
  Caddy, and Next.js).
- **API readiness** is checked ONLY from the VPS host over the staging overlay's
  loopback seam: `curl -fsS http://127.0.0.1:8000/health/ready`. Do NOT expose
  FastAPI `/health` or `/health/ready` publicly.

Run + record evidence for:
1. Full required Playwright E2E against the real domain (TLS-validated).
2. Failure drills A–K (tests/drills + manual G/H/I/J/K with real providers).
3. k6 capacity (limits raised) → fill docs/staging/capacity-statement.md.
4. k6 rate-limit (normal limits) → 429/Retry-After/fail-closed.
5. Backup → destroy → restore drill; measure real RPO/RTO. Note: restores NLW
   Postgres state ONLY — Supabase Auth identities are a SEPARATE DR dependency.
6. Migration drill (fresh, upgrade, interrupted, rollback-by-digest).
7. Secret-rotation drill (harden file/host perms first — risk B).
8. Observability diagnosis walkthroughs; confirm no secret/token exposure.
9. Executed runbooks with corrections.
10. Trivy on both images (0 HIGH/CRITICAL fixable).

## Note: true migration-interruption (real-VPS only)

CI runs a schema-incompatibility / readiness drill (mismatched alembic_version ->
readiness 503 -> repair). The TRUE live-interruption test — SIGKILL the process
mid-`alembic upgrade`, then observe transaction rollback / partial state /
alembic_version and confirm readiness stays 503 until repaired — is performed
here on the real host (not in ephemeral CI).

## M12 GO/NO-GO checklist (signed-context rollout, M12A)

The **code gate** closed with P3B (`1eebf2e`) and the M12A-Prep tooling; the
**operational gate** is the list below. Every item needs real evidence (not the
CI "staging simulation" job, which contacts no host). Decision = GO only when
all boxes are ticked.

- [ ] Off-host backup provider configured (`docs/ops/backup-providers.md`),
      `/opt/nlw/.env.backup` in place, `nlw-backup.timer` active, and
      **one verified backup** of the pre-upgrade database (`rev-0010…`) — the
      `verify-backup` gate proves it; a MinIO/local fixture never counts.
- [ ] `python -m nlw.ops.rollout preflight` clean against the intended instance
      (`i-0d1e65cdc9401dbb9`): revision `0010_readiness_schema_grant`, M11 roles,
      zero non-terminal work.
- [ ] Production-grade keys prepared on the host (`prepare-keys`: 0700/0400,
      uid 10001, fingerprints only) and **escrowed off-host** with a recovery
      test; attestation written by the operator; `verify-escrow` passed with
      `SIGNED_CONTEXT_KEYS_ESCROWED_AND_RECOVERY_TESTED`.
- [ ] Operator authorization `AUTHORIZE_M12A_SIGNED_CONTEXT_STAGING_DEPLOYMENT`
      given for this host + release (`deploy/staging/release.json`). Neither
      phrase substitutes for the backup provider.
- [ ] Rollout phases `drain → migrate → install-context-keys → recreate-runtime →
      validate → reopen` completed; state file kept as evidence; `signed_context: ok`.
- [ ] `scripts/ops/verify-staging-deployment.sh` green after reopen (instance id,
      release digests, roles incl. `nlw_ctx_verifier`, schema `0016`, registry
      posture, TLS).
- [ ] Prometheus rule groups `nlw-backup` + `nlw-signed-context` loaded;
      Alertmanager healthy; **a real alert receiver wired and a controlled test
      alert delivered** (open until an operator chooses the channel —
      `docs/ops/alerting.md`).
- [ ] Non-destructive key-rotation drill on staging (API class, overlap, revoke).
- [ ] k6 planner/API load profile + non-destructive failure drills (restart
      api/worker/scheduler; wrong-key canary fails closed).
- [ ] Real-provider fresh-host DR drill (not MinIO) — `dr-real-vps-checklist.md`.
- [ ] Interactive reboot drill.
- [ ] Real Slack/webhook delivery test — deliberately **last**.
