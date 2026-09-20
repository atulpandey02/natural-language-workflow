# Real-VPS staging validation checklist (required before M12)

CI ephemeral evidence (staging-validation.yml) proves the LOGIC. This checklist
produces the AUTHORITATIVE staging evidence on a real host. Keep this evidence
separate from CI (D3).

Prerequisites:
- A VPS (record vCPU/RAM/disk) running `docker-compose.prod.yml` with the exact
  GHCR image digests intended for production.
- A real Supabase project (JWKS/asymmetric) + `PUBLIC_HOSTNAME` with DNS.
- Caddy ACME TLS; verify clients TRUST the cert (no ignoreHTTPSErrors).
- Real Slack workspace + a real webhook receiver (idempotency-aware) for actions.
- Off-host encrypted backup destination configured.

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
