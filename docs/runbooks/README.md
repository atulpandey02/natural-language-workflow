# Runbooks

Operational procedures for on-call and recovery — one per failure mode. All
diagnosis uses the correlation keys (`run_id` end-to-end, `request_id` for the
control plane) and the internal Prometheus metrics (ADR-016).

- [postgres-unavailable.md](postgres-unavailable.md)
- [redis-unavailable.md](redis-unavailable.md)
- [worker-stuck.md](worker-stuck.md)
- [scheduler-lagging.md](scheduler-lagging.md)
- [runs-beyond-horizon.md](runs-beyond-horizon.md) — poisoned-run guard (req 4)
- [failed-migration.md](failed-migration.md)
- [restore-from-backup.md](restore-from-backup.md) — pointer to the DR restore below
- **Disaster recovery (M11.5 P2, ADR-022):**
  - [backup-operations.md](backup-operations.md) — run/inspect backups, metrics, retention
  - [backup-failure-troubleshooting.md](backup-failure-troubleshooting.md) — backup/restore alerts & failures
  - [disaster-declaration-checklist.md](disaster-declaration-checklist.md) — decide to restore
  - [dr-fresh-host-restore.md](dr-fresh-host-restore.md) — guarded fresh-host restore
  - [post-restore-quiescence.md](post-restore-quiescence.md) — what quiescence changes & why
  - [dr-real-vps-checklist.md](dr-real-vps-checklist.md) — real-provider/real-VPS drill (human-gated)
- [staging-signed-context-rollout.md](staging-signed-context-rollout.md) — phased, gated M12A upgrade (0010 → 0016) of the staging VPS; read-only by default
- [signed-context-keys.md](signed-context-keys.md) — **security sensitive**: signed DB context keys (M11.5 P3B, ADR-024): deployment order, install/rotate/revoke, rollback warning
- [rotate-secret.md](rotate-secret.md) — connector secrets (worker env `NLW_SECRET_*`)
- [rotate-db-role-password.md](rotate-db-role-password.md) — DB runtime role passwords (`ALTER ROLE`)
- [rotate-exposed-secrets.md](rotate-exposed-secrets.md) — rotate exposed migration/Anthropic/Supabase secrets
- [disable-tenant-connector.md](disable-tenant-connector.md)
- [rate-limit-tuning.md](rate-limit-tuning.md)
- [inspect-failed-run.md](inspect-failed-run.md)
- [action-outcome-unknown.md](action-outcome-unknown.md) — reconcile an ambiguous (UNKNOWN) external action
