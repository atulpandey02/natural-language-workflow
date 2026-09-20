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
- [restore-from-backup.md](restore-from-backup.md)
- [rotate-secret.md](rotate-secret.md) — connector secrets (worker env `NLW_SECRET_*`)
- [rotate-db-role-password.md](rotate-db-role-password.md) — DB runtime role passwords (`ALTER ROLE`)
- [disable-tenant-connector.md](disable-tenant-connector.md)
- [rate-limit-tuning.md](rate-limit-tuning.md)
- [inspect-failed-run.md](inspect-failed-run.md)
