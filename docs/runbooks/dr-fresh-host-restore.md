# Runbook: disaster-recovery restore onto a fresh host

Restores NLW PostgreSQL state from an encrypted off-host backup onto a **new**
recovery host, then **quiesces** and **validates** before any runtime service may
start. See [ADR-022](../adr/ADR-022-encrypted-offhost-backup-dr.md).

> **Scope.** This restores **NLW application Postgres state only** (users,
> workspaces, connectors, workflows, versions, runs, schedules, approvals,
> external-action audit). It does **not** restore **Supabase Auth** (accounts,
> passwords, sessions, JWT signing keys) — that is a **separate DR dependency**
> with its own backup/restore. Full-platform recovery needs both.

> **This is destructive and human-gated.** The restore refuses to run unless
> `NLW_RESTORE_CONFIRM` exactly equals `NLW_RESTORE_TARGET_ID`, no runtime role is
> connected, and the target database is empty.

## Preconditions

1. A recovery host with Docker + the repo checked out at `/opt/nlw`.
2. The **repository encryption passphrase** (`RESTIC_PASSWORD`) and the object-store
   credentials — stored **separately** from each other and off the failed VPS.
3. A **fresh** database whose roles are bootstrapped from IaC
   (`docker/postgres/initdb`) — the app/worker/scheduler/rls-bypass/workspace
   roles must exist (ownership is reinstated onto them during restore) — but with
   **no application tables** yet.
4. `/opt/nlw/.env.restore` filled from [`.env.restore.example`](../../.env.restore.example)
   (mode 0600). Set `NLW_RESTORE_TARGET_ID` to the exact fresh target and
   `NLW_RESTORE_CONFIRM` to the same value to authorize the destructive restore.

## Steps

1. **Confirm the runtime is DOWN.** Do not start api/worker/scheduler. The restore
   asserts no `nlw_app`/`nlw_worker`/`nlw_scheduler` connection exists.

2. **(Optional) inspect available snapshots:**
   ```bash
   docker compose -f docker-compose.prod.yml --profile restore run --rm \
     --entrypoint restic restore snapshots
   ```
   Set `NLW_RESTORE_SNAPSHOT` to `latest` (default) or a specific id.

3. **Run the guarded restore** (does restic restore → manifest+hash verify →
   `pg_restore` (ownership preserved) → flush Redis → **quiesce** → **validate**):
   ```bash
   docker compose --env-file /opt/nlw/.env.restore \
     -f docker-compose.prod.yml --profile restore run --rm restore
   ```
   It exits non-zero on any failure (bad confirmation, non-empty target, active
   runtime, hash mismatch, failed validation). On success it prints the validation
   summary and the number of non-terminal runs quiesced.

4. **Review the validation summary.** Every check must be `[ok]`, including
   `security_definer_owners_and_search_path`, `rls_enabled_and_forced`,
   `runtime_roles_nosuperuser_nobypassrls`, `non_terminal_runs_quiesced`, and
   `dr_restore_event_recorded`. A single failure means **do not go live** —
   see [backup-failure-troubleshooting](backup-failure-troubleshooting.md).

5. **Understand what quiescence did** (see
   [post-restore-quiescence](post-restore-quiescence.md)): in-flight runs/steps
   were marked `FAILED` with `DR_RESTORE_UNCERTAIN`; ambiguous external actions
   were set to `unknown`; stale schedules were recomputed after the recovery
   cutoff. This is deliberate — it prevents replaying already-delivered side
   effects and missed schedule occurrences.

6. **Only now start the runtime.** The runtime-start gate (`restore_ready`) is
   satisfied (a `dr_restore_events` row exists and no non-terminal runs remain).
   Point `DATABASE_URL` at the restored DB and bring up api → worker → scheduler.

7. **Record** the incident: snapshot id/age, the measured RTO, the quiescence
   counts, and (if a real provider) note it in `docs/incidents/`.

## Data-loss expectation (RPO)

Everything written **after** the restored snapshot is lost, bounded by the backup
interval (objective **RPO ≤ 24h**). Sub-daily RPO requires PITR, which is **not**
configured — see [pitr-boundary](../ops/pitr-boundary.md). Notify affected tenants
that runs/actions in the lost window may need to be re-submitted, and that
`DR_RESTORE_UNCERTAIN` runs completed with an unknown external-effect status.

## Verifying the mechanism before you need it

Run the disposable drill (`scripts/ops/dr-drill.sh`, MinIO fixture) to prove the
mechanism locally, and do a real-provider dry run per
[dr-real-vps-checklist](dr-real-vps-checklist.md) before go-live.
