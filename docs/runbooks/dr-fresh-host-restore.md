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

2a. **Confirm runtime services are stopped (scoped preflight).** The restore
   inspects Compose runtime state scoped to `NLW_RESTORE_COMPOSE_PROJECT` and fails
   closed if `api`/`worker`/`scheduler`/`web` are running (a running-but-idle
   container still blocks — a DB-session check alone is not enough) or if state
   cannot be determined. If the restore container has no docker access, run the
   scoped preflight on the host first:
   ```bash
   docker compose -p "$NLW_RESTORE_COMPOSE_PROJECT" ps --status running --services
   # must list NONE of: api worker scheduler web
   ```

3. **Run the guarded restore** (runtime-state guard → no-runtime-connections →
   empty-target → restic restore → manifest+hash verify → `pg_restore` (ownership
   preserved) → flush Redis → recheck runtime → **quiesce** → **validate** → write
   the **restore-ready gate**):
   ```bash
   docker compose --env-file /opt/nlw/.env.restore \
     -f docker-compose.prod.yml --profile restore run --rm restore
   ```
   It exits non-zero on any failure (bad confirmation, runtime active/undeterminable,
   non-empty target, hash mismatch, failed validation). On success it prints the
   validation summary, the number of non-terminal runs quiesced, and the gate
   generation. The runtime-state guard is rechecked immediately before the
   destructive `pg_restore` and again before quiescence (TOCTOU).

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

6. **Runtime is DATABASE-LOCKED until you explicitly enable it.** The restore
   marked this generation *validated* in `dr_restore_events` but left
   `runtime_enabled_at` NULL, so it is **locked**. api/worker/scheduler run a
   **mandatory** startup preflight that reads this DB state — **regardless of any
   env flag, compose profile, or mounted file** — and refuse to start while the
   newest generation is not enabled. (The file gate / `NLW_RESTORE_MODE` /
   `gate-check` are now defense-in-depth and a binding artifact; the **database is
   the authority**.) Attempting to start a service now fails closed (exit 6).

7. **Operator ENABLE — a separate, explicit command (operator credential).** Get the
   generation id and enable exactly it:
   ```bash
   # the newest restore generation id (operator/owner credential):
   psql "$NLW_RESTORE_DATABASE_URL" -tAc \
     "SELECT id FROM dr_restore_events ORDER BY restored_at DESC LIMIT 1"
   NLW_RESTORE_EVENT_ID=<that-id> \
   NLW_RESTORE_COMPOSE_PROJECT=<exact-project> \
   NLW_RESTORE_OPERATOR="$(whoami)" \
   docker compose --env-file /opt/nlw/.env.restore \
     -f docker-compose.prod.yml --profile restore run --rm \
     --entrypoint "python -m nlw.backup" restore enable-runtime
   ```
   `enable-runtime` uses the restore/operator credential (never a runtime role),
   requires the exact newest **validated** generation and the project confirmation,
   records the server-side enablement time + operator, and is idempotent for the
   same already-enabled generation. It does **not** start any container.

8. **Only now start the runtime.** Bring up api → worker → scheduler; each passes
   the startup preflight (the generation is enabled) and serves. Starting the
   runtime does **not** replay restored work (quiescence neutralized it). A **later**
   restore inserts a new locked generation, so this enablement cannot authorize it —
   you must enable the new generation explicitly.

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
