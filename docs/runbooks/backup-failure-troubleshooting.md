# Runbook: backup / restore failure troubleshooting

For the alerts in [`backup.rules.yml`](../../docker/prometheus/alerts/backup.rules.yml)
and restore failures. Logs never print secrets; errors are sanitized to a class
name on the CLI and full detail goes to journald.

## `NlwBackupStale` (dead-man — CRITICAL)

No verified backup within the freshness budget, **or the metric is absent**.

1. `systemctl list-timers nlw-backup.timer` — is the timer active and firing?
2. `journalctl -u nlw-backup.service -n 200` — did recent runs fail?
3. Is node_exporter's `--collector.textfile.directory` still pointed at the
   metrics dir, and does `nlw_backup.prom` exist and update?
4. If the timer stopped: `systemctl enable --now nlw-backup.timer`. Run one now:
   `systemctl start nlw-backup.service`. Confirm the timestamp advances.

## `NlwBackupFailed` (last run exited non-zero)

Read `journalctl -u nlw-backup.service`. Common causes:

- **Fail-closed config** in staging/production: a missing `RESTIC_REPOSITORY` /
  `RESTIC_PASSWORD` / `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
  `NLW_BACKUP_DATABASE_URL` raises at startup. Fix `.env.backup`.
- **Object store unreachable / 403:** bad keys, wrong bucket/region, or the
  provider rejecting the request. Verify with
  `--entrypoint restic backup snapshots`.
- **`pg_dump` failed:** DB unreachable or the connection role lacks privilege for
  a complete dump. The backup role must be owner/superuser.
- The last-success timestamp was **not** advanced (correct), so recovery point is
  the previous good backup.

## `NlwBackupVerifyFailed` (repository verification failed — CRITICAL)

`restic check` failed: the repository may be corrupt/unreadable. Treat as **no
usable backup**.

1. Re-run `restic check` (`--entrypoint restic backup check`).
2. `restic check --read-data-subset=10%` to sample pack integrity.
3. If corruption is confirmed, take a fresh full backup to a **new** repository
   path and investigate the object store. Do not prune the old repo until the new
   one is verified.

## `NlwBackupRetentionFailed` (prune failed — WARNING)

Backups are still taken/verified, but the repo may grow.

- If provider **object-lock/immutability** is enabled, prune cannot delete locked
  objects — this may be expected; run human-gated pruning with a credential that
  can delete, and size the bucket accordingly.
- Otherwise check for a stale restic **lock** (an interrupted run):
  `--entrypoint restic backup unlock` (only when no backup is in progress).

## Backup "already running" (exit 3)

A second backup found the `flock` held (manual run racing the timer, or a duplicate
timer). This is expected and safe — the second process ran no dump/upload/prune and
did not touch metrics. If it recurs, check for a stuck first process
(`systemctl status nlw-backup.service`) or a duplicate timer. A leftover lock
*file* does not block anything; only a live holder does.

## Restore failures

- **`restore refused: NLW_RESTORE_CONFIRM must exactly equal
  NLW_RESTORE_TARGET_ID`** — intentional destructive-confirmation gate. Set both
  to the exact fresh target id.
- **`target database not empty`** — restore refuses to overwrite. Use a genuinely
  fresh DB (roles bootstrapped, no application tables).
- **`runtime services are running in the restore project`** (RuntimeActive) — the
  scoped Compose probe found api/worker/scheduler/web up (even if idle). Stop them
  in that project first.
- **`cannot inspect Compose runtime state` / `no Compose project to scope`**
  (RuntimeStateUnknown) — the guard failed closed because it could not determine
  runtime state. Give the restore docker access, run the host preflight and set
  `NLW_RESTORE_RUNTIME_GUARD` accordingly, or set `NLW_RESTORE_COMPOSE_PROJECT`.
- **`runtime services appear active`** — an `nlw_app`/`worker`/`scheduler` DB
  connection exists (defense-in-depth session check). Stop the runtime first.
- **gate-check failed (exit 4)** — a runtime service (restore mode) found a
  missing/malformed/stale/cross-DB/wrong-project restore-ready file gate
  (defense-in-depth). Ensure the restore completed and wrote the gate for THIS DB.
- **startup blocked by the recovery lock (exit 6 / RecoveryLocked)** — the
  AUTHORITATIVE database lock: the newest `dr_restore_events` generation is not
  operator-enabled (or is quiesced-but-not-validated). api/worker/scheduler refuse
  to start until you run `nlw.backup enable-runtime` for the exact newest validated
  generation. `RecoveryStateUnknown` means the state could not be read (e.g. missing
  grant/columns) — fail closed; check the migration ran and the grant is present.
- **enable-runtime rejected (exit 5)** — the supplied generation is not the newest
  validated one, or the project confirmation does not match. Re-query the newest
  `dr_restore_events` id and confirm the project.
- **manifest hash mismatch** — the decrypted artifact does not match the recorded
  sha256; the snapshot is corrupt. Restore an earlier snapshot.
- **`restore validation FAILED`** — the restored security posture/invariants are
  wrong (e.g. a SECURITY DEFINER function not owned by its NOSUPERUSER role, RLS
  not forced, missing `dr_restore_events` row). **Do not go live.** Confirm the
  target roles were bootstrapped from IaC before restore (ownership is reinstated
  onto them) and that `pg_restore` preserved ownership (no `--no-owner`). Re-run
  the drill to reproduce.

## Escalation

If no verified backup exists and the primary is lost, recovery point is the last
good snapshot; data after it is lost (bounded by RPO). Communicate the window to
tenants per [dr-fresh-host-restore](dr-fresh-host-restore.md).
