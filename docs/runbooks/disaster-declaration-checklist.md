# Checklist: declaring a disaster & deciding to restore

A restore is destructive and loses data after the last snapshot. Use this
checklist before invoking [dr-fresh-host-restore](dr-fresh-host-restore.md). This
is a decision aid, not automation.

## 1. Confirm it is actually a disaster

- [ ] The primary database is **lost or unrecoverable** (corrupt, deleted, host
      gone) — not a transient outage. For a transient DB outage, prefer
      [postgres-unavailable](postgres-unavailable.md); Redis loss is
      [redis-unavailable](redis-unavailable.md) (transport only, no restore).
- [ ] In-place recovery (fsck, failover, provider snapshot rollback) has been
      ruled out or is slower than restore.

## 2. Confirm you can recover before you destroy anything

- [ ] You have the **`RESTIC_PASSWORD`** (repo encryption key) — stored off the
      failed host. *Without it, no backup is recoverable.*
- [ ] You have the **object-store credentials** and the repository is reachable
      (`restic snapshots` lists snapshots).
- [ ] The most recent snapshot **verifies** (`restic check`) and its age is
      acceptable for the RPO you can tolerate.

## 3. Decide the recovery target

- [ ] A **fresh** recovery host/DB with roles bootstrapped from IaC
      (`docker/postgres/initdb`) and **no application tables**.
- [ ] The runtime (api/worker/scheduler) will stay **down** until validation +
      quiescence pass.
- [ ] `NLW_RESTORE_TARGET_ID` chosen and `NLW_RESTORE_CONFIRM` set to match.

## 4. Understand the blast radius before you start

- [ ] Data written after the snapshot **will be lost** (bounded by RPO ≤ 24h; no
      PITR — see [pitr-boundary](../ops/pitr-boundary.md)).
- [ ] In-flight runs/actions will be **quiesced** (marked FAILED /
      `DR_RESTORE_UNCERTAIN`, ambiguous actions → `unknown`) — some external side
      effects may already have fired. See
      [post-restore-quiescence](post-restore-quiescence.md).
- [ ] **Supabase Auth is separate** — if identity was also lost, recover it via
      its own backup/restore; NLW restore alone is not full-platform DR.

## 5. Communicate

- [ ] Notify stakeholders: incident declared, expected downtime (RTO objective
      ≤ 4h), and the data-loss window.
- [ ] Prepare tenant messaging for `DR_RESTORE_UNCERTAIN` runs and re-submission
      of work in the lost window.

## 6. Execute & record

- [ ] Follow [dr-fresh-host-restore](dr-fresh-host-restore.md).
- [ ] Record snapshot id/age, measured RTO, quiescence counts, and validation
      result. File a postmortem in `docs/incidents/`.

## 7. Enable the runtime (separate, explicit)

- [ ] The runtime is **database-locked** after restore: api/worker/scheduler
      refuse to start (non-zero exit; `nlw.backup startup-check` exits 6, the
      worker exits 1 with `WorkerBootRefused`) against the restored generation
      until it is explicitly enabled — regardless of any env flag or file. A
      service started too early restart-loops without processing anything and
      its healthcheck fails on `recovery_lock`. Enable it with the operator
      credential: `nlw.backup enable-runtime` (exact newest validated generation +
      project confirmation). See [dr-fresh-host-restore](dr-fresh-host-restore.md)
      steps 6–8.
- [ ] Only then start api/worker/scheduler. Starting the runtime does **not** replay
      restored work (quiescence handled it); confirm no duplicate side effects.

## 8. After go-live

- [ ] Confirm a **new backup** succeeds and verifies against the recovered host.
- [ ] Confirm the dead-man metric is fresh and alerts are green.
