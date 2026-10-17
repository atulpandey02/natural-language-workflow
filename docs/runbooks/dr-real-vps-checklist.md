# Checklist: real-provider / real-VPS DR drill (human-gated)

The disposable drill (`scripts/ops/dr-drill.sh`) proves the **mechanism** against
a **MinIO / local-Docker fixture** — it is **not** proof of a real off-host
provider or a real VPS restore. Before production go-live, run this drill against
the **real** provider on a **disposable** VPS. Every step here is an operator
action; nothing in the M11.5 P2 package performs it.

> **Never** run a destructive restore against a live production environment as a
> drill. Use a throwaway host and, ideally, a **separate drill bucket/repo path**.

## Prepare

- [ ] A disposable recovery VPS (same shape as prod) with Docker + repo at `/opt/nlw`.
- [ ] `RESTIC_PASSWORD` and object-store credentials available (from the secret
      store, not the primary VPS).
- [ ] Roles bootstrapped from IaC on the drill DB; runtime services **not** started.

## Backup side (against the real provider)

- [ ] Take a fresh backup to the real repository and confirm
      `nlw_backup_success 1`, `nlw_backup_repository_verify_success 1`, and that
      `nlw_backup_last_success_timestamp_seconds` advanced.
- [ ] `restic snapshots` lists the snapshot; confirm objects exist in the bucket.
- [ ] Confirm the object store is a **different failure domain** than the VPS
      (separate account/region/vendor).

## Ransomware-resistance verification (only if you claim it)

- [ ] Object-lock/immutability is enabled and a delete of a locked object is
      **rejected**.
- [ ] The automated backup credential **cannot** `DeleteObject`; pruning uses a
      separate, human-gated credential.
- [ ] Versioning + account MFA on. *Until all of these hold, do not claim
      ransomware resistance.*

## Restore side (measure RPO/RTO honestly)

- [ ] Note the **snapshot age** at restore start (this is your observed RPO input).
- [ ] Start a stopwatch. Run [dr-fresh-host-restore](dr-fresh-host-restore.md)
      against the real repository.
- [ ] Every validation check is `[ok]`; note the **wall-clock** to a validated,
      runtime-ready DB (observed RTO — include provider download time, which the
      local drill does not).
- [ ] Confirm quiescence counts are sane and `restore_ready` is true before any
      runtime start.
- [ ] **Deletion log** (see
      [offboarding-and-deletion](../security/offboarding-and-deletion.md)):
      before any runtime starts, while the recovery lock holds the restored
      database, run `python -m nlw.ops.datasets reapply-receipts` against the
      environment's deletion log (step 6b of
      [dr-fresh-host-restore](dr-fresh-host-restore.md)). Record
      `deletion_log_step: applied` only when it exited 0 (no conflict, no
      unreadable receipt, no unexpected object, no unreadable workspace
      receipt). Only an environment that has never had a deletion log, and
      therefore no dataset store, records
      `deletion_log_step: not_applicable_no_deletion_log` (with
      `objects_step: not_applicable_no_dataset_store`; any other combination
      fails the evidence check). "No offboarding yet" is no longer accepted:
      workspace offboarding exists (ADR-037).
- [ ] **Dataset objects** (ADR-036): after the deletion log step, restore the
      objects (step 6c of [dr-fresh-host-restore](dr-fresh-host-restore.md))
      and record `objects_step: restored_and_verified` only when
      `restore-objects` and `verify-objects` both exited 0. Where no dataset
      store is configured, record `objects_step: not_applicable_no_dataset_store`.

## Record & decide

- [ ] Record measured backup duration, snapshot age, and restore wall-clock
      against the objectives (**RPO ≤ 24h**, **RTO ≤ 4h**). These are the numbers
      that justify (or refute) the objectives for production — the local drill's
      numbers do not.
- [ ] Write the drill record as JSON from the drill's own outputs (validator
      JSON, recorded timestamps; repository **redacted**, no credentials) to
      `docs/ops/dr-drills/<date>.json` and evaluate it:
      `python -m nlw.ops.dr_evidence check docs/ops/dr-drills/<date>.json`.
      Only a `PASS` from the tool is reported as a passed drill; a `FAIL` is
      filed with its reasons. Fields: see `nlw.ops.dr_evidence.DrillRecord`.
- [ ] Tear down the disposable VPS. If you used the production repo, prune the
      drill's test snapshot with a human-gated delete credential.

## Cadence

- [ ] Re-run at least once per quarter and after any change to the backup image,
      schema, or provider configuration.
