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

## Record & decide

- [ ] Record measured backup duration, snapshot age, and restore wall-clock
      against the objectives (**RPO ≤ 24h**, **RTO ≤ 4h**). These are the numbers
      that justify (or refute) the objectives for production — the local drill's
      numbers do not.
- [ ] File the drill result (date, provider, measured RPO/RTO, issues) under
      `docs/incidents/` or an ops log.
- [ ] Tear down the disposable VPS. If you used the production repo, prune the
      drill's test snapshot with a human-gated delete credential.

## Cadence

- [ ] Re-run at least once per quarter and after any change to the backup image,
      schema, or provider configuration.
