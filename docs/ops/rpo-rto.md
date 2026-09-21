# RPO / RTO — objectives, not guarantees

For the pilot's disaster recovery ([ADR-022](../adr/ADR-022-encrypted-offhost-backup-dr.md)).
These are **objectives** the design targets, **not** contractual guarantees, and
**not** proven by any single local drill.

## Objectives

| Metric | Objective | Basis |
|---|---|---|
| **RPO** (max data loss) | **≤ 24h** | daily logical backup via systemd timer |
| **RTO** (time to recover) | **≤ 4h** | fresh-host restore + quiesce + validate, human-gated |

## What "objective, not guarantee" means

- **RPO** is bounded by the **backup interval**, not by a replication stream.
  Everything written between the last verified snapshot and the incident is lost.
  A sub-daily RPO would require continuous WAL archiving + PITR, which is **not**
  configured — see [pitr-boundary](pitr-boundary.md).
- **RTO** depends on real-world factors the local drill does not capture: provider
  **download** time for the encrypted repo, host provisioning, human decision
  time (see [disaster-declaration-checklist](../runbooks/disaster-declaration-checklist.md)),
  and database size. The drill measures only the local mechanism.

## Evidence and its limits

The disposable drill (`scripts/ops/dr-drill.sh`) measures the **mechanism** against
a **MinIO / local-Docker fixture**:

- It proves: encrypted off-host backup → verification → source destruction →
  fresh-host restore → quiescence → deep validation, end to end, with the security
  posture (ownership, RLS/FORCE RLS, SECURITY DEFINER owners) intact.
- It does **not** prove: a real provider's throughput/durability, a real VPS
  restore, or the RPO/RTO **objectives**. Local backup/restore durations are
  seconds because there is no network egress and the dataset is tiny — do **not**
  quote them as the production RTO.

To validate the objectives against reality, run
[dr-real-vps-checklist](../runbooks/dr-real-vps-checklist.md) on a disposable VPS
against the real provider and record the measured numbers there.

## Dependencies outside this RPO/RTO

- **Supabase Auth** (identity) has its **own** backup/restore and its own RPO/RTO.
  Full-platform recovery needs both. NLW's Postgres restore alone is not
  full-platform DR.
- **Redis** is transport only — no backup, no RPO contribution; the reconciler
  rebuilds recovery eligibility from Postgres after Redis loss.
