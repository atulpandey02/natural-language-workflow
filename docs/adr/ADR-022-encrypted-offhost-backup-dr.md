# ADR-022 — Encrypted off-host backup & disaster recovery (M11.5 P2)

- Status: Accepted
- Date: 2026-09-21
- Supersedes the backup/restore mechanism of [ADR-018](ADR-018-production-topology-and-ops.md)
  (the `docker/scripts/backup.sh` / `restore.sh` gpg approach). ADR-018's policy
  framing (RPO/RTO objectives, Redis-is-transport, roles-from-bootstrap) stands.

## Context

The pilot had a documented backup *policy* (ADR-018, `docs/ops/backup-restore.md`)
but the *mechanism* had disaster-recovery deficiencies that a review confirmed
with tests (Part A):

1. **Success was defined as `pg_dump` exit 0**, not as a verified off-host object.
   A dump that never left the host — or a silently corrupt repository — still
   "succeeded." There was no repository verification and no proof of off-host
   durability.
2. **No freshness / dead-man signal.** A backup timer that silently stopped
   firing produced no alert; the last-known-good age was unobservable.
3. **Restore had no destructive guards.** Nothing stopped a restore from running
   against a live database, and nothing required the runtime (worker/scheduler)
   to be down first.
4. **No post-restore quiescence.** A logical restore reinstates rows *as they
   were mid-flight*: non-terminal runs, leased external actions, and schedules
   whose `next_run_at` is now in the past. Starting the runtime against such a
   snapshot **re-drives already-delivered side effects** (duplicate webhooks /
   Slack messages) and replays missed schedule occurrences. This is the critical
   correctness gap.
5. **Secrets could leak** into the backup DB URL on argv, into manifests, or by
   the runtime services inheriting backup credentials.

This is a single-VPS pilot. The fix is small, PostgreSQL-native, and
operator-driven — **not** Kubernetes, not an enterprise backup platform, not
custom cryptography, not multi-region replication.

## Decision

### Encrypted off-host backup via restic (S3-compatible)

- **restic** is the backup engine: client-side-encrypted (AES-256 + Poly1305,
  repository-key model — we do **not** implement cryptography), content-addressed
  dedup, snapshotting, `check` verification, `forget --prune` retention, and repo
  locking that prevents overlapping runs. Backend is any **S3-compatible** object
  store (AWS S3, Backblaze B2, MinIO for drills) via the `s3:` repository URL —
  the platform is **provider-neutral**.
- **What is backed up:** a `pg_dump` **custom format** (`-F c`, owner/superuser
  connection so the dump is complete under FORCE RLS) plus
  `pg_dumpall --roles-only --no-role-passwords` (role *names* only — never
  passwords). Roles/bootstrap are reinstated from version-controlled IaC
  (`docker/postgres/initdb`), so a backup never carries a role password.
- **A JSON manifest** (`nlw-backup/1`) records format version, `pg_version`,
  `alembic_revision`, `app_version`, per-artifact sha256 + byte counts, and tool
  versions. It is asserted **secret-free** (no `password`/`token`/`://`/`@`…) and
  written `0600`. Restore re-verifies every artifact's sha256 before `pg_restore`.

### Success = verified off-host, never `pg_dump` exit 0

The orchestrator (`nlw.backup.backup.run_backup`) runs a fixed sequence and a run
is a success **only** if every off-host step passed:
`config → db_info → dump → manifest → ensure_repo → backup(off-host) → check(verify)
→ verify snapshot present → forget/prune → metrics`. Retention pruning is refused
if verification failed. The freshness timestamp
(`nlw_backup_last_success_timestamp_seconds`) advances **only** on a verified
off-host snapshot; a local dump that never reached the repo preserves the prior
value (proven by `tests/unit/test_backup_orchestrator.py`).

### Fail-closed config + secret isolation

- Backup/restore settings live in their **own** Pydantic model
  (`nlw.backup.config`), never in `nlw.core.config.Settings`, so the API / worker
  / scheduler / web / migrate services can never inherit backup credentials.
- In `staging`/`production` the config **fails closed**: missing
  `RESTIC_REPOSITORY`, `RESTIC_PASSWORD`, `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY`, or `NLW_BACKUP_DATABASE_URL` raises at construction.
- Secrets are `SecretStr` (masked in logs/reprs), passed to `restic`/`pg_dump`
  via a **sanitized child environment** (`restic_env()` / `PGPASSWORD`), **never
  on argv**. `restic_env()` forwards only restic's own secrets, not the parent
  process environment.
- Compose isolation: the `backup` and `restore` services are one-shot
  (`profiles`, `restart: "no"`), carry dedicated `RESTIC_*` / `*_AWS_*` /
  `NLW_BACKUP_*` / `NLW_RESTORE_*` vars, and do **not** consume the shared
  `x-app-env` anchor (proven by `tests/unit/test_backup_compose_isolation.py`).

### Scheduling via systemd timer, not the app scheduler

Backups run from a **systemd timer** (`docker/systemd/nlw-backup.timer`,
`Type=oneshot`, daily `OnCalendar=03:00` + `RandomizedDelaySec=3600` +
`Persistent=true`), **not** the in-app Dramatiq scheduler. Backups must survive
the app being wedged; coupling them to the thing they exist to recover from would
be self-defeating.

### Freshness / dead-man metrics + alerts

The job atomically writes a node_exporter **textfile**
(`nlw_backup.prom`, temp + `os.replace`) with `nlw_backup_success`,
`nlw_backup_duration_seconds`, `nlw_backup_repository_verify_success`,
`nlw_backup_retention_success`, and `nlw_backup_last_success_timestamp_seconds`.
Prometheus alerts (`docker/prometheus/alerts/backup.rules.yml`) fire on a failed
run, a failed verification, and — the **dead-man** — a last-success age exceeding
the freshness budget or a **missing** metrics series (the timer stopped firing).

### Safe, guarded restore

`nlw.backup.restore.run_restore` fails closed unless
`NLW_RESTORE_CONFIRM == NLW_RESTORE_TARGET_ID` (an explicit, per-target
destructive confirmation). It then asserts **no runtime connections**
(`pg_stat_activity` for the app/worker/scheduler roles) and an **empty target**
(no public tables) before restoring; it re-verifies the manifest, runs
`pg_restore`, flushes Redis, **quiesces**, then **validates**.

### Mandatory post-restore quiescence (correctness core)

`nlw.backup.quiescence.quiesce` runs as owner/superuser in a single transaction
against a static 13-point transition matrix (bound params, never an f-string in
`text()`):

- Non-terminal **runs** (`PENDING/RUNNING/WAITING_APPROVAL/…`) → `FAILED` with
  `error = DR_RESTORE_UNCERTAIN`; terminal runs untouched.
- Non-terminal **steps** → `FAILED` with the same reason.
- **External actions** in a non-final delivery state → `unknown`
  (`error_class = ACTION_OUTCOME_UNKNOWN`, lease cleared, `next_attempt_at`
  NULL) — reusing P1C UNKNOWN semantics so an at-least-once side effect that may
  already have fired is **never blindly re-driven**.
- **Schedules** with `next_run_at <= cutoff` are recomputed with the existing
  `next_occurrence` math so missed occurrences are **not** replayed.

It is **idempotent** (transitions target only non-terminal / pre-cutoff state)
and **audited**: a `dr_restore_events` row (Alembic `0014`, no runtime-role grant,
outside RLS → non-forgeable) records the cutoff, manifest identity, and counts.
The runtime-start gate (`restore_ready`) permits worker/scheduler start **only**
after a `dr_restore_events` row exists and no non-terminal runs remain.

### Deep restore validation

`nlw.backup.validate.validate_restore` asserts the restored database's security
posture and invariants survived: alembic head, required tables, critical
constraints, P1D reconciler indexes, roles present + runtime roles are
`NOSUPERUSER`/`NOBYPASSRLS`, table ownership by a privileged owner, RLS enabled
**and forced**, `SECURITY DEFINER` owners + `search_path`, no `PUBLIC EXECUTE` on
SECURITY DEFINER functions, external-action key `NOT NULL`, non-terminal runs
quiesced, no pending external actions, a `dr_restore_event` recorded, schedules
after the recovery cutoff, and a read-only verification query.

## Alternatives considered

- **Keep gpg + `pg_dump` (ADR-018).** Rejected: no dedup, no built-in
  verification, no snapshot/retention model, and the "success = exit 0" gap.
- **pgBackRest / WAL-G with PITR.** Deferred (see PITR boundary below). Real
  continuous WAL archiving + PITR is pre-production work with its own restore
  drills; claiming a 5-minute RPO now would be dishonest.
- **Physical (base-backup) instead of logical.** Rejected for the pilot: logical
  dumps are version-portable and let us restore into a *fresh* host cleanly;
  physical backups tie RPO to WAL and couple restore to exact PG builds.
- **App-scheduler-driven backups.** Rejected: must survive a wedged app.

## Consequences

- **RPO/RTO are objectives, not guarantees.** Targets: **RPO ≤ 24h** (daily
  logical backup), **RTO ≤ 4h** (fresh-host restore + quiesce + validate). A
  single local MinIO drill measures the *mechanism's* backup/restore duration —
  it is **not** proof of a real-provider or real-VPS objective. See
  `docs/ops/rpo-rto.md`.
- **PITR boundary.** Data written between the last backup and the incident is
  lost (bounded by RPO). Sub-daily RPO requires WAL archiving + PITR (WAL-G /
  pgBackRest), which is explicitly **future** work. See `docs/ops/pitr-boundary.md`.
- **Ransomware resistance is conditional.** Client-side encryption protects
  confidentiality. Resistance to *deletion* of backups requires object-lock /
  append-only, versioning, and isolated credentials at the provider — an operator
  gate documented in `docs/ops/backup-providers.md`, **not** claimed by default.
- **Supabase Auth is a separate DR dependency.** This restores NLW application
  Postgres state only. Full-platform recovery also needs the identity provider's
  own backup/restore.
- Adds an operational surface (a second image, a timer, provider credentials) but
  no new runtime dependency and no architectural boundary change.
