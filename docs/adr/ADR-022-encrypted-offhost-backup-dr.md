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
  dedup, snapshotting, `check` verification, and `forget --prune` retention.
  Backend is any **S3-compatible** object store (AWS S3, Backblaze B2, MinIO for
  drills) via the `s3:` repository URL — the platform is **provider-neutral**.
  (restic's repository lock guards the repo during its own operation; it is **not**
  relied on as proof of single execution — see the flock below.)
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

## Operational-safety addendum (M11.5 P2)

Five operational-safety hardenings on top of the accepted architecture; no schema
change (migration `0014` unchanged).

- **(A) Single backup execution.** An explicit host/process `flock`
  (`nlw.backup.locking`) wraps the ENTIRE backup lifecycle on a shared runtime
  volume (`backup_run` → `/run/nlw/backup.lock`), acquired before any dump/temp
  artifact. A second process exits **3** ("already running") and runs no
  dump/upload/prune/metrics. Released on success/failure/signal/death (advisory
  lock keyed to the fd). restic's repo lock is defense in depth, **not** the proof
  of single execution. Proven by a real multi-process test.
- **(B) Runtime services proven stopped for restore.** Beyond the DB-session
  check, the restore inspects Compose runtime state **scoped to the exact project
  and service names** (`nlw.backup.runtime_guard`), fails closed if any of
  api/worker/scheduler/web is running OR if state is undeterminable, and rechecks
  immediately before the destructive restore and before quiescence (TOCTOU).
  Network isolation from the runtime is achieved by running restore as a separate
  Compose project on a fresh host (where those services are not defined).
- **(C) Enforceable runtime-start gate — DATABASE-authoritative.** The gate is
  `dr_restore_events` itself (runtime roles cannot write it). The restore leaves the
  newest generation *validated* but with `runtime_enabled_at` NULL (LOCKED). Every
  api/worker/scheduler process runs a **mandatory** startup preflight
  (`nlw.backup.recovery_lock`, via the API lifespan, the scheduler main, and the
  worker's `RecoveryLockMiddleware.before_worker_boot`) that reads this state and
  fails closed unless the newest generation is validated **and** operator-enabled.
  The worker hook raises `WorkerBootRefused`, a subclass of Dramatiq's
  `MiddlewareError` — the one exception class the pinned framework's
  `Broker.emit_before` re-raises instead of logging and swallowing — so
  `Worker.start()` aborts before any consumer or worker thread exists and the
  `dramatiq` process exits non-zero (exit 1 under the CLI; the standalone
  `nlw.backup startup-check` preflight exits **6**). Under Compose
  (`restart: unless-stopped`) a locked worker therefore restart-loops without ever
  consuming, and the container healthcheck (`nlw.ops.healthcheck`) independently
  fails with `recovery_lock failed: RecoveryLocked`. Proven by
  `tests/unit/test_worker_boot_recovery_lock_inprocess.py` (real `Worker.start()`, every
  lock state) and `tests/integration/test_worker_boot_recovery_lock.py` (the real
  `dramatiq nlw.worker.actors` entrypoint against a locked/unreachable database) —
  **regardless of `NLW_RESTORE_MODE`, compose profile, or any mounted file**. This
  closes the earlier fail-open where an omitted `NLW_RESTORE_MODE` let services start
  against a restored DB. A never-restored DB (no event) starts normally; a reachable
  but indeterminate state fails closed (a pure connection failure is tolerated only
  by the API, preserving its DB-free liveness/readiness contract — a restored DB is
  reachable, so it is always evaluated). Runtime roles get only column-scoped SELECT
  on the lock-state columns (migration `0014`); only the operator credential can
  INSERT an event, mark it validated, or enable. A **separate** operator command
  `nlw.backup enable-runtime` performs the conditional, audited enable of the exact
  newest validated generation (idempotent; rejects stale/mismatched/unvalidated,
  exit **5**); a later restore re-locks (its new generation is not enabled). The
  file **restore-ready gate** (`nlw.backup.gate`, bound to generation +
  `system_identifier`, verified by `gate-check`, exit **4**) and the
  `NLW_RESTORE_MODE` entrypoint wrapper remain as **defense in depth** and a binding
  artifact — never the sole authority.
  - **Live API gate.** The worker/scheduler evaluate the lock once at boot and refuse
    to start; the API instead may stay ALIVE for DB-independent liveness, so it must
    not treat a boot-time connection failure as "allowed" and then serve forever. A
    live gate (`nlw.api.recovery_gate.RecoveryGate`) holds a three-valued state —
    `ALLOWED`/`LOCKED`/`UNKNOWN` (initial `UNKNOWN`, never allowed until proven) —
    refreshed from `dr_restore_events` on a short **bounded cache**
    (`recovery_gate_ttl_s`, default 5s) under a bounded query timeout
    (`recovery_gate_query_timeout_s`, default 2s). A **deny-by-default** middleware
    keeps only liveness/version/readiness available and returns a sanitized **503**
    (no ids/project/DB/exception text) on every other route unless `ALLOWED`;
    readiness reports a `recovery` component. Because the state is re-read on the
    cache boundary, a **running** API re-locks when a later restore generation
    appears, opens when the generation is enabled, and fails closed when the DB is
    lost after being allowed — all without a restart. Any query failure/timeout/
    malformed row → `UNKNOWN` (fail closed). Liveness never triggers a query.
- **(D) Retention vs immutable credentials.** Two explicit modes:
  `simple` (the job prunes; needs delete rights) and `immutable` (the writer has
  no delete rights; the job **never** prunes — a separate human-gated
  `nlw.backup prune` with off-VPS credentials does). Contradictory config
  (immutable + forced local prune) fails closed. Object-lock support is documented
  but **not** verified against a real provider.
- **(E) Functional post-restore drill.** The disposable drill proves startup is
  blocked before the gate, quiescence+validation produce the gate, a separate
  enable step passes gate-check, a brand-new post-restore run executes to
  COMPLETED, restored work is not replayed, and the gate cannot be reused for a
  second destination.

## Amendment 1 (2026-10-04) — the backup freshness series is actually scraped

**Finding.** The dead-man `NlwBackupStale` fired permanently on staging. The
backup job wrote `nlw_backup.prom` into the `backup_textfile` volume as designed,
but no exporter served it and Prometheus had no scrape target for it, so
`absent(nlw_backup_last_success_timestamp_seconds)` was always true: every
Prometheus start produced a false critical alert 15 minutes later, repeated
hourly to the operator channel, while real backups were succeeding. A
permanently firing critical alert trains operators to ignore real incidents.

**Decision.**

- The staging overlay adds `node-exporter` (`prom/node-exporter:v1.12.1`)
  with **only** the textfile collector (`--collector.disable-defaults
  --collector.textfile`), no host mounts, non-root (`65534`), read-only root
  filesystem, no capabilities, `no-new-privileges`, internal network only, no
  published port. It mounts `backup_textfile` **read-only** at `/textfile`.
- Prometheus scrapes it as job `nlw-backup` (`role=backup`).
- The evidence-volume invariant becomes: the backup job is the **only writer**;
  `node-exporter` is the **only other** service that may mount it, and only
  read-only. The rollout's `validate` mount-isolation gate and the compose tests
  enforce exactly that.
- The rollout's `recreate-runtime` (re)creates `node-exporter` with
  Prometheus and Alertmanager (`MONITORING_SERVICES`), and a contract test
  requires every monitoring service the overlay adds to be in that list.
- The alert rule is unchanged: it still fires when the series is stale **or
  absent**. promtool unit tests (`docker/prometheus/tests/`) prove it stays
  silent while a fresh backup is scraped, fires when stale or absent, and
  clears on recovery.

**Image selection (2026-10-04).** `prom/node-exporter:v1.12.1` (multi-arch
index `sha256:1b4e4438faca4dd7e001dd445d161a4a2091b0fededa84093b3a8dfeae1f1be0`;
the tested linux/amd64 binary embeds Go 1.26.5). Trivy CRITICAL scans of fixed
vulnerabilities found **zero** findings, with v0.70.0 (DB 2026-10-04 01:47 UTC),
v0.65.0 (DB 2026-10-03 19:02 UTC) and CI's non-gating scan. CVE-2025-68121
(present in v1.9.1 through v1.10.2) is absent. There is **no** risk acceptance
and **no** `.trivyignore`. The tag in `docker-compose.staging.yml` is the one
CI's visibility scan checks. Digest pinning and the upstream distroless variant
are separate supply-chain decisions, not made here.

**Consequence.** The fix reaches staging only through a normal migration-free
release rollout (its `recreate-runtime` starts the exporter). Until then the
alert keeps firing. Alternatives rejected: relaxing the rule (loses the
dead-man), exposing backup metrics from an application process (couples backup
evidence to the runtime it exists to recover), or a host-level node_exporter
(broader host access than a single read-only volume).

## Note (2026-09-29) — the signed-context key registry in database backups

Recorded so it is not re-litigated (Phase 2 plan §0.3). Facts, from the code:

- `ctx_keys` (migration `0016`, ADR-024) holds `key_id` (identifier),
  `key_class` (`api`/`worker`/`scheduler`), `secret bytea` (≥ 32 bytes: the
  **symmetric HMAC-SHA256 key**, byte-identical to the host key file, so it is
  signing-capable secret material, not a public verification key),
  `secret_sha256` (fingerprint), and lifecycle metadata (`status`,
  `activated_at`, `retired_at`, `revoked_at`, `created_at`). `ctx_key_events`
  holds lifecycle events and no material. Both are owned by the NOLOGIN
  `nlw_ctx_verifier` with no grant to any login role or PUBLIC.
- The runtime copies of the secrets are host files
  `/srv/nlw/ctx-keys/{api,worker,scheduler}.key` (0400, uid 10001), each
  mounted read-only into exactly its own service (`docker-compose.prod.yml`;
  `tests/unit/test_ctx_compose_isolation.py` asserts backup/restore services
  mount none), plus the operator's off-host escrow.
- `nlw.backup` runs `pg_dump --format=custom` with the owner credential and no
  `--exclude-table`, so **the dump includes `ctx_keys` rows with their
  secrets**. The dump is encrypted client-side by restic; role passwords are not
  in it (`pg_dumpall --roles-only --no-role-passwords`).
- This is intended: [dr-fresh-host-restore](../runbooks/dr-fresh-host-restore.md)
  item 3a restores the registry with the database and pairs it with the
  separately kept key files (or installs fresh keys when the files are lost),
  and the restore validator checks `ctx_keys_registry_protected`.

Assessment: not a defect. Anyone able to decrypt the restic repository already
holds every tenant's data; using the key material against a live database would
additionally need a runtime role password (not in the dump) and network access,
and `ctxkeys revoke` invalidates leaked material immediately.

Policy (owner decisions, 2026-09-29): the registry stays in the encrypted
database backups and is restored with the database; key files, escrow and the
restic passphrase stay outside the backup, and restoring still needs the
matching host/escrow key files (or carefully installed replacements). After a
restored environment is validated, the API, worker and scheduler signing keys
are rotated and escrow is updated: the exact sequence is
[dr-fresh-host-restore § Post-restore signing-key rotation](../runbooks/dr-fresh-host-restore.md#post-restore-signing-key-rotation-required).
The rejected alternative (`--exclude-table-data=public.ctx_keys`, reinstall
from escrow before any runtime starts) would remove signing material from
backups at the cost of making every restore depend on escrow.
