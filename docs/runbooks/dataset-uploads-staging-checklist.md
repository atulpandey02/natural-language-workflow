# Checklist: before dataset uploads may reach staging (NOT RUN)

Status: **a plan, not a record.** Nothing in this checklist has been executed.
Phase 2B ([ADR-030](../adr/ADR-030-csv-ingestion-and-profiling.md)) is a
review-ready local implementation. Staging and production refuse
`DATASETS_API_ENABLED=true` and `DATASET_STORAGE_BACKEND=local` by
configuration, and that refusal must stay in place until every gate in sections
A and B is closed by an owner-approved change.

## A. Owner decisions that must be recorded first (blocking)

| # | Decision | Why it blocks staging |
|---|---|---|
| O-2 | **Decided (owner, 2026-10-09)**: AWS S3 in us-east-1, with one immutable `versions/` object per version, separate buckets, assumed roles and KMS keys per environment, and boto3 as the client ([ADR-033](../adr/ADR-033-s3-dataset-object-storage.md), D1–D6 approved). **Implemented without AWS contact** (`S3BlobStore`, pinned credentials, migration `0028`); no AWS resources exist; the real-AWS proof needs explicit authorization | There is no deployed object store; the local backend is refused outside development |
| O-3 | **Decided (owner, 2026-10-14)**: a dedicated S3 Object Lock bucket per environment in the dataset account, GOVERNANCE for the synthetic pilot, 365 days ([ADR-034](../adr/ADR-034-external-deletion-receipt-log.md)). **Implemented without AWS contact** (`S3DeletionLog`, `reconcile-receipts`, `reapply-receipts`, migration `0029`); no bucket exists; the real-AWS proof needs explicit authorization. Record retention set by O-5 (365 days) | `purge` refuses to run without a log that can retain its receipt; the local fake is refused outside development |
| O-4 | **Decided (owner, 2026-10-15)**: AWS Backup continuous backups (30-day point-in-time restore) in a vault in the same account and us-east-1; restore into a separate bucket and copy back with `restore-objects` ([ADR-036](../adr/ADR-036-dataset-object-backup.md)). **Implemented without AWS contact**; no vault or bucket exists; the restore drill against AWS needs explicit authorization | Without it a database restore brings back no bytes |
| O-5 | **Decided (owner, 2026-10-15)**: the synthetic-pilot retention policy in [ADR-035](../adr/ADR-035-phase2-retention-policy.md) (`nlw.core.retention`): rejected and deleted bytes purged within 7 days, inactive versions kept 30 days, noncurrent versions 30 days, multipart 1 day, receipts and audit events 365 days, backups 30 daily + 12 monthly. **Implemented without AWS contact** (`retention-sweep`, migration `0030`, dormant alerts). Real customer data stays blocked until receipt and audit storage and the object-backup vault lock (O-4) use COMPLIANCE and a separate GO decision | The sweep is not scheduled and its alerts are not loaded until O-6 |
| O-6 | A deliberate code change that allows `DATASETS_API_ENABLED` in staging (and how it is scoped). **Dormant configuration done (owner scope 2026-10-15, [ADR-038](../adr/ADR-038-o6-dormant-staging-configuration.md))**: `docker-compose.datasets.yml` (never rendered by the rollout), credential refresher and retention timer units, `prometheus.datasets.yml`, env template ([runbook](dataset-staging-dormant.md)); NOT RUN, nothing installed | The configuration still refuses the flag; the role gates, the ingest-key refusal and the rollout compose list are the enablement PR |
| O-1 | **Decided** ([ADR-031](../adr/ADR-031-dataset-ingest-runtime-boundary.md)): processing runs in the dedicated ingest runtime as `nlw_ingest`; the API records requests and enqueues | Enabling it is part of O-6: `nlw_ingest` LOGIN + password, the ingest key prepared and escrowed (four-key attestation, real recovery test), an ingest service in the deployed Compose, and a reviewed rollout path for all of it |
| O-7 | **Decided and implemented, dormant** ([ADR-032](../adr/ADR-032-dataset-ingest-dispatcher.md)): the `nlw_ingest_dispatch` role (one read-only function) and the `ingest-dispatch` process re-send lost enqueues, bounded and oldest first, with pending-age alerts | Enabling it is part of O-6: a LOGIN password for `nlw_ingest_dispatch`, the service in the deployed Compose, and `datasets.rules.yml` plus a scrape target in `prometheus.yml` with an alert route |

## B. Engineering that must exist first (blocking)

- [ ] An S3 `BlobStore` adapter behind the existing protocol, tested without
      network (a fake), with write-once semantics (conditional put), streamed
      digests and verified per-version deletion; scanned and pinned per
      repository policy.
- [x] A real `DeletionLog` implementation for the chosen provider, plus a
      restore runbook step that re-applies deletion receipts before any runtime
      starts (ADR-034; tested without AWS, NOT RUN against AWS).
- [x] An object restore path in the restore runbook (step 6c: AWS Backup
      restore, `restore-objects`, `verify-objects`) and DR evidence
      (`objects_step`) (ADR-036; tested without AWS, NOT RUN against AWS).
- [ ] An object restore drill against AWS (authorized proof).
- [ ] Settings changes for O-6, with tests that keep refusing the local backend
      and the fake log in staging and production.
- [ ] A container memory limit and a profiler `RLIMIT_AS` validated on the
      staging host image. The API container is 512 MB; measured peak is about
      16 MB traced for a 24 MB, 200-column file.
- [ ] Monitoring: an alert on pending requests older than a defined threshold.
      These are versions stuck in `QUARANTINED`-with-content, or in
      `PROFILING` beyond the stale lease: requests no consumer has settled.
      Proposed threshold: 15 minutes, plus any request older than
      `MAX_ENVELOPE_AGE_S` − 1 h. Also alert on refused envelopes, and on purge
      or verification failures.
- [ ] The ingest runtime deployable on staging (O-6): service, key, role
      password, readiness, and the rollout's ingest-key refusal lifted by a
      reviewed protocol change. *(Service, readiness and per-container
      credentials are configured dormant in `docker-compose.datasets.yml`,
      ADR-038; the key, the password and the protocol change remain.)*
- [ ] A second operator/reviewer named (owner decision, 2026-09-29).

## C. Release procedure (when A and B are done; do not run before)

1. CI green on the release commit, including the seeded E2E job with the
   dataset journey (it uses the local overlay only).
2. Release manifest: a migration release (`0024 → 0026` on staging today),
   signed policies **74**. The image head must be the checkout's Alembic head
   (`0026_dataset_ingest_role` or later).
3. Operator preflight (existing rollout CLI). Take a verified backup **before**
   the migration (`0025` downgrade is for disposable environments only; fix
   forward).
4. Migrate. Then verify:
   - `alembic_version` = the release's target revision;
   - forced RLS on `dataset_profiles`, `dataset_semantic_revisions` and
     `dataset_processing_requests`;
   - `nlw_worker` and `nlw_scheduler` have no grants on them; `nlw_ingest`
     holds exactly its ADR-031 grants;
   - the restore validator passes.
5. Deploy the API with the dataset store configured but
   `DATASETS_API_ENABLED=false`. Confirm the upload routes are absent (404)
   and the existing flows are unchanged.
6. Only with explicit owner authorization, enable the flag for the pilot
   workspace. Then run the synthetic journey: upload
   `web/e2e/fixtures/synthetic-orders.csv`, let the ingest runtime profile it,
   confirm, activate, request deletion, purge, tombstone, and run
   `verify-objects` (all zero) and `dispatch-pending --dry-run` (nothing
   pending).
7. Record evidence, ids and counts only, under `docs/evidence/`.

## D. Before external or customer uploads (in addition to A–C)

- The customer deletion statement is approved and published (owner decision,
  [offboarding-and-deletion](../security/offboarding-and-deletion.md)).
- Workspace offboarding purge exists and covers dataset objects.
- An independent security review of the upload path, the profiler process and
  the object store policy is complete.
- The real-provider, fresh-host DR drill (Phase 2 B03) includes object restore
  and deletion-receipt re-application.
