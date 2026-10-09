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
| O-2 | **Decided (owner, 2026-10-09)**: AWS S3 in us-east-1, with one immutable `versions/` object per version, separate buckets, assumed roles and KMS keys per environment, and boto3 as the client ([ADR-033](../adr/ADR-033-s3-dataset-object-storage.md), D1–D6 approved). Not yet implemented; no AWS resources exist; the real-AWS proof needs explicit authorization | There is no deployed object store; the local backend is refused outside development |
| O-3 | External deletion-log provider and record retention | `purge` refuses to run without a log; the local fake is refused outside development |
| O-4 | Object durability, replication and restore policy (RPO/RTO for uploaded files) | A database restore brings back no bytes (`verify-objects` would report every live version missing) |
| O-5 | Retention periods (request → purge → tombstone; tombstones, events, receipts) | The deletion statement cannot be published without them |
| O-6 | A deliberate code change that allows `DATASETS_API_ENABLED` in staging (and how it is scoped) | The configuration refuses it today |
| O-1 | **Decided** ([ADR-031](../adr/ADR-031-dataset-ingest-runtime-boundary.md)): processing runs in the dedicated ingest runtime as `nlw_ingest`; the API records requests and enqueues | Enabling it is part of O-6: `nlw_ingest` LOGIN + password, the ingest key prepared and escrowed (four-key attestation, real recovery test), an ingest service in the deployed Compose, and a reviewed rollout path for all of it |
| O-7 | **Decided and implemented, dormant** ([ADR-032](../adr/ADR-032-dataset-ingest-dispatcher.md)): the `nlw_ingest_dispatch` role (one read-only function) and the `ingest-dispatch` process re-send lost enqueues, bounded and oldest first, with pending-age alerts | Enabling it is part of O-6: a LOGIN password for `nlw_ingest_dispatch`, the service in the deployed Compose, and `datasets.rules.yml` plus a scrape target in `prometheus.yml` with an alert route |

## B. Engineering that must exist first (blocking)

- [ ] An S3 `BlobStore` adapter behind the existing protocol, tested without
      network (a fake), with write-once semantics (conditional put), streamed
      digests and verified per-version deletion; scanned and pinned per
      repository policy.
- [ ] A real `DeletionLog` implementation for the chosen provider, plus a
      restore runbook step that re-applies deletion receipts before any runtime
      starts.
- [ ] `verify-objects` wired into the restore validation (`nlw.backup.validate`)
      for the deployed store, and an object restore drill.
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
      reviewed protocol change.
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
