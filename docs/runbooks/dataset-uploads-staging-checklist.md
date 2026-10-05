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
| O-2 | S3-compatible client dependency + ADR; a **dedicated** per-environment bucket or prefix (never the backup repository); encryption, versioning and object lock; access policy for the API role | There is no deployed object store; the local backend is refused outside development |
| O-3 | External deletion-log provider and record retention | `purge` refuses to run without a log; the local fake is refused outside development |
| O-4 | Object durability, replication and restore policy (RPO/RTO for uploaded files) | A database restore brings back no bytes (`verify-objects` would report every live version missing) |
| O-5 | Retention periods (request → purge → tombstone; tombstones, events, receipts) | The deletion statement cannot be published without them |
| O-6 | A deliberate code change that allows `DATASETS_API_ENABLED` in staging (and how it is scoped) | The configuration refuses it today |
| O-1 | Whether processing stays under the uploading admin's authority or moves to a dedicated `nlw_ingest` role, signed purpose and key class | Only needed if processing moves to an unattended worker; it would need a verifier change, a key class, escrow and a deployment secret |

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
- [ ] Monitoring: an alert for versions stuck in `QUARANTINED`-with-content or
      `PROFILING` beyond the stale lease, and for purge or verification
      failures.
- [ ] A second operator/reviewer named (owner decision, 2026-09-29).

## C. Release procedure (when A and B are done; do not run before)

1. CI green on the release commit, including the seeded E2E job with the
   dataset journey (it uses the local overlay only).
2. Release manifest: a migration release (`0024 → 0025` on staging), signed
   policies **65**. The image head must be `0025_dataset_ingestion`.
3. Operator preflight (existing rollout CLI). Take a verified backup **before**
   the migration (`0025` downgrade is for disposable environments only; fix
   forward).
4. Migrate. Then verify:
   - `alembic_version` = `0025`;
   - forced RLS on `dataset_profiles` and `dataset_semantic_revisions`;
   - `nlw_worker` and `nlw_scheduler` have no grants on them;
   - the restore validator passes.
5. Deploy the API with the dataset store configured but
   `DATASETS_API_ENABLED=false`. Confirm the upload routes are absent (404)
   and the existing flows are unchanged.
6. Only with explicit owner authorization, enable the flag for the pilot
   workspace. Then run the synthetic journey: upload
   `web/e2e/fixtures/synthetic-orders.csv`, profile, confirm, activate, request
   deletion, purge, tombstone, and run `verify-objects` (all zero).
7. Record evidence, ids and counts only, under `docs/evidence/`.

## D. Before external or customer uploads (in addition to A–C)

- The customer deletion statement is approved and published (owner decision,
  [offboarding-and-deletion](../security/offboarding-and-deletion.md)).
- Workspace offboarding purge exists and covers dataset objects.
- An independent security review of the upload path, the profiler process and
  the object store policy is complete.
- The real-provider, fresh-host DR drill (Phase 2 B03) includes object restore
  and deletion-receipt re-application.
