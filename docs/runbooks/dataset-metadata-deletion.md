# Runbook: dataset deletion (purge, then tombstone)

Datasets ([ADR-029](../adr/ADR-029-dataset-lifecycle-foundation.md),
[ADR-030](../adr/ADR-030-csv-ingestion-and-profiling.md)) are deleted in three
steps:

1. A workspace admin/owner **requests** deletion. The dataset or version
   becomes `DELETING` and is unusable at once.
2. The operator **purges** the stored objects: physical deletion, verified,
   with a receipt.
3. The operator applies the **tombstone** (`DELETING → DELETED`), which scrubs
   every name, the storage key, the profile and the semantic mappings.

The runtime role can never write `DELETED` or the purge evidence.

**Scope today.**
- Uploads exist only in development (`DATASETS_API_ENABLED` and
  `DATASET_STORAGE_BACKEND=local` are refused in staging and production), so
  only development has objects to purge.
- The only deletion log is a **local fake**. The external, restore-proof
  deletion log is a launch gate (owner decision O-3).
- This runbook does **not** make external uploads deletable to customer
  standard yet.

## Who may run this

Atul is the primary operator (owner decision, 2026-09-29). A second
operator/reviewer is required before external customer onboarding.

The commands need:
- the **owner** database credential (`DATABASE_MIGRATION_URL`), like
  `python -m nlw.ops.grants`;
- the same dataset store settings as the API (`DATASET_STORAGE_BACKEND`,
  `DATASET_STORAGE_ROOT`, `APP_ENV`);
- for `purge`, a deletion log (`DATASET_DELETION_LOG`,
  `DATASET_DELETION_LOG_PATH`).

Never paste a credential into a ticket, chat or log. The commands print ids,
states and counts only.

## What is kept and what is removed

| Kept | Removed or scrubbed |
|---|---|
| dataset and version ids, tenant id, version numbers | the stored objects (purge: both areas, including partial uploads) |
| declared size, media type, content digest | dataset name, normalized name, description |
| profile row counts and digest (row kept, `profile` → `NULL`) | original filename, storage key |
| semantic revision numbers, confirming user and time (`mapping` → `NULL`) | profile content, semantic labels |
| actors, every lifecycle timestamp, the full append-only `dataset_events` trail | — |
| deletion receipts (outside the database) | — |

## 1. List what is waiting

```bash
python -m nlw.ops.datasets pending
```

This prints one tab-separated line per dataset: tenant id, dataset id, dataset
status (`DELETING`, or `ACTIVE` when only some versions were deleted), deletion
requested at, and the number of `DELETING` versions.

## 2. Purge the stored objects

For a whole dataset (it must be `DELETING`):

```bash
python -m nlw.ops.datasets purge --dataset <dataset-uuid> --operator <your-label>
```

For one version (it must be `DELETING`):

```bash
python -m nlw.ops.datasets purge --dataset <dataset-uuid> --version <version-uuid> --operator <your-label>
```

For each `DELETING` version, the purge:
1. deletes every stored file (published, quarantine, crash-orphaned partials);
2. **verifies absence**;
3. appends one `deletion-receipt-2` record to the deletion log;
4. records `VERSION_OBJECT_PURGED` (`actor_kind = operator`).

A whole-dataset purge also clears and verifies the dataset's prefixes. It is
idempotent: a repeat deletes nothing new and records fresh evidence.

Exit code `0` prints `dataset_id=… versions_purged=… objects_deleted=…`. Exit
code `2` is a refusal:

| Message | Meaning | Action |
|---|---|---|
| `no deletion log is configured` | refused **before** anything is deleted | configure the deletion log; never purge without one |
| `… not DELETING` | deletion was never requested | ask the workspace admin to request deletion |
| `no dataset store is configured` | the operator shell lacks the store settings | use the API's store settings |
| `… could not be verified absent` | bytes remain after deletion | **stop**; check storage permissions; escalate |

## 3. Apply the tombstone

```bash
python -m nlw.ops.datasets tombstone --dataset <dataset-uuid>
python -m nlw.ops.datasets tombstone --dataset <dataset-uuid> --version <version-uuid>
```

The tombstone is **refused** for any version that references a storage key
unless both of these hold:
- a purge was recorded after its deletion request;
- a live check of the store finds nothing for it.

A whole-dataset tombstone also requires the dataset's prefixes to be empty.
Exit code `2` messages:

| Message | Meaning | Action |
|---|---|---|
| `… was not purged: run purge first` | no purge evidence | run step 2 |
| `… still present: run purge` | bytes reappeared after the purge (e.g. an object restore) | run step 2 again, then retry |
| `deletion receipt … was not verified: <REASON>` | the purge's receipt is `MISSING`, `STALE`, `MALFORMED`, `UNVERIFIABLE`, or bound to another workspace, dataset, version or digest | **stop**: never tombstone without a verified receipt; investigate the deletion log, then purge again (a fresh receipt) |
| `… held by sink …; the configured verifier is …` | the operator shell's deletion log differs from the one that recorded the purge | use the same deletion-log settings as the purge |
| `no dataset store is configured` | absence cannot be verified | use the API's store settings |
| `… not DELETING` / `no such …` | wrong id or state | re-check `pending` |

## 4. Verify

```bash
python -m nlw.ops.datasets pending          # the dataset is gone from the list
python -m nlw.ops.datasets verify-objects   # every count is 0
```

The version's events end with `VERSION_DELETION_REQUESTED`,
`VERSION_OBJECT_PURGED`, `VERSION_TOMBSTONED` (and `DATASET_TOMBSTONED`).

## Never

- Never `DELETE` rows from the dataset tables by hand. The tombstone, the
  receipts and the event trail are the deletion evidence.
- Never delete objects by hand instead of `purge`: the tombstone would refuse
  (there would be no receipt and no evidence).
- Never downgrade migrations `0024`/`0025` on an environment that holds
  dataset data. Fix forward.
- Never set `DATASETS_API_ENABLED=true` or `DATASET_STORAGE_BACKEND=local` in
  staging or production (both are refused), and never point dataset storage at
  the backup repository (refused).

Retention periods (how soon after a request the purge and tombstone run, and
how long tombstones, events and receipts are kept) are not set. They are pilot
proposals awaiting owner approval (owner decision O-5; see
[offboarding-and-deletion](../security/offboarding-and-deletion.md)).
