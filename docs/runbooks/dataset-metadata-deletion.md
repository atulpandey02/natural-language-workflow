# Runbook: dataset metadata deletion and tombstones

Dataset metadata (migration `0024_dataset_lifecycle`,
[ADR-029](../adr/ADR-029-dataset-lifecycle-foundation.md)) is deleted in two
steps: a workspace admin/owner **requests** deletion (the dataset or version
becomes `DELETING` and unusable), and the operator later applies the
**tombstone** (`DELETING → DELETED`), which scrubs every name. The runtime role
can never write `DELETED`.

**Scope today.** No upload exists, so no customer file, object or profile
exists either: a tombstone only scrubs metadata rows. The metadata API is
refused in staging and production (`DATASETS_API_ENABLED`), so on those
environments there is nothing to tombstone. This runbook is for development
and for the future pilot; it does **not** satisfy the customer deletion launch
gate (physical object deletion + external deletion log, owner decision 13).

## Who may run this

Atul is the primary operator (owner decision, 2026-09-29); a second
operator/reviewer is required before external customer onboarding. Commands
need the **owner** database credential (`DATABASE_MIGRATION_URL`), like
`python -m nlw.ops.grants`. Never paste the credential into a ticket, chat or
log; the commands print only ids, states and counts.

## What a tombstone keeps and removes

| Kept | Scrubbed to `NULL` |
|---|---|
| dataset and version ids, tenant id, version numbers | dataset name, normalized name, description |
| declared size, media type, content digest | original filename |
| actors (`created_by`), every lifecycle timestamp | storage object key |
| the full append-only `dataset_events` trail | — |

The freed name can be reused by a **new** dataset (new id). A tombstoned row is
never revived: the database refuses any change to a `DELETED` row, for every
role including the owner.

## 1. List what is waiting

```bash
python -m nlw.ops.datasets pending
```

One tab-separated line per dataset: tenant id, dataset id, dataset status
(`DELETING`, or `ACTIVE` when only some versions were deleted), deletion
requested at, number of `DELETING` versions.

## 2. Apply the tombstone

Whole dataset (it must already be `DELETING`; all its versions are tombstoned
in the same transaction):

```bash
python -m nlw.ops.datasets tombstone --dataset <dataset-uuid>
```

One version (it must already be `DELETING`; the dataset may still be live):

```bash
python -m nlw.ops.datasets tombstone --dataset <dataset-uuid> --version <version-uuid>
```

Exit code `0` prints `dataset_id=… versions_tombstoned=… dataset=DELETED|…`.
Exit code `2` is a refusal and changes nothing:

| Message | Meaning | Action |
|---|---|---|
| `no such dataset` / `no such version` | wrong id, or a version of another dataset | re-check `pending` |
| `… not DELETING` | deletion was never requested (or the row is already `DELETED`) | ask the workspace admin to request deletion; never tombstone a live row |
| `… physical deletion …` | a version references a stored object | **stop**: object deletion does not exist yet; tombstoning would orphan bytes. Escalate. |

## 3. Verify

```bash
python -m nlw.ops.datasets pending
```

The dataset no longer appears. Its lifecycle events end with
`VERSION_TOMBSTONED` / `DATASET_TOMBSTONED` (`actor_kind = operator`,
`reason_code = OPERATOR_TOMBSTONE`).

## Never

- Never `DELETE` rows from `datasets`, `dataset_versions` or `dataset_events`
  by hand: the tombstone and the event trail are the deletion evidence.
- Never downgrade migration `0024` on an environment that holds dataset
  metadata (it drops the tables and the evidence). Fix forward.
- Never set `DATASETS_API_ENABLED=true` in staging or production; the
  configuration refuses it until upload and end-to-end deletion exist.

Retention periods (how soon after a request the tombstone is applied, how long
tombstones and events are kept) are not set yet; they are pilot proposals
awaiting owner approval (see
[offboarding-and-deletion](../security/offboarding-and-deletion.md)).
