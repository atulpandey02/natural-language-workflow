# ADR-034: The external deletion-receipt log on S3 Object Lock (owner decision O-3)

Status: **accepted; implemented without AWS contact (branch
`feat/o3-s3-deletion-log`); NOT RUN against AWS, no AWS resources.** The owner
decided O-3 on 2026-10-14. Retention stays a placeholder until O-5. Uploads stay
refused in staging and production (O-6).
Date: 2026-10-14.
Builds on [ADR-030](ADR-030-csv-ingestion-and-profiling.md) (the `deletion-receipt-2`
contract and the verified tombstone) and [ADR-033](ADR-033-s3-dataset-object-storage.md)
(the S3 store, the verified operator identity and note 3 on partial purges).
Templates: [deletion-receipt-log-provisioning](../runbooks/deletion-receipt-log-provisioning.md)
(NOT RUN).

> **Principle.** Evidence that bytes were deleted must outlive both the bytes
> and the database that tracked them. It is written once, protected by the
> storage itself, and re-applied before a restored database serves anyone.

## Context

ADR-030 defined a provider-neutral receipt per purged version and made the
tombstone verify it, but only a local fake existed, so `purge` was a launch
gate. `docs/security/offboarding-and-deletion.md` records the constraint
(owner decision 2026-09-29): the log must live outside PostgreSQL and its
backups, in a separately controlled, versioned or Object-Locked S3 location,
and a restore must re-apply it before any runtime starts. ADR-033 since added
the S3 client, pinned credentials and a verified operator identity, so no new
dependency is needed.

## Decision (owner, 2026-10-14)

1. **Location: a dedicated bucket in the same account.**
   `nlw-<env>-deletion-receipts-<account>-us-east-1`, one per environment,
   separate from the dataset bucket, the CloudTrail audit bucket and the Restic
   repository (settings refuse any sharing). A separate account was considered
   (stronger isolation) and deferred: it needs cross-account roles and a second
   account to operate. A prefix in the dataset bucket was rejected: receipts
   would share the controls of the objects whose deletion they prove.
2. **Retention: GOVERNANCE, 365 days.** Object Lock is enabled at creation
   with a default retention of 365 days (set by O-5 on 2026-10-15,
   [ADR-035](ADR-035-phase2-retention-policy.md)). GOVERNANCE is for the
   synthetic pilot only; real customer data stays blocked until receipt and
   audit storage use COMPLIANCE and a separate GO decision is recorded.
3. **Scope of this change:** the provider, a reconcile command, the restore
   re-application, the provisioning templates and the runbook steps. The
   real-AWS proof is a later, separately authorized step.

## Design

**One write-once object per receipt:**
`receipts/<workspace>/<dataset>/<version>/<receipt_id>.json`, the canonical
`deletion-receipt-2` JSON (unchanged contract).

- `append`: `PutObject` with `If-None-Match: *`, `ChecksumSHA256` and SSE-S3;
  then `HeadObject` of the returned version must show the same checksum and
  size and an Object Lock mode with a future retain-until date. Otherwise the
  purge fails (the transaction rolls back; the bytes are already gone, as
  ADR-033 note 3 records for any failure after deletion).
- `preflight`, called **before anything is deleted** by `purge` and
  `purge-rejected`: the bucket must report Object Lock enabled with a default
  retention mode and period. A log that cannot protect its receipt never
  allows a deletion.
- `verify`: `GetObject` by the ids the database expects (never by receipt id
  alone), bounded to 64 KiB and to a JSON nesting depth of 4 (checked before
  parsing, so a deeply nested document is `MALFORMED`, never a parser crash),
  checksum intact, retention live (`NOT_RETAINED` otherwise, a new
  `ReceiptCheck`), then the existing provider-neutral `check_receipt`.
- `refs` / `read`: `ListObjectsV2` of `receipts/`, complete or refused: a page
  whose prefix echo differs, an `EncodingType`, a key outside `receipts/`, a
  truncated page without a token, a repeated token or more than 1000 pages
  refuses the whole listing before any caller acts on it. Objects under
  `receipts/` that are not receipts are counted (`unexpected_objects`), never
  read.
- Writers: the bucket policy denies `PutObject` to every principal except the
  environment's `nlw-<env>-dataset-operator` role
  (`DenyReceiptWritesExceptOperator`), whatever another principal's identity
  policy allows.
- Sink id `s3.<bucket>`: the purge event records it, so the tombstone verifies
  against the same bucket that holds the receipt.
- Identity: the verified operator role `nlw-<env>-dataset-operator` and the
  pinned credential file of ADR-033 D3; the receipt bucket must be in the dataset
  bucket's account and environment. The grants are a **second inline policy**
  (`role-operator-receipts`); the reviewed `role-operator` template and the D6
  pins are unchanged. Runtime roles have no access (bucket policy deny).
- Encryption: SSE-S3. Receipts hold ids, digests, counts, an operator label and
  a time, never names, keys, paths or values; SSE-S3 keeps the evidence
  readable without depending on a KMS key policy.

**Reconcile** (`python -m nlw.ops.datasets reconcile-receipts`): every
`VERSION_OBJECT_PURGED` event is verified against its receipt; receipts that
no event names are listed (the documented trace of a purge that failed after
writing its receipt). Exit 1 on any unverified event, foreign sink, or
unexpected object in the log (`unexpected_objects`: never read, but an
operator must look at it). A malformed receipt is reported as unverified and
never stops the check of the others.

**Restore re-application** (`reapply-receipts [--dry-run]`): refused unless the
recovery lock holds a restored database. For each self-consistent receipt
(well formed, filed where it says, this sink, digest recomputes):

| Restored database shows the version as | Action |
|---|---|
| absent (created after the snapshot) | none, counted |
| `DELETED` | none, counted |
| `DELETING` with this receipt's evidence | none, counted |
| `DELETING` without it | record the purge evidence (`RESTORE_REAPPLY`) |
| any live state | move to `DELETING` (clearing the dataset's active version), then record the evidence; both events `RESTORE_REAPPLY` |
| any state with a different content digest | **conflict**: listed, never changed |

An untrustworthy receipt (checksum, retention, shape, nesting) is listed as
`unreadable`, changes nothing, and the run continues. The log is listed in
full before anything changes. The command is idempotent; exit 1 on any
conflict, unreadable receipt or unexpected object.

**Operator errors.** Both commands (and every other `nlw.ops.datasets`
command) print only author-controlled messages: an operational failure
(database, network, storage) prints its class and exits 3, with partial
progress of `reapply-receipts` as counts only; a configuration error prints
the validator's reason without the rejected value. No traceback, bucket name,
account id, key, credential or receipt content is printed; a sink is named by
its kind (`s3`, `local-fake`), never its id.

**Migration `0029_deletion_receipt_reapply`:** reason code `RESTORE_REAPPLY`;
`ck_dataset_events_purge_shape` admits it beside `OPERATOR_PURGE`. No grant,
trigger or policy change (74 policies). Downgrade refused once used.

**Tombstone:** a receipt must postdate the deletion request it answers,
except `RESTORE_REAPPLY` evidence: that deletion happened in the timeline the
restored database forgot, so it necessarily predates the request the restore
re-created. Identity, digests and live absence are still checked; an ordinary
purge with an older receipt is still `STALE`.

## Consequences

- O-3's provider is decided and implemented; `purge` can run in a deployed
  environment once the bucket exists and the operator holds the grants. It is
  **NOT RUN** against AWS; the verification steps are in the runbook §7.
- The DR runbook gains a step between validation and `enable-runtime`.
- Corrected wording: receipts hold **hashed** object references (S3 version,
  delete-marker and upload ids hashed with the key) and a count, not version
  ids in clear (ADR-033 and the provisioning runbook said "version ids").
- **Remaining open:** O-5 sets the retention; workspace offboarding and its
  receipts are ADR-037 (in the same log and prefix). CloudTrail data events for
  this bucket: a pinned selector set for the existing trail
  (`trail-advanced-event-selectors-all-buckets`, runbook §8, which also covers the dataset and O-4 restore buckets; NOT RUN), kept
  365 days with the rest of the audit log.

## Security review of PR #66 (2026-10-14) and fixes

| Finding | Fix |
|---|---|
| M-1: any same-account principal but the runtime roles could create receipts | `DenyReceiptWritesExceptOperator`, pinned exactly; the in-memory S3 enforces it |
| M-2: a deeply nested receipt raised `RecursionError` from `verify`/`read`, aborting reconcile, reapply and the tombstone | depth bound before parsing, `RecursionError` contained; reported as `MALFORMED`/unreadable; the runs continue |
| L-1: the listing's fail-closed paths were untested | direct tests for each, plus "nothing changes, nothing is read" integration tests; a repeated token is refused at once |
| L-2: `unexpected_objects` was never reported | printed by both commands, which then exit 1 |
| L-3: an unexpected failure printed a traceback | sanitized CLI errors (class only, exit 3), partial progress as counts; sink kinds instead of sink ids |

## Operator role path (2026-10-15)

Every `nlw-<env>-dataset-*` role is at IAM path `/`. The receipt bucket policy
admits exactly `arn:aws:iam::<account>:role/nlw-<env>-dataset-operator`, and
STS session ARNs omit the path, so a role at another path would pass the
identity check and be refused only when writing a receipt, after its bytes
were deleted. `preflight` therefore calls `iam:GetRole` on the operator's own
role (granted on exactly that path-`/` ARN, `ConfirmOwnRolePath`): a role at
another path is AccessDenied, a role at `/` must report `Path: "/"`, and the
purge stops before deleting anything otherwise. The provisioner also records
`aws iam get-role ... --query Role.Path` = `/`.

## Residual risks

- GOVERNANCE lets the audit administrator remove a receipt early with a
  separately granted bypass, until COMPLIANCE.
- A trusted operator (the only principal allowed to create receipts) can write
  a well-formed receipt for a live version, which `reapply-receipts` would
  honour during a restore. The operator can already request any deletion;
  receipts carry the operator label and, once the trail covers the bucket,
  `PutObject` data events.
- A stray object under `receipts/` cannot be removed during retention, so the
  commands keep exiting 1 until an operator records it as reviewed.
- A receipt can exist without a purge event (ADR-033 note 3);
  `reconcile-receipts` lists it.
- `reapply-receipts` does not move a dataset whose versions it re-applied to
  `DELETING`: receipts are per version and do not say whether a whole dataset
  was deleted. The dataset stays usable for its remaining versions.
