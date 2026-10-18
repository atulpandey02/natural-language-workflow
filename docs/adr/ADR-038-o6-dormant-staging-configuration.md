# ADR-038: O-6 dormant staging configuration

Status: **accepted; configuration only, NOT RUN, nothing installed or deployed;
uploads stay refused in staging and production.** Owner decision (scope):
2026-10-15, "dormant, flag stays refused". Builds on ADR-031 (ingest runtime),
ADR-032 (dispatcher), ADR-033 (S3 store, §5 per-container credentials), ADR-034
(receipts) and ADR-035 (retention, alerts).

> **Principle.** Everything staging needs to run the dataset path is reviewed
> and tested now; nothing of it can run until a separate, authorized enablement
> flips the switches this ADR leaves off.

## Decision

1. **A separate overlay, `docker-compose.datasets.yml`**, never rendered by the
   rollout (its compose list stays `docker-compose.prod.yml` +
   `docker-compose.staging.yml`; a test pins that nothing under `src/`,
   `scripts/` or `.github/` names the overlay except the dormant systemd unit):
   - `api`: the S3 store settings, `DATASETS_API_ENABLED: "false"`, its own
     credential directory (`/run/nlw/aws/api`, read-only), IMDS disabled. With
     the flag off the API builds no store and mounts no dataset route;
   - `ingest` (uid 10002) and `ingest-dispatch` (uid 10003), profile
     `datasets` only, hardened exactly like the reviewed runtimes; the ingest
     runtime mounts only its own key and credential directory, the dispatcher
     no AWS mount and no key;
   - `operator` (uid 10004), profile `operator`, one-shot: the owner database
     credential, the S3 deletion log, the operator's per-session credential
     file, and the dataset textfile volume;
   - `node-exporter-datasets` (profile `datasets`): a textfile-only exporter of
     its own volume (the backup exporter's volume keeps one writer);
   - Prometheus mounts `prometheus.datasets.yml`: the reviewed config plus the
     dataset rules file and three targets, otherwise identical (pinned).
2. **Credential refresher** (`scripts/ops/nlw_aws_credential_refresh.py`,
   standard library only) with `nlw-aws-credentials.service`/`.timer` (15
   min): assumes only the api and ingest roles (1 h, fixed session names),
   writes `0400` files in `0700` directories atomically, logs no value.
3. **Retention timer** (`nlw-dataset-retention.service`/`.timer`, daily):
   `retention-sweep` and `reconcile-receipts` with their textfile metrics, in
   the operator one-shot.
4. **Env template** `deploy/staging/datasets.env.example` (placeholders only).
5. **Still refused, deliberately** (the enablement PR): `DATASETS_API_ENABLED`
   in staging; LOGIN for `nlw_ingest`/`nlw_ingest_dispatch` (gates expect
   `fff`); the rollout's ingest-key refusal; installing any unit.

## Integration after #68-#70 (2026-10-18)

The four open points of the first version are decided and built; the assembled
configuration now includes O-4 and the offboarding operations.

| Point | Decision and implementation |
|---|---|
| Unattended retention identity | **Owner decision: a new narrow role** `nlw-<env>-dataset-retention` ([templates](../runbooks/dataset-retention-identity-provisioning.md), pinned). Host-trusted (bootstrap role, fixed session name), refreshed every 15 min; it may list `versions/`, delete object versions and abort uploads, and write/read/list receipts; it reads no dataset content, uses no key, never touches the restore bucket, the trail, another environment or any configuration. Two reviewed documents name it: a complete alternative of the D6 dataset bucket policy (delete exception) and of the D6 bootstrap role (may assume it), each the D6 document byte for byte except that one list (pinned; the D6 proof account keeps the originals); the O-3 receipt bucket policy's write exception names it directly. `DATASET_OPERATOR_IDENTITY=retention` limits the CLI to `retention-sweep`, `retention-status` and `reconcile-receipts` (refused before any database connection otherwise); offboarding refuses it. The timer runs the new `retention` one-shot (uid 10005), never the operator. |
| Ingest key ownership | Enforced: `nlw.ctxkeys` prepares and checks `ingest.key` for uid 10002 only, whatever `--owner` says for the other classes. |
| IMDS blocking | **A rollout gate**: `recreate-runtime` probes from a throwaway release-image container on the deployed network **before** `current` is switched, and inside api, worker, scheduler (Python) and web (Node) **after** recreation; any answer, error or missing probe stops the rollout before traffic reopens. The host steps (IMDSv2 hop limit 1, firewall rule) remain the means; the gate proves them. |
| Refresher monitoring | The refresher writes `nlw_aws_credentials.prom` (last success, expiry, last run per service) to `/run/nlw/aws-metrics`, served by the dataset exporter (a second textfile directory, verified with the pinned image); `NlwDatasetCredentialRefreshStale` fires after two missed runs or for a service that never reported (promtool-tested). |
| O-4 and offboarding | `object-restore` one-shot (uid 10006, profile `object-restore`, the human restore role's per-session file, `DATASET_RESTORE_BUCKET`); the operator one-shot mounts the worker's secrets file read-only (never created by Compose) for `offboarding complete --secrets-file`. |
| Found while integrating | The refresher asked for session names `nlw-<env>-<svc>-refresher`, which `trust-api`/`trust-ingest` refuse; it now uses the exact names, pinned against every trust template. |

## Open owner decisions

- **Separate uids** 10002-10006 have no `/etc/passwd` entry in the image; the
  runtimes need none.
- The retention role trusts the host: anyone with root on the staging host can
  purge due data and write receipts as it (as they could already read the
  runtimes' credentials); its grants are limited to exactly that.
