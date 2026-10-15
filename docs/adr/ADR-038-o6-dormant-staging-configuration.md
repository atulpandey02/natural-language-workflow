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

## Open owner decisions

- **Unattended identity for the retention timer.** The operator role trusts
  humans only (MFA), so the timer fails closed unless an operator has supplied
  a fresh credential file. A dedicated, narrower automation role (sweep and
  reconcile only) would need new pinned templates.
- **Separate uids** 10002-10004 have no `/etc/passwd` entry in the image; the
  runtimes need none, but the ingest key file must be owned by 10002 (the
  key-install step changes per class).
- **Refresh-failure alert**: a failed refresher unit is visible in the journal
  and `NlwDatasetS3CredentialsExpiring` fires 15 min before a file expires; a
  dedicated refresher metric is not built.
- **IMDS firewall rule** (second layer) and the in-container metadata probe are
  host steps in the runbook, not automated.
