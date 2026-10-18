# Dataset staging configuration — dormant (O-6, ADR-038)

Status: **a plan, not a record. NOT RUN.** Nothing here has been installed,
started or deployed. Every step below needs the separately authorized
enablement: provisioned AWS resources (D6 proof, O-3/O-4 templates), an owner
GO, and the enablement PR that lifts the refusals listed at the end. Until
then the reviewed rollout ignores all of it.

## What exists (reviewed, inert)

| Piece | File | Dormant because |
|---|---|---|
| Dataset overlay | `docker-compose.datasets.yml` | never in the rollout's compose list; runtimes behind profiles |
| API dataset settings | overlay `api` | `DATASETS_API_ENABLED: "false"` (and "true" is refused) |
| Ingest, dispatcher | overlay, profile `datasets` | roles NOLOGIN; rollout refuses an ingest key |
| Operator one-shot | overlay, profile `operator` | run by hand only (human role); mounts the worker secrets file read-only for offboarding |
| Retention one-shot | overlay, profile `retention` (uid 10005) | run by the timer only, as `nlw-<env>-dataset-retention` ([templates](dataset-retention-identity-provisioning.md)); the CLI allows only the sweep, its status and reconciliation |
| Object-restore one-shot | overlay, profile `object-restore` (uid 10006) | run by hand during a declared recovery only (human restore role, O-4) |
| Dataset metrics | `node-exporter-datasets`, `prometheus.datasets.yml` | not mounted by the rollout |
| Credential refresher | `scripts/ops/nlw_aws_credential_refresh.py`, `docker/systemd/nlw-aws-credentials.*` | not installed |
| Retention timer | `docker/systemd/nlw-dataset-retention.*` | not installed; fails closed without the retention role's credentials |
| IMDS gate | `recreate-runtime` (nlw.ops.rollout) | **active in every rollout**: a container that reaches instance metadata stops activation |
| Settings template | `deploy/staging/datasets.env.example` | placeholders only |

## Render check (safe, local, no host)

`tests/unit/test_o6_dormant_staging.py` renders prod + staging + the overlay
with dummy values for every required variable and checks the invariants
(isolation, profiles, the flag, the uids, the Prometheus config). By hand, with
the required variables exported:

```bash
docker compose -f docker-compose.prod.yml -f docker-compose.staging.yml \
  -f docker-compose.datasets.yml --profile datasets --profile operator config --quiet
```

## Enablement order (NOT RUN; each step needs authorization)

1. AWS: dataset bucket and key, roles (D6), receipt bucket and its trail
   selectors (O-3), object backup (O-4). Record ids in `/opt/nlw/.env.datasets`
   (root, 0600) from `deploy/staging/datasets.env.example`.
   Also the retention role and the two documents that name it
   ([dataset-retention-identity-provisioning](dataset-retention-identity-provisioning.md)).
2. Host: `/etc/nlw/datasets.env` (root, 0600) with `NLW_AWS_ENV` and
   `NLW_AWS_ACCOUNT`; install and start `nlw-aws-credentials.timer`; confirm
   `/run/nlw/aws/{api,ingest,retention}/credentials` are `0400`, owned by
   10001, 10002 and 10005, directories `0700`, and
   `/run/nlw/aws-metrics/nlw_aws_credentials.prom` reports each service.
3. IMDS: instance metadata IMDSv2 with hop limit 1, and the host firewall rule
   dropping `169.254.169.254` from Docker bridges. **Required before the next
   rollout of any release with this gate**: `recreate-runtime` probes from the
   deployed network and inside api, worker, scheduler and web, and stops
   otherwise. The enablement adds ingest and ingest-dispatch to the probe.
4. Ingest key (signed-context-keys.md §"ingest"): the reviewed protocol change,
   four-key escrow attestation, install owned by uid 10002, `check`.
5. Roles: `nlw_ingest` and `nlw_ingest_dispatch` passwords and LOGIN, with the
   rollout gate changed to expect it (enablement PR).
6. Deploy with the overlay and `DATASETS_API_ENABLED=false`: upload routes must
   be absent (404); ingest, dispatcher and the dataset exporter healthy;
   Prometheus on `prometheus.datasets.yml` with every dataset alert inactive
   except `NlwDatasetRetentionSweepStale` until the first sweep.
7. Retention: install `nlw-dataset-retention.timer` once the retention role
   exists and its credential file is refreshed; `NlwDatasetCredentialRefreshStale`
   and `NlwDatasetRetentionSweepStale` must stay inactive after the first day.
8. Only then, with owner authorization: the flag (checklist §C step 6).

## Refusals the enablement PR must lift (and test)

- `DATASETS_API_ENABLED` refused in staging/production (`nlw.core.config`).
- Rollout gates expecting `nlw_ingest:fff` and `nlw_ingest_dispatch:fff`.
- The rollout's refusal of an ingest key (`check_ingest_not_declared`).
- The rollout's compose list (adding `docker-compose.datasets.yml`, and its
  keys to `AMBIENT_UNSET`).
