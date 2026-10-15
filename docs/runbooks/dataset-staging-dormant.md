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
| Operator one-shot | overlay, profile `operator` | run by hand or by the timer only |
| Dataset metrics | `node-exporter-datasets`, `prometheus.datasets.yml` | not mounted by the rollout |
| Credential refresher | `scripts/ops/nlw_aws_credential_refresh.py`, `docker/systemd/nlw-aws-credentials.*` | not installed |
| Retention timer | `docker/systemd/nlw-dataset-retention.*` | not installed; fails closed without operator credentials |
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
2. Host: `/etc/nlw/datasets.env` (root, 0600) with `NLW_AWS_ENV` and
   `NLW_AWS_ACCOUNT`; install and start `nlw-aws-credentials.timer`; confirm
   `/run/nlw/aws/api/credentials` and `/run/nlw/aws/ingest/credentials` are
   `0400`, owned by 10001 and 10002, directories `0700`.
3. IMDS: instance metadata IMDSv2 with hop limit 1, and the host firewall rule
   dropping `169.254.169.254` from Docker bridges; prove a metadata request
   fails inside api, ingest, ingest-dispatch, worker, scheduler and web.
4. Ingest key (signed-context-keys.md §"ingest"): the reviewed protocol change,
   four-key escrow attestation, install owned by uid 10002, `check`.
5. Roles: `nlw_ingest` and `nlw_ingest_dispatch` passwords and LOGIN, with the
   rollout gate changed to expect it (enablement PR).
6. Deploy with the overlay and `DATASETS_API_ENABLED=false`: upload routes must
   be absent (404); ingest, dispatcher and the dataset exporter healthy;
   Prometheus on `prometheus.datasets.yml` with every dataset alert inactive
   except `NlwDatasetRetentionSweepStale` until the first sweep.
7. Retention: install `nlw-dataset-retention.timer` once an operator credential
   file (or an approved automation identity, ADR-038 open decision) exists.
8. Only then, with owner authorization: the flag (checklist §C step 6).

## Refusals the enablement PR must lift (and test)

- `DATASETS_API_ENABLED` refused in staging/production (`nlw.core.config`).
- Rollout gates expecting `nlw_ingest:fff` and `nlw_ingest_dispatch:fff`.
- The rollout's refusal of an ingest key (`check_ingest_not_declared`).
- The rollout's compose list (adding `docker-compose.datasets.yml`, and its
  keys to `AMBIENT_UNSET`).
