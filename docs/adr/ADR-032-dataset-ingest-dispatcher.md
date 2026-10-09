# ADR-032: Unattended dataset dispatcher (owner decision O-7)

Status: accepted for implementation; **not deployed, dormant in staging and
production**. Branch `feat/o7-ingest-dispatcher`.
Date: 2026-10-08.
Builds on [ADR-031](ADR-031-dataset-ingest-runtime-boundary.md) (the ingest
boundary and its O-7 decision record) and [ADR-030](ADR-030-csv-ingestion-and-profiling.md).

## Context

The upload API commits a processing request with the content, then enqueues
its envelope after commit. If that enqueue fails (503 `PROCESSING_NOT_QUEUED`),
or Redis later loses the message, the committed request waits. Until now, three
actions recovered it: a client retry of the `PUT`, an admin's
`POST …/process`, or the operator's `dispatch-pending`. Without one of these,
the request stayed pending indefinitely.

The owner decided O-7 as recommended in ADR-031: build a bounded, dedicated
dispatcher identity on the ingest side, and do **not** widen the worker or
scheduler. Alert on requests pending longer than about 15 minutes.

## Decision

### Identity: `nlw_ingest_dispatch`

- A runtime login role, provisioned outside Alembic like `nlw_ingest`:
  - `initdb` makes it LOGIN only when `NLW_INGEST_DISPATCH_DB_PASSWORD` is set
    (development, CI, E2E);
  - `nlw.ops.roles ensure` and the rollout's `prepare-roles` create it NOLOGIN;
  - every deployed-target gate expects it NOLOGIN (`fff`) until O-6.
- Never superuser, BYPASSRLS, CREATEDB, CREATEROLE or INHERIT, and never a
  member of anything.
- **Exact privileges** (migration `0027_dataset_ingest_dispatch`), checked by
  the rollout gate, restore validation and tests:
  - CONNECT and USAGE;
  - EXECUTE on `dataset_dispatch_pending(integer, integer, integer)`;
  - SELECT on the DR recovery-lock columns of `dr_restore_events`, like every
    runtime.
- It has **no privilege on any dataset table**, no signed-context purpose, no
  key, no storage, and no LLM, connector, backup, alerting or operator secret.
  It never writes to the database.

### The one function

`dataset_dispatch_pending(limit, min_age_s, fresh_age_s)`:

- **Ownership:** read-only, `SECURITY DEFINER`, `search_path = pg_catalog`. It
  is owned by the existing NOLOGIN read-only BYPASSRLS function owner
  `nlw_rls_bypass` (the migration 0004 pattern). That owner gets column-level
  SELECT on exactly the columns the function reads.
- **Returns** the latest request of each waiting version, meaning
  `QUARANTINED` with matching content, or `PROFILING` with an expired or
  missing lease. Each row carries only:
  - request, tenant, dataset and version ids;
  - the content and envelope digests;
  - the request time.
- **Batch:** one bounded batch (`limit` clamped to 1..1000), oldest first,
  holding only requests older than `min_age_s` and still fresh for the
  consumer.
- **Stats:** every row also carries aggregates over all waiting versions (count,
  oldest age, count too old to re-send), for monitoring. With nothing waiting,
  one stats-only row is returned.
- **No new RLS policy:** the signed policy inventory stays 74.

### The dispatcher process

`python -m nlw.ingest_dispatch.dispatcher`, the dev Compose service
`ingest-dispatch` (profile `ingest`).

- **Boot:** refused (exit 3) unless the process is connected as
  `nlw_ingest_dispatch` and the recovery lock permits runtimes.
- **Each cycle** (`DATASET_DISPATCH_INTERVAL_S`, default 60 s):
  1. Check the recovery lock. If it is locked, nothing happens (`locked`).
  2. Take the same session advisory lock as the operator CLI, so only one
     sweep runs at a time. If it is held, nothing happens (`busy`).
  3. Read one batch (`DATASET_DISPATCH_BATCH`, default 100) of requests older
     than `DATASET_DISPATCH_MIN_AGE_S` (default 120 s, so an initial enqueue in
     flight is not raced).
  4. Re-send each request at most once per `DATASET_DISPATCH_RESEND_S`
     (default 600 s). This uses bounded in-memory state, pruned to the current
     batch; a restart re-sends at most one extra copy.
- **Failures:** a broker or database failure ends the cycle (`error`) without
  changing database state, and the next cycle retries.
- **What it can never do:**
  - Process anything. The ingest runtime re-verifies every envelope, and its
    lease settles each version once, so a duplicate is harmless.
  - Renew a request too old for the consumer, because a request records the
    admin who asked for it. Those are counted, and an admin re-dispatch
    records a fresh one.

### Monitoring

- **Metrics:** aggregate gauges and counters only, with no per-workspace label:
  - `nlw_dataset_dispatch_pending`;
  - `nlw_dataset_dispatch_oldest_pending_age_seconds`;
  - `nlw_dataset_dispatch_stale`;
  - `nlw_dataset_dispatch_enqueued_total`;
  - `nlw_dataset_dispatch_cycles_total{result}` (ok, locked, busy or error);
  - `nlw_dataset_dispatch_last_success_timestamp_seconds`.
- **Alerts** (`docker/prometheus/alerts/datasets.rules.yml`, with promtool unit
  tests):

  | Alert | Fires when |
  |---|---|
  | `NlwDatasetProcessingPendingTooLong` | The oldest pending request is older than 900 s, for 5 m |
  | `NlwDatasetProcessingRequestsExpired` | A pending request is too old to re-send, for 15 m |
  | `NlwDatasetDispatcherStalled` | No successful cycle for 10 m, for 5 m |

- **Dormant until O-6:** the rules file is not referenced by `prometheus.yml`,
  and no scrape target exists. Deployed monitoring is unchanged.

### Delivery semantics (unchanged in kind)

At-least-once, and never exactly-once. With the dispatcher running, a lost
enqueue is re-sent within about `min_age + interval` (default about 3 minutes)
without any human action. While the dispatcher is down, the alerts fire and the
three manual paths remain available.

### Runbook

| Symptom | Action |
|---|---|
| `PendingTooLong` | Check the ingest runtime (up, healthy, not refusing), Redis, and the recovery lock (`locked` cycles). Duplicates are harmless. |
| `RequestsExpired` | An admin runs `POST /datasets/{id}/versions/{vid}/process` for each waiting version, which records a fresh request. Find the versions with `python -m nlw.ops.datasets dispatch-pending --dry-run`, which counts them as `stale`. |
| `DispatcherStalled` | Read the dispatcher logs (`dispatch.cycle_failed error_class=…`). Meanwhile, the operator sweep `dispatch-pending` recovers lost work. |

## Alternatives considered

- **Give the scheduler or worker dataset read access.** Rejected: this would
  widen two general-purpose identities to every workspace's dataset metadata.
- **Column grants and an RLS `USING (true)` policy for the dispatcher.**
  Rejected: it adds two policies (a signed-inventory change) and a broader
  read surface than one fixed function.
- **Run the dispatcher inside the ingest container.** Rejected: one container
  would hold both the ingest key and credential and the cross-workspace read
  path. Separate identities keep both small.
- **Persist "last dispatched" in the database.** Rejected: it would need a
  writable table for the dispatcher. Duplicates are already harmless, and the
  in-memory bound is enough.

## Consequences

- O-7 is implemented and dormant. Enabling it is part of O-6, which needs:
  - a LOGIN password for `nlw_ingest_dispatch`;
  - an `ingest-dispatch` service in the deployed Compose;
  - the rules file and a scrape target in `prometheus.yml`;
  - an alert route.
- Release manifests and rollouts now expect the `0027` head and the dormant
  role. `prepare-roles` creates it, and the rollout gate and restore validation
  check its exact privileges.
- Uploads remain disabled in staging and production.
