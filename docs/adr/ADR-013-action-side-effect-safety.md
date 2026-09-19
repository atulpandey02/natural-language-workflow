# ADR-013 — Action side-effect execution, approvals & idempotency

- Status: Accepted
- Date: 2026-09-19

## Context

M7 introduces the first real external ACTION tools (`webhook.send`,
`slack.send_message`). Side effects must preserve M0–M6 guarantees (durability,
tenant isolation, deterministic execution) while adding human approval and safe,
bounded, **at-least-once** delivery carrying a stable idempotency key
(effectively-once only where the receiver honors deduplication). M5's "run the
I/O inside the run lock" pattern was explicitly limited to read-only, bounded
queries and must NOT be reused for side effects.

## Decision

- **Tool taxonomy.** `ToolSpec` gains `side_effecting`; inline read/processing
  tools keep `execute` (in-lock, M3/M5), while ACTION tools set
  `side_effecting=True` + `execute_action` and `requires_approval=True`. The M6
  planner sees them automatically and returns `NEEDS_APPROVAL`.
- **Two-transaction, out-of-lock execution.**
  - **Txn1 (run `FOR UPDATE`):** claim the step → `RUNNING`, insert/lease a
    durable `external_actions` row with a **stable `external_action_key`**
    (generated once, reused on every retry/resume), COMMIT (lock released).
  - **External side effect:** performed with **no DB txn / no run lock**.
  - **Txn2 (run `FOR UPDATE`):** finalize `SUCCESS`/`FAILED`/retry idempotently,
    guarded by the lease token.
  A durably-committed `RUNNING` step now uniquely means "in-flight action"
  (inline tools never persist `RUNNING`), which makes crash recovery detectable.
- **Approvals.** An approval-gated action parks the run at **`WAITING_APPROVAL`**
  (run + step) and inserts one `PENDING` approval. Admin/owner decide via the API
  (RLS also enforces admin/owner + `decided_by = app.user_id`); the API mutates
  only the approvals row and enqueues a resume — **the worker is the sole run/step
  writer**. Decisions are compare-and-set: re-approving/re-rejecting is idempotent
  and re-enqueues (recovery-safe); the opposite decision on a decided approval is
  409. If the enqueue fails, the API returns 503 (the resume is not claimed).
- **Lease (concurrency).** Acquisition is atomic CAS under the run lock; a worker
  finalizes only if its `lease_token` still matches. A redelivery that sees a
  **live foreign lease** defers (delayed re-enqueue) and NEVER permanently acks,
  so a claim-then-die can always be recovered after lease expiry
  (`lease_duration > max network timeout + margin`).
- **Retry.** `external_actions` carries `attempts, last_attempt_at,
  next_attempt_at, error_class`. Retryable failures (5xx/429/network/timeout)
  clear the lease, set a bounded backoff `next_attempt_at` (honoring a bounded
  `Retry-After`), and schedule a delayed resume; an early redelivery before
  `next_attempt_at` does not execute. At the attempt cap (default 5, hard cap 10)
  the action → step → run FAIL. `attempts` counts durable **claims**, so a crash
  after claim but before send may consume an attempt (accepted for M7).
- **Audit.** Every attempt is recorded (tenant/run/step/connector/key/status/
  provider id/classification) with **no secret-bearing headers/bodies, no full
  provider response, and no payload hash**; `destination_summary` is host/channel
  only.

## Honest guarantee (no exactly-once)

We do **not** claim exactly-once side effects. Duplicates can occur when *(a)* an
external 2xx succeeds and the worker crashes before Txn2, or *(b)* an ambiguous
connect/read timeout or network failure occurs **after the request was
transmitted** (outcome unknown → retried with the same key). Idempotency-aware
webhook receivers dedupe via the stable `Idempotency-Key`; non-idempotent
receivers (arbitrary webhook; Slack `chat.postMessage`, which has no idempotency
key) may see duplicates. The lease prevents *concurrent* duplicates; it does not
remove these windows. This is at-least-once delivery, documented as such.

## Alternatives considered

- **Run the side effect inside the run lock (M5 style)** — rejected: holds the
  lock across a network call and blocks the run; unsafe for side effects.
- **APPROVED/REJECTED run/step states** — rejected: kept minimal; the decision
  lives on the approval record, run/step only add `WAITING_APPROVAL`.
- **Deriving the idempotency key from the attempt** — rejected: would change per
  retry and defeat receiver-side dedup; the key is generated once and reused.

## Consequences

- Actions are durable, tenant-isolated, approval-gated, and bounded, with honest
  at-least-once semantics and full audit. The seam extends to future providers
  and to hard per-tool timeouts without changing the model.
