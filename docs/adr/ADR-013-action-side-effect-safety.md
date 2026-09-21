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

## Honest guarantee (no exactly-once; what the lease does and does NOT do)

We do **not** claim exactly-once side effects, and we are precise about the
lease's guarantee (corrected in P1C — earlier wording overclaimed):

- A live lease **serializes ordinary database claims**: two workers cannot both
  hold the claim and both finalize; finalization is a compare-and-set on the
  `lease_token`, so only the current owner writes the outcome.
- Keeping the HTTP total deadline **shorter than the lease** (`total + margin <
  lease`) reduces overlap during *normal* execution.
- A database lease **cannot fence an external receiver.** A process pause, VM
  suspension, severe scheduler stall, or any execution beyond lease expiry can let
  another worker reclaim the action **while the first attempt is still capable of
  producing an external effect**. Both attempts then transmit — the DB lease does
  not (and cannot) prevent this.
- The stable `Idempotency-Key` prevents duplicate **effects** only when the
  **receiver enforces it.** For an arbitrary webhook we cannot assume it does; for
  Slack `chat.postMessage` there is no idempotency key at all.

So duplicates are **not** limited to a success-before-finalize crash: they can
also arise from lease overrun without any crash. This is at-least-once delivery
against a receiver that may or may not dedupe — documented as such, with no
guarantee we cannot implement without receiver-side idempotency or true fencing.

An **ambiguous** outcome — a failure once the request may already have been
transmitted (write/read/reset/total-deadline; a 5xx; a truncated/garbled response)
— is handled differently since P1C: it is **not** retried. See the P1C amendment
and the classification matrix below.

## P1C amendment (M11.5 hardening, 2026-09-21)

The eight action-delivery defects closed here refine the model without expanding
run/step states (the only new persisted state is the `external_actions.status`
value `unknown`).

- **Lease is authoritative before the attempt cap.** On resume the order is:
  status-not-pending → **live foreign lease defers** → `next_attempt_at` defers →
  attempt-cap → acquire. A duplicate/redelivery can no longer fail a legitimate
  **live final attempt** or clear/replace another worker's lease, and never
  increments `attempts` while a live lease is observed. Only the current
  lease-token owner finalizes.
- **Ambiguous outcome → terminal UNKNOWN (`ACTION_OUTCOME_UNKNOWN`).** A failure
  once the request may have been transmitted (httpx write/read/reset, a **generic
  5xx**, a truncated or unparseable response, or the total deadline elapsing at/after
  the response head), and an **expired final attempt** whose prior send cannot be
  disproven, resolve to a terminal `unknown` external-action status. The step and
  run FAIL with the distinguishing `ACTION_OUTCOME_UNKNOWN` error class (the UI
  reports "may have occurred", not a definite failure). UNKNOWN is **persistent,
  terminal, and excluded from retry, reconciliation, and redelivery** — the side
  effect is never auto-resent. Classification is **conservative**: we auto-retry
  ONLY when the effect provably did not occur (DNS/connect/TLS/pool failure before
  the request left) **or** a connector-specific contract makes retry safe (HTTP
  429; Slack `ok:false`). Everything else once transmission may have started is
  UNKNOWN. There is **no retry/resend button** for UNKNOWN in this package
  (operators follow the runbook below). See the full matrix below.
- **True total wall-clock deadline.** Delivery is bounded by a single monotonic
  deadline (`TOTAL_ACTION_DEADLINE_S = 30s`) covering resolution/connect/TLS/write
  /response, not a per-operation inactivity timer. The invariant
  `TOTAL + FINALIZE_MARGIN_S (10s) < LEASE_DURATION_S (45s)` guarantees a
  completed-or-timed-out send always leaves room to re-lock and finalize before
  the lease could be reclaimed. A trickling response is stopped at the deadline
  (it can no longer outlive the lease), and the whole operation runs
  synchronously — no background thread continues after the caller returns. See
  ADR-014 for the transport details.
- **Stable key preserved.** The `external_action_key` / outbound `Idempotency-Key`
  is still generated once per (run, step) and reused on every attempt; UNKNOWN
  introduces no new key and no exactly-once claim.
- **Approval preview correctness.** The approval API shows the connector
  type/name, the **effective non-secret destination** (webhook host only — no
  path/query/credentials; Slack channel id), and the **complete bounded** payload
  from the immutable plan. A payload exceeding the reviewable size
  (`MAX_REVIEWABLE_ACTION_PAYLOAD_BYTES = 16_000`) is **rejected** at
  materialization, and defence-in-depth at approve time returns 422 rather than
  approving unseen/truncated content. Approval binds the immutable plan step **and
  the connector identity**: a post-approval connector swap (same name, new id)
  fails the step deterministically ("re-approval required") instead of silently
  redirecting the side effect. Secrets, `secret_ref`, auth headers, tokens, and
  credential-bearing query parameters are never exposed.
- **Reconciler compatibility.** An `unknown` action is never re-enqueued or
  reclaimed (the finalizer sets the run FAILED atomically with the action, and the
  reconciler additionally guards its RUNNING-stall branch against any run bearing
  an `unknown` action). Redelivery of any still-pending action remains idempotent.

## P1C addendum — connector classification matrix, lease boundary & downgrade (2026-09-21)

**Correction of the earlier P1C wording:** a generic webhook **5xx used to be
retried**. It is not any more — a receiver may perform the action and then fail
while responding, so without an enforced idempotency contract a 5xx is UNKNOWN.

Outcome legend: `SUCCESS` (step SUCCESS / run continues), `FAILED` (deterministic,
step+run FAILED), `RETRY` (external_action stays `pending` with a backoff
`next_attempt_at`; step RUNNING), `UNKNOWN` (`ACTION_OUTCOME_UNKNOWN`; step+run
FAILED, never auto-resent). No case triggers a *second automatic* transmission on
immediate redelivery (RETRY defers until `next_attempt_at`).

**Generic webhook** (`webhook.send`):

| Condition                                   | Outcome  | error_class              | Why |
|---------------------------------------------|----------|--------------------------|-----|
| DNS / destination-policy rejection (SSRF)   | FAILED   | `deterministic`          | Blocked before any bytes; won't change on retry |
| DNS resolution failure (transient)          | RETRY    | `retryable`              | No transmission occurred |
| Pool acquisition / connect / TLS failure    | RETRY    | `retryable`              | Provably before transmission |
| Write failure (bytes may have left)         | UNKNOWN  | `ACTION_OUTCOME_UNKNOWN` | Transmission may have started |
| Timeout waiting for response headers        | UNKNOWN  | `ACTION_OUTCOME_UNKNOWN` | Request sent; server may have acted |
| Total deadline reached at/after head        | UNKNOWN  | `ACTION_OUTCOME_UNKNOWN` | Request sent; outcome unprovable |
| 2xx                                         | SUCCESS  | —                        | Status is authoritative (body not read) |
| 3xx                                         | FAILED   | `deterministic`          | Redirects disabled (SSRF); misconfiguration |
| 401 / 403                                   | FAILED   | `auth`                   | Rejected, no effect |
| 429                                         | RETRY    | `retryable`              | RFC 6585: rate-limited, **not processed**; `Retry-After` honored, bounded. Residual: a non-conforming receiver could act then return 429 (accepted; treating all 429 as UNKNOWN would make ordinary rate limiting unrecoverable) |
| Other 4xx                                   | FAILED   | `deterministic`          | Rejected, no effect |
| **5xx**                                     | **UNKNOWN** | `ACTION_OUTCOME_UNKNOWN` | A generic 5xx does NOT prove no effect; may have acted then failed responding |
| Body stream error / trickle past deadline   | n/a for webhook | —                  | Webhook does not read the body (ADR-014); a 2xx head already decided SUCCESS |

**Slack** (`slack.send_message`) — Slack's documented contract makes the JSON
`ok`/`error` and 429 deterministic; an HTTP 5xx is not:

| Condition                                   | Outcome  | error_class              | Why |
|---------------------------------------------|----------|--------------------------|-----|
| Pool / connect / TLS failure                | RETRY    | `retryable`              | Before transmission |
| Write/read failure after send               | UNKNOWN  | `ACTION_OUTCOME_UNKNOWN` | Transmission may have started |
| HTTP 429 (+ `Retry-After`)                  | RETRY    | `retryable`              | Slack rate-limit contract: throttled, not delivered |
| **HTTP 5xx**                                | **UNKNOWN** | `ACTION_OUTCOME_UNKNOWN` | Not part of Slack's `ok`/`error` contract; may have posted |
| Truncated / oversized response              | UNKNOWN  | `ACTION_OUTCOME_UNKNOWN` | POSTed, but `ok` can't be read |
| Malformed / non-JSON / non-object body      | UNKNOWN  | `ACTION_OUTCOME_UNKNOWN` | POSTed, but `ok` can't be read |
| Other non-200 HTTP status                   | FAILED   | `deterministic`          | Rejected at HTTP layer |
| `200 ok:true`                               | SUCCESS  | —                        | Delivered per contract |
| `200 ok:false` invalid_auth/token_revoked/… | FAILED   | `auth`                   | Slack: not delivered |
| `200 ok:false` ratelimited/service_unavailable/internal_error | RETRY | `retryable` | Slack: not delivered, transient |
| `200 ok:false` (other, e.g. channel_not_found) | FAILED | `deterministic`         | Slack: not delivered, permanent |

Only stable, sanitized `error_class` codes are ever persisted; no response body,
URL path/query, credential, or raw exception text reaches any durable surface
(verified by the classification-matrix leak assertions).

**Lease-overrun boundary (honest limitation).** A regression test
(`test_lease_overrun_two_transmissions_possible_without_state_corruption`) models
worker A held past lease expiry while B reclaims the same action: **both A and B
transmit with the SAME idempotency key** (no new key is manufactured), yet
finalization stays CAS-safe (A's stale-lease finalize is a noop; exactly one
success is recorded; the run completes cleanly). Two external observations remain
possible when the receiver ignores the key — the DB lease cannot fence the
receiver. This is documented, not "fixed", because it cannot be without
receiver-side idempotency or true fencing.

**Config invariant enforced at startup.** `total action deadline + finalize
margin < lease duration` is asserted at import of the action HTTP module
(`assert_action_deadline_fits_lease`); a violating configuration refuses to start.

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
