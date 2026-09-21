# Resolve an action with an UNKNOWN (ambiguous) outcome

**Goal:** safely reconcile an external side effect whose outcome the platform
could not prove, without blindly resending it.

## What UNKNOWN means

An external action (`webhook.send`, `slack.send_message`) whose request **may
have been transmitted** but whose result **cannot be proven** is finalized as a
**terminal UNKNOWN**, not a definite failure. It appears as:

- `external_actions.status = 'unknown'`, `error_class = 'ACTION_OUTCOME_UNKNOWN'`,
  lease cleared, `next_attempt_at` NULL;
- the owning `step_runs.status = 'FAILED'` with `error = 'ACTION_OUTCOME_UNKNOWN'`;
- the `workflow_runs.status = 'FAILED'`.

Causes: a connection reset or timeout **after** the request bytes may have been
written, a response lost/truncated/garbled after a successful POST, or a final
attempt that expired without proof its prior send did not land.

**The platform will NOT auto-resend an UNKNOWN action.** It is deliberately
excluded from retry, reconciliation, and redelivery. There is intentionally **no
"retry" button** — resending could duplicate a side effect that already happened.
Resolution is a human decision, informed by the destination system.

## Diagnose (read-only)

1. Get the `run_id` from logs/metrics (`error_class=ACTION_OUTCOME_UNKNOWN`), then
   read `workflow_runs`, `step_runs`, `external_actions`, `approvals` for it
   (see [inspect-failed-run.md](inspect-failed-run.md)). These rows never contain
   secrets or response bodies.
2. From `external_actions` note the `tool`, `destination_summary` (host/channel
   only), `external_action_key` (the stable `Idempotency-Key` that was sent),
   `attempts`, `last_attempt_at`, and `provider_request_id` if any.
3. **Check the destination system of record** to determine whether the side
   effect actually landed:
   - Webhook: look for the request carrying `Idempotency-Key = external_action_key`
     in the receiver's logs (an idempotency-aware receiver will have deduped).
   - Slack: check the target channel around `last_attempt_at` for the message
     (`chat.postMessage` has no idempotency key).

## Resolve

- **If the side effect DID land:** no resend is needed. Record the finding; the
  run stays FAILED/UNKNOWN as an accurate audit of an ambiguous-but-delivered
  action. If downstream steps must proceed, start a new run from the point after
  this action rather than resending it.
- **If the side effect did NOT land:** re-drive the intent deliberately — start a
  **new run** of the workflow (fresh approval, fresh `external_action_key`). Do
  **not** mutate the `unknown` row back to `pending`; that is not a supported
  recovery and would bypass approval and the stable-key contract.
- **If you cannot tell:** prefer NOT resending to a non-idempotent destination
  (arbitrary webhook, Slack). Duplicate delivery is usually worse than a missed
  one; escalate to the workflow owner for a business decision.

## Do not

- Do not add or wire a resend/retry control for UNKNOWN in this package.
- Do not edit `external_actions.status`, `step_runs`, or `workflow_runs` to
  "unstick" the run without first confirming the destination state.
- Prefer **fix-forward** over a schema downgrade on a live pilot. Downgrading below
  `0012` rewrites `unknown` rows to `failed`, losing the "may have occurred"
  distinction. It does NOT reactivate automatic delivery (the run/step are already
  terminal FAILED and the reconciler never re-enqueues FAILED runs), but it erases
  the signal you need to reconcile the receiver, so review any `unknown` rows first
  (see the migration warning).
