# Inspect a failed/stuck run safely

**Goal:** understand a run without exposing secrets or mutating state casually.

**Do:**
1. From logs/metrics get the `run_id`. Query `workflow_runs`, `step_runs`,
   `external_actions`, `approvals` for that run (read-only). Step I/O and action
   rows never contain secrets (secrets live only on the connector side).
2. Check `external_actions.status/attempts/error_class/next_attempt_at` and
   lease fields to see where an action is in the two-phase lifecycle.
3. For approval-gated steps, check `approvals.status`.
4. Only after understanding the cause, take a deliberate, audited action (retry
   by re-enqueue, disable a connector, or an operator terminal-fail). Never edit
   run state to "unstick" without knowing why it stuck.
