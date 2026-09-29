# ADR-028 — Redacted plan outcome events (Phase 2 B02)

- Status: Accepted (implementation on `feat/phase2-foundations`, migration
  `0023_plan_outcome_events`)
- Date: 2026-09-29

## Context

Every planner call already writes one immutable `plan_proposals` row with the
feasibility report and the bounded request text. That row is the evidence for a
single proposal, but it is not a measurement source: the text is deliberately
never listed or logged, provider failures write no row, and there is no
category taxonomy. Phase 2 changes the planner's task (semantic fields over
customer schemas), so the pilot's current failure profile must be measured
before anything changes ("measure before optimising", Phase 2 plan §11–§12).

## Decision

- A tenant-scoped, append-only table `plan_outcome_events`, one row per
  planning attempt: outcome (`PASS`, `APPROVAL`, `CLARIFY`, `REJECT`,
  `INVALID_OUTPUT`, `INFRA_FAIL`), one category from a fixed taxonomy, finding
  codes, clarification and step counts, a request-length bucket, request-shape
  tags, provider, model, contract version, latency and token counts.
- **No free text by schema.** Every column is a closed vocabulary, a number or
  a constrained identifier (CHECK constraints); feasibility messages, request
  text and user ids are never copied. Request shape is a set of boolean tags
  from fixed English patterns (`nlw.observability.plan_outcomes`).
- **Classification is code-owned.** Category is derived from finding codes with
  a fixed precedence (policy > invalid output > missing capability > platform
  limit > model misunderstanding > underspecified). A unit test requires every
  `FeasibilityCode` to be classified.
- **Same transaction as the proposal**, inside a SAVEPOINT, so the event
  commits with the proposal and a measurement failure never fails or alters the
  planning response. Provider failures (no proposal, request rolled back) are
  written in a short signed transaction of their own.
- **RLS on the signed context:** `nlw_app` inserts for its request's workspace;
  owners/admins read their own workspace; no runtime role may update or delete.
  The signed-policy inventory becomes 53 (51 + 2) in the rollout gate, the
  restore validator and the integration test.
- **Operator report:** `python -m nlw.ops.outcomes report --days 7` (owner
  credential) prints aggregates only; a request-shape tag is shown for a
  category only when it occurs in at least three workspaces.

## Deferred (explicitly not in this change)

- `user_hash` (HMAC of the user id with a platform key): needs a new platform
  key and its custody; no key material was introduced.
- Nightly derived fields (`followed_by_pass_within_10m`), 13-month event
  retention job, and nulling `plan_proposals.request_text` after 90 days: the
  retention periods are part of the customer statement awaiting owner approval
  (plan §22, "Retention promises").
- Tenant-facing `GET /workspaces/current/plan-outcomes` (Phase 2A API).
- Semantic fields (`field_refs_redacted`, `dataset_ref`) and repair-turn
  outcomes: they arrive with the semantic layer and planner-2. The
  `repair_attempted`/`repair_succeeded` columns exist and stay false/null.
- The analytics-to-Slack handoff creates `plan_proposals` rows without a
  planner call; it is not a planning attempt and writes no event.

## Consequences

The pilot's current first-pass rate and failure mix become observable per
model and contract version without reading anyone's request, which is the
baseline Phase 2A planning must beat. The table adds one small row per
planning call.
