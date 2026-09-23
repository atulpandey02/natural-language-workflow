# AI observability coverage matrix (M12B-A addendum, Part 6)

Every requested AI-behavior signal mapped to an existing metric/event, a metric
added in M12B-A, or an intentional gap with justification. All metric labels are
bounded vocabularies (method/route/status, tool, outcome/result/reason class,
purpose) — never tenant/run/step ids, request text, prompts, or tool output
(`observability/metrics.py` docstring; enforced by `test_ai_metrics.py`).

| requested signal | status | metric / event |
|---|---|---|
| planner request / success / failure | existing | `nlw_plans_total{status}` (PASS/REJECT/NEEDS_CLARIFICATION/NEEDS_APPROVAL) + `nlw_errors_total{error_class}` for provider faults (`planner_unavailable`/`planner_auth`/`planner_prompt_budget`) |
| invalid structured output | existing (M12B-A) | `nlw_planner_invalid_output_total` |
| bounded repair attempts | **intentional gap** | the planner is single-shot: it has NO re-prompt/repair loop (ADR-026). Invalid output is a deterministic reject, not a retry. There is nothing to count; adding a always-zero metric would mislead. |
| feasibility outcome | existing (M12B-A) | `nlw_plans_total{status}` + `nlw_feasibility_reject_total{code}` (stable `FeasibilityCode`) |
| plan size / bytes | existing (M12B-A) | `nlw_plan_steps`, `nlw_plan_bytes` (histograms) |
| token usage and latency | existing (M12B-A) | `nlw_planner_tokens{direction}`, `nlw_planner_latency_seconds` |
| queue-to-start latency | **added (addendum)** | `nlw_run_queue_to_start_seconds` — observed once at the run's first PENDING→RUNNING transition |
| step duration | existing | `nlw_tool_latency_seconds{tool,outcome}` (inline tool exec) + action attempt latency folded into the same histogram from `process_advance`; per-step wall-clock is derivable from `step_runs.started_at/finished_at` (kept in the DB, not a metric, to avoid a high-cardinality/duplicate signal) |
| retries | existing | `nlw_action_attempts_total{tool,outcome}` (one per durable attempt) |
| recovery / resume | existing | `nlw_scheduler_reconcile_reenqueued_total`, `nlw_scheduler_reconcile_candidates_total` |
| duplicate-delivery suppression | existing | `nlw_advance_total{result="deferred"}` — a live-lease/backoff deferral is exactly a suppressed duplicate delivery |
| approval wait duration | **added (addendum)** | `nlw_approval_wait_seconds` — observed once when a decision is recorded (decided_at − requested_at) |
| UNKNOWN actions | existing | `nlw_action_attempts_total{outcome}` records the terminal action outcome; the ambiguous case surfaces as the `unknown`/failed outcome label |
| summary success / fallback | existing (M12B-A) | `nlw_run_summary_total{outcome}` — the grounded summary is always the deterministic fallback (no LLM), and its outcome (`COMPLETED`/`FAILED`/`FAILED_WITH_UNKNOWN`/…) is the signal |
| evaluation pass rate | **intentional gap (build-time, not runtime)** | the deterministic corpus pass rate is a CI gate and an artifact of `python -m nlw.eval.runner`, not a live production signal; exposing it as a runtime metric would be meaningless (it does not vary at runtime). The live-model benchmark emits its own rates in `eval-artifacts/`. |
| stale-plan blocks (M12B-A) | **added (addendum)** | `nlw_stale_plan_total{outcome,reason}` — STALE_PLAN/POLICY_DENIED/INVALID_PLAN by stable reason |

## Cardinality & privacy

No new label introduces high cardinality: `stale_plan` uses a 3-value outcome ×
a fixed `FeasibilityCode` reason; the two new histograms carry no labels. No
request text, prompt, tool output, email, tenant/run/step id, or connector secret
is ever a label or a metric value — request provenance lives only in the
RLS-scoped `plan_proposals.request_text` column and is never logged or metered
(`test_plan_provenance.py::test_secret_like_request_text_does_not_leak_to_list_or_metrics`).
