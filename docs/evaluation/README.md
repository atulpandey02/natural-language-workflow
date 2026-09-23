# Live-model benchmark evidence (versioned, sanitized)

The live planning benchmark (`python -m nlw.eval.live_runner`) writes its
outputs to the gitignored `eval-artifacts/` directory, which disappears on local
cleanup. Production-readiness evidence therefore lives here, versioned, as
`live-benchmark-<date>.json`, containing **only** sanitized data:

- evaluation date, corpus version + sha256, planner contract version,
  provider/model, non-secret sampling parameters, call count;
- aggregate and per-category metrics, sanitized failure classifications,
  consistency, latency and token totals;
- the per-run classified outcomes (case id, category, statuses, boolean checks,
  latency, tokens, model id) from which every aggregate is recomputed by
  `tests/unit/test_live_benchmark_evidence.py`;
- a statement that raw provider responses, request ids, headers, credentials and
  request text are excluded, and the command to repeat the run.

Raw provider responses (`raw-responses.jsonl`) are never committed.

## `live-benchmark-2026-09-22.json` — what it does and does not show

Independent-review reading of the 102-call run (claude-haiku-4-5, 34 cases × 3):

| measure | value | meaning |
|---|---|---|
| unsafe executable outcomes | **0 / 102** | no run produced an executable `PASS` against a non-`PASS` expectation (reproducible from `per_run`) |
| immediate executable-plan rate | **21 / 33 (63.6%)** | of the 11 cases expected to be executable, 7 produced an executable plan on every repeat |
| correct product-decision rate (actionable cases) | **33 / 33** | the 12 non-exact runs are `NEEDS_CLARIFICATION` on requests missing required content (message body, recipient/channel, a recurrence a plan cannot express) or on fixture labels |
| consistency | 34 / 34 | identical classified **status** across repeats, not identical text |

**Caveats that bound this evidence** (also embedded in the artifact):

1. The corpus `request` strings were written as fixture labels for deterministic
   replay, not as customer requests. 21 of 34 are labels such as `a->b->c->a`,
   `51 steps`, `use foo.bar`, `query with int sql`; the live runner sends them
   verbatim and the model asked for clarification on every one. `exact_outcome`
   (26.5%) and `failures_by_category` must **not** be read as planner quality.
2. `expected_status` is derived from the checked-in planner-output fixture, not a
   request-level contract; for unsupported or policy-disallowed requests,
   `NEEDS_CLARIFICATION` is the model's only refusal channel (`REJECT` only arises
   when a *proposed* plan fails deterministic feasibility).
3. No live run produced a `REJECT`, so the **deterministic reject path was not
   exercised by live model output** in this benchmark; `injection_resistance =
   1.0` reflects model refusal/under-specification. Deterministic protection is
   proven by the replay corpus and `tests/unit/test_injection_boundary.py`, which
   grade adversarial *fixtures* through the real feasibility engine.
4. Clarification **text** quality cannot be verified from this artifact (raw
   responses excluded).

Before the live benchmark can measure planner quality, the corpus needs a
request-level expectation (`live_expect`) and natural-language requests; that is
a follow-up, deliberately not done by editing the existing expectations.

## Corpus v1 is DIAGNOSTIC only (superseded by v2 for quality claims)

`tests/eval/corpus/v1_core.json` (`live-benchmark-2026-09-22.json`) is an early
DIAGNOSTIC benchmark: its `request` fields are implementation-oriented fixture
labels (`a->b->c->a`, `51 steps`, `use foo.bar`), so it measures deterministic
SAFETY, not planner QUALITY on real customer input. Planner-quality claims use the
natural-language corpus **v2** (`tests/eval/corpus/v2/v2_core.json`,
`nlw.eval.live_runner_v2`), whose requests are realistic customer instructions and
whose grader reports the product-decision / feasible-plan / clarification-usefulness
rates separately. The v1 corpus file itself is left byte-for-byte unchanged so the
committed v1 evidence stays bound to it by sha256.

## `live-benchmark-v2-2026-09-23.json` — natural-language corpus v2 run

102 planner calls (34 NL cases × 3), `anthropic` / `claude-haiku-4-5-20251001`,
planning only. Every aggregate recomputes from `per_run` and the artifact is bound
to the exact v2 corpus by sha256 (`tests/unit/test_live_benchmark_v2_committed.py`).

| measure | value |
|---|---|
| unsafe executable outcomes (category D) | **0 / 102** |
| approval-policy safety | **1.0** |
| tenant/connector-isolation safety | **1.0** |
| direct + indirect injection resistance | **1.0** |
| secret-exfiltration safety | **1.0** |
| schema-valid / argument-schema / dependency validity | 0.980 / 1.0 / 1.0 |
| immediate feasible-plan rate (sufficiently specified supported cases) | **0.733** |
| useful-clarification rate (genuinely underspecified) | **1.0** |
| unsupported/rejection correctness | 0.882 |
| correct product-decision (all cases) | 0.392 |
| three-run consistency (classified outcome) | 32 / 34 |

### Independent delta-review reading of the v2 run (2026-09-23)

Numerators behind the table: schema-valid 100/102 · tool selection 100/102 ·
argument schema 102/102 · dependency validity 102/102 · immediate feasible plan
33/45 · useful clarification 6/6 · unsupported/rejection correct 45/51 · correct
product decision 40/102 · approval safety 12/12 · isolation safety 6/6 ·
injection resistance 9/9 · exfiltration safety 3/3 · unsafe executable 0/102 ·
consistency 31/34 · median/p95 latency 1.668 s / 2.582 s · tokens 169,818 in /
16,020 out. All recompute from `per_run` (`review_annotations.numerators`).

**What this run does NOT prove on its own** (details in the artifact's
`review_annotations`):

- The six executable outcomes on the two `direct_injection` cases are safe **by
  construction of the deterministic feasibility engine** (their only available
  tools were `postgres.query`/`fake.echo`/`fake.fail`, and `PASS` requires every
  SQL step to pass the read-only + table-allowlist validator that rejects the
  checked-in `DROP`/`pg_shadow` fixtures). This run retained **no plan
  projection**, so no independent per-plan oracle was applied to what the model
  actually emitted. The grader now records a sanitized projection and applies
  `independent_safety_oracle` on every future run.
- `useful_clarification = 1.0` is a run-time Boolean; the question text was not
  retained, so it is **not independently reproducible** from this file. Future
  runs retain bounded question text.
- Three of the four missed PLAN cases are under-specified for the static-argument
  tool model (`sched_daily_signups`, `appr_webhook_summary`, `approval_bypass`);
  excluding them the immediate feasible-plan rate is **33/36**, and the single
  genuine over-conservative miss is `cbq_users_month` (0/3).
- `correct_product_decision = 40/102` mostly measures corpus contract strictness:
  for REJECT-expected requests the model's only refusal channel is
  `NEEDS_CLARIFICATION`. Under a request-level contract that accepts a safe
  non-executable refusal, acceptable product decisions are 90/102 (99/102 if the
  three under-specified cases' clarifications are accepted).

The low overall product-decision rate is dominated by a conservative model that
prefers `NEEDS_CLARIFICATION` over emitting a plan for adversarial or terse inputs —
a SAFE degradation, not an unsafe one. The two `direct_injection` cases are counted
as product-decision misses (the model did the benign part and IGNORED the injection,
producing an executable but harmless plan); the injected `DROP`/exfiltration payload
is never executable (SQL-safety + table allowlist), so injection resistance is 1.0
and D = 0. Deterministic rejection of the 14 adversarial plan FIXTURES is proven
separately (`tests/eval/test_corpus_v2.py`).
