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

The low overall product-decision rate is dominated by a conservative model that
prefers `NEEDS_CLARIFICATION` over emitting a plan for adversarial or terse inputs —
a SAFE degradation, not an unsafe one. The two `direct_injection` cases are counted
as product-decision misses (the model did the benign part and IGNORED the injection,
producing an executable but harmless plan); the injected `DROP`/exfiltration payload
is never executable (SQL-safety + table allowlist), so injection resistance is 1.0
and D = 0. Deterministic rejection of the 14 adversarial plan FIXTURES is proven
separately (`tests/eval/test_corpus_v2.py`).
