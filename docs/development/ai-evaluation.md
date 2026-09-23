# AI evaluation harness (M12B-A, Part B)

A versioned, synthetic, non-secret corpus that grades planner outputs against the
**real** tool registry and the **real** deterministic feasibility engine. It
proves the safety-critical acceptance criteria: no invalid or adversarial plan
reaches execution, approval policy cannot be weakened by model output, and
tenant/connector substitution and injection are blocked deterministically.

## Two modes

**Deterministic replay** (default; what CI runs). Checked-in planner-output
fixtures are graded through `check_plan` with zero LLM and zero network. Grading
stops at the feasibility verdict, so **no case executes anything** or causes a
side effect.

```bash
uv run pytest tests/eval/test_eval_corpus_replay.py
uv run python -m nlw.eval.runner --json eval-results.json --md eval-summary.md
```

**Live-model** (optional, credential-gated). Runs the actual planner per case,
feeding the case's `request` string to the planner verbatim. Note (independent
review): most corpus `request` strings are fixture *labels*, not customer
requests, and `expect.feasibility_status` is fixture-derived — so live
`exact_outcome` is not a planner-quality figure. See
[docs/evaluation/README.md](../evaluation/README.md) for the versioned evidence
and its caveats. It
captures the model / provider / token usage, and grades the structured result
for safety (never exact-match — a live model may propose a different valid plan,
but must never turn an adversarial/unsupported case into an executable PASS). It
**plans only, never executes**, so no external side effect can occur. Off in
ordinary CI. A single run does not establish model quality.

```bash
NLW_EVAL_LIVE=1 NLW_LLM_PROVIDER=anthropic NLW_LLM_API_KEY=... \
  uv run pytest tests/eval/test_eval_live_model.py
```

## Corpus

`tests/eval/corpus/*.json`, each with a `corpus_version`. A case declares:

- `request` (informational), `actor_role`, `connectors` (synthetic, non-secret);
- `planner_output` — the fixture the model returned / would return;
- `expect` — the deterministic verdict: `feasibility_status`, `reject_codes`
  (subset that must appear), `approvals_required`, `allowed_tools` (the exact
  capability view offered, when asserted), `approval_required`,
  `execution_may_start`.

`v1_core.json` has 34 cases across all 20 categories: valid single/multi-step,
connector-required, schedule, approval-required, unsupported, ambiguous,
nonexistent tool, wrong arg types, missing args, cross-step reference errors,
cycles, excessive plan size/bytes, approval bypass, direct + indirect injection,
credential/hidden-context probes, malicious action content, tenant/connector
substitution, and destructive/policy-disallowed requests.

## Adding a case

Add an object to the `cases` array of a corpus file (or add a new versioned
file). Run the replay test; the grader will report any mismatch between the
fixture's real feasibility verdict and `expect`. Keep everything synthetic and
secret-free. Never point a rollout or the app at corpus data — it is test input,
not a workflow.

## What it does and does not prove

- **Does**: the deterministic authorization contract (schema, tool availability,
  args, connectors, SQL safety, DAG, approval, limits, byte bounds) holds for
  every fixture, including adversarial ones; the capability view is connector-
  gated; nothing invalid/adversarial can start execution.
- **Does not**: measure model quality (that is the credential-gated live mode,
  and even then a single run is not a benchmark), or execute plans / test real
  delivery (out of scope by design).
