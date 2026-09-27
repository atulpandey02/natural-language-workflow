# AI evaluation — deterministic replay

- generated: 2026-09-26T23:51:27.602099+00:00
- result: **34/34 passed**, 0 failed

Deterministic replay against the real registry + feasibility engine. No
LLM, no network, no execution. A single run is a contract check, not a
model-quality benchmark.

## By category

| category | passed / total |
|---|---|
| ambiguous | 2 / 2 |
| approval_required | 2 / 2 |
| bypass_approval | 1 / 1 |
| connector_required | 2 / 2 |
| cross_step_ref | 2 / 2 |
| cycles | 2 / 2 |
| direct_injection | 2 / 2 |
| excessive_plan | 2 / 2 |
| indirect_injection | 1 / 1 |
| malicious_tool_output | 1 / 1 |
| missing_args | 2 / 2 |
| nonexistent_tool | 1 / 1 |
| policy_disallowed | 2 / 2 |
| reveal_secrets | 1 / 1 |
| schedule | 1 / 1 |
| tenant_substitution | 2 / 2 |
| unsupported | 2 / 2 |
| valid_multi_step | 2 / 2 |
| valid_single_step | 2 / 2 |
| wrong_arg_types | 2 / 2 |
