"""Deterministic evaluation-corpus replay (M12B-A, Part B; acceptance #1, #14).

Every checked-in case is graded against the REAL registry + feasibility engine
with zero LLM/network. This proves the acceptance criteria that matter for
safety: no invalid or adversarial plan reaches execution, approval policy cannot
be weakened by model output, and tenant/connector substitution and injection are
blocked deterministically. No case executes anything.
"""

import pytest

from nlw.eval.harness import EvalCase, load_all_cases, replay_case

CASES = load_all_cases()
REQUIRED_CATEGORIES = {
    "valid_single_step",
    "valid_multi_step",
    "connector_required",
    "schedule",
    "approval_required",
    "unsupported",
    "ambiguous",
    "nonexistent_tool",
    "wrong_arg_types",
    "missing_args",
    "cross_step_ref",
    "cycles",
    "excessive_plan",
    "bypass_approval",
    "direct_injection",
    "indirect_injection",
    "reveal_secrets",
    "malicious_tool_output",
    "tenant_substitution",
    "policy_disallowed",
}


def test_corpus_has_at_least_30_cases_across_all_categories() -> None:
    assert len(CASES) >= 30, f"corpus has only {len(CASES)} cases"
    present = {c.category for c in CASES}
    assert present >= REQUIRED_CATEGORIES, f"missing categories: {REQUIRED_CATEGORIES - present}"
    ids = [c.id for c in CASES]
    assert len(ids) == len(set(ids)), "duplicate case ids"


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_case_matches_expected_outcome(case: EvalCase) -> None:
    result = replay_case(case)
    assert result.passed, f"{case.id}: {result.failures}"


def test_no_invalid_or_adversarial_case_can_start_execution() -> None:
    # Every REJECT case must be non-executable; approval cases must not auto-start
    # without the approval gate. This is the safety backstop of the whole corpus.
    for case in CASES:
        result = replay_case(case)
        if result.expected_status == "REJECT":
            assert not result.execution_may_start, f"{case.id} REJECT but execution could start"
        if result.observed_status == "NEEDS_APPROVAL":
            assert result.observed_approvals, f"{case.id} NEEDS_APPROVAL without an approval step"


def test_adversarial_categories_never_pass_silently() -> None:
    adversarial = {
        "direct_injection",
        "reveal_secrets",
        "tenant_substitution",
    }
    for case in CASES:
        if case.category in adversarial:
            result = replay_case(case)
            assert result.observed_status == "REJECT", f"{case.id} adversarial but not REJECT"
