"""Tests for scripts/ops/deploy-staging.sh (Stage-2 deploy).

Covers the migration-verification fix (deterministic head derivation + scalar
current revision, robust to NAMED revisions like 0010_readiness_schema_grant)
and the first/--resume state-machine safety guarantees. The pure shell helpers
are exercised by sourcing the script (its main() is source-guarded); the
first/resume guarantees are asserted statically on the script text.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "scripts" / "ops" / "deploy-staging.sh"
VERIFY = ROOT / "scripts" / "ops" / "verify-staging-deployment.sh"
NAMED_REV = "0010_readiness_schema_grant"


def _sh(call: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
    """Source the deploy script (main() is guarded) and run a helper call."""
    return subprocess.run(
        ["bash", "-c", f'source "{DEPLOY}"; {call}'],
        input=stdin,
        capture_output=True,
        text=True,
    )


def _func_body(text: str, name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{\n(.*?)\n\}}$", text, re.S | re.M)
    assert m, f"could not locate function {name}()"
    return m.group(1)


# --- 1. Expected-head derivation yields the NAMED revision for this repo -----
def test_alembic_head_derivation_named_revision() -> None:
    # The exact method the deploy script runs in-image, here against the repo.
    proc = subprocess.run(
        [
            "uv",
            "run",
            "python",
            "-c",
            "from alembic.config import Config; from alembic.script import ScriptDirectory; "
            "print(ScriptDirectory.from_config(Config('alembic.ini')).get_current_head())",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == NAMED_REV


def test_parse_head_line_extracts_named_revision() -> None:
    r = _sh("parse_head_line", stdin=f"HEAD={NAMED_REV}\n")
    assert r.stdout.strip() == NAMED_REV
    # Tolerates surrounding container noise on other lines.
    r2 = _sh("parse_head_line", stdin=f"some noise\nHEAD={NAMED_REV}\n")
    assert r2.stdout.strip() == NAMED_REV


# --- 2. Current-revision scalar extraction ----------------------------------
def test_parse_current_strips_whitespace_and_cr() -> None:
    r = _sh("parse_current", stdin=f"  {NAMED_REV}\r\n")
    assert r.stdout.strip() == NAMED_REV


# --- 3-6. assert_revisions matrix -------------------------------------------
def test_assert_revisions_match_passes() -> None:
    assert _sh(f'assert_revisions "{NAMED_REV}" "{NAMED_REV}"').returncode == 0


def test_assert_revisions_mismatch_fails() -> None:
    assert _sh(f'assert_revisions "{NAMED_REV}" "0009_other"').returncode != 0


def test_assert_revisions_empty_expected_fails() -> None:
    assert _sh(f'assert_revisions "" "{NAMED_REV}"').returncode != 0


def test_assert_revisions_empty_current_fails() -> None:
    assert _sh(f'assert_revisions "{NAMED_REV}" ""').returncode != 0


# --- the old brittle hex-only parser is GONE (root cause) --------------------
def test_no_hex_only_alembic_grep_remains() -> None:
    for f in (DEPLOY, VERIFY):
        assert "[0-9a-f]{12,}" not in f.read_text(), f"{f.name} still uses the hex-only grep"


def test_deterministic_verifier_uses_scriptdirectory_and_scalar() -> None:
    for f in (DEPLOY, VERIFY):
        t = f.read_text()
        assert "get_current_head()" in t, f"{f.name} must derive head via ScriptDirectory"
        assert "SELECT version_num FROM alembic_version" in t, f"{f.name} must read current scalar"


# --- 7. First deploy rejects an existing .env.prod --------------------------
def test_first_deploy_rejects_existing_env() -> None:
    body = _func_body(DEPLOY.read_text(), "create_env_first")
    assert "test -e '$REMOTE_APP/.env.prod'" in body
    assert "already exists" in body and "--resume" in body
    # The remote builder also refuses to overwrite.
    assert 'if [ -e "\\$ENVF" ]; then echo "STOP:' in body


# --- 8. --resume requires an existing .env.prod (mode 600) ------------------
def test_resume_requires_existing_env_600() -> None:
    body = _func_body(DEPLOY.read_text(), "verify_env_resume")
    assert "does not exist" in body
    assert '"$mode" = "600"' in body or '= "600"' in body


# --- 9. --resume never regenerates secrets ----------------------------------
def test_resume_never_regenerates_secrets() -> None:
    text = DEPLOY.read_text()
    # openssl only appears in the first-deploy builder, never the resume verifier.
    assert "openssl rand" in _func_body(text, "create_env_first")
    assert "openssl" not in _func_body(text, "verify_env_resume")
    # main() routes first->create_env_first, resume->verify_env_resume.
    main = _func_body(text, "main")
    assert 'if [ "$mode" = "first" ]; then' in main
    assert "create_env_first" in main and "verify_env_resume" in main


# --- 10. Never deletes volumes / recreates pg / downgrades (both modes) ------
def test_no_destructive_operations_anywhere() -> None:
    text = DEPLOY.read_text()
    for danger in ("down -v", "--volumes", "volume rm", "rm -rf", "alembic downgrade"):
        assert danger not in text, f"destructive op present: {danger}"
    # Datastores are started with --no-recreate to protect pgdata/redis.
    assert "up -d --no-recreate postgres redis" in text


# --- 11-14. --resume validates SHA, backend digest, web digest, hostname -----
def test_resume_validates_pins() -> None:
    text = DEPLOY.read_text()
    # Git SHA is enforced by pin_config (runs in BOTH modes).
    assert "!= pinned $DEPLOY_SHA" in _func_body(text, "pin_config")
    resume = _func_body(text, "verify_env_resume")
    assert "NLW_IMAGE=$BACKEND_IMAGE" in resume
    assert "NLW_WEB_IMAGE=$WEB_IMAGE" in resume
    assert "PUBLIC_HOSTNAME=$STAGING_HOST" in resume


# --- Phase-aware reporting + source guard -----------------------------------
# --- Deploy-time secret validation (pure helpers) ---------------------------
def test_valid_supabase_anon_key_accepts_publishable() -> None:
    assert _sh('valid_supabase_anon_key "sb_publishable_abc123"').returncode == 0


def test_valid_supabase_anon_key_rejects_bad_keys() -> None:
    for bad in ("", "sb_publishable_", "sb_secret_abc", "eyJhbGciOi", "publishable_x"):
        assert _sh(f'valid_supabase_anon_key "{bad}"').returncode != 0, bad


def test_llm_key_required_only_for_anthropic() -> None:
    # anthropic + empty key => fail; anthropic + key => ok
    assert _sh('require_llm_key_ok "anthropic" ""').returncode != 0
    assert _sh('require_llm_key_ok "anthropic" "sk-ant-xxx"').returncode == 0
    # stub (or anything else) never requires a key
    assert _sh('require_llm_key_ok "stub" ""').returncode == 0
    assert _sh('require_llm_key_ok "" ""').returncode == 0


def test_deploy_validates_anon_key_before_writing() -> None:
    body = _func_body(DEPLOY.read_text(), "create_env_first")
    assert 'valid_supabase_anon_key "$anon"' in body  # validated before the builder runs
    assert 'echo "$anon"' not in body  # never echoed


def test_deploy_verify_secrets_config_present() -> None:
    text = DEPLOY.read_text()
    assert "verify_secrets_config" in _func_body(text, "main")
    body = _func_body(text, "verify_secrets_config")
    assert "sb_publishable_?*" in body
    assert "= anthropic" in body
    assert "NLW_LLM_API_KEY=.+" in body


# --- Role-attribute verifier (verify-staging-deployment.sh) ------------------
_ROLES_OK = "\n".join(
    [
        "nlw_app:tff",
        "nlw_rls_bypass:fft",
        "nlw_scheduler:tff",
        "nlw_worker:tff",
        "nlw_workspace_bootstrap:fft",
    ]
)
_EXPECTED_ROLE_LINES = [
    "nlw_app:tff",
    "nlw_worker:tff",
    "nlw_scheduler:tff",
    "nlw_rls_bypass:fft",
    "nlw_workspace_bootstrap:fft",
]


def _assert_role(expected: str, block: str) -> int:
    return subprocess.run(
        ["bash", "-c", f'source "{VERIFY}"; assert_role "$1" "$2"', "_", expected, block],
        capture_output=True,
        text=True,
    ).returncode


def test_verifier_uses_case_not_boolean_concat() -> None:
    # Root-cause fix: boolean || text yields 'true'/'false', so CASE renders t/f.
    t = VERIFY.read_text()
    assert "CASE WHEN rolcanlogin THEN 't' ELSE 'f' END" in t
    assert "rolname||':'||rolcanlogin||rolsuper||rolbypassrls" not in t


def test_all_five_expected_roles_match() -> None:
    for role in _EXPECTED_ROLE_LINES:
        assert _assert_role(role, _ROLES_OK) == 0, role


def test_expected_roles_array_is_exactly_the_five() -> None:
    out = subprocess.run(
        ["bash", "-c", f'source "{VERIFY}"; printf "%s\\n" "${{EXPECTED_ROLES[@]}}"'],
        capture_output=True,
        text=True,
    ).stdout.split()
    assert sorted(out) == sorted(_EXPECTED_ROLE_LINES)


def test_wrong_attribute_combination_fails() -> None:
    # nlw_app with bypassrls set (tft) or superuser (ttf) must NOT satisfy :tff.
    for wrong in ("nlw_app:tft", "nlw_app:ttf", "nlw_app:ttt", "nlw_app:fff"):
        block = _ROLES_OK.replace("nlw_app:tff", wrong)
        assert _assert_role("nlw_app:tff", block) != 0, wrong
    # A login helper role (should be NOLOGIN) must fail.
    bad = _ROLES_OK.replace("nlw_rls_bypass:fft", "nlw_rls_bypass:tft")
    assert _assert_role("nlw_rls_bypass:fft", bad) != 0


def test_verify_script_source_guarded() -> None:
    assert 'if [ "${BASH_SOURCE[0]}" != "${0}" ]; then' in VERIFY.read_text()


def test_phase_tracking_and_source_guard() -> None:
    text = DEPLOY.read_text()
    for ph in (
        "env_created",
        "postgres_started",
        "redis_started",
        "role_bootstrap_verified",
        "migrations_applied",
        "migrations_verified",
        "application_services_started",
        "readiness_verified",
        "tls_verified",
    ):
        assert ph in text, f"phase {ph} not tracked"
    assert "migrations_applied && warn" in text or "migrations_applied" in _func_body(
        text, "fail_report"
    )
    assert 'if [ "${BASH_SOURCE[0]}" = "${0}" ]; then' in text
