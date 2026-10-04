"""scripts/ci/evidence_guard.py: browser-failure evidence never carries credentials.

Redaction removes every canary; raw canaries are detected; the fail-closed scan
looks inside the base64 zip Playwright embeds in its HTML report; diagnostics
name files and rule ids only, never the matched value.
"""

from __future__ import annotations

import importlib.util
import io
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _guard() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "evidence_guard", ROOT / "scripts/ci/evidence_guard.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["evidence_guard"] = module
    spec.loader.exec_module(module)
    return module


G = _guard()


def _fake(prefix: str) -> str:
    """Synthetic credential-shaped values are assembled at runtime so no
    credential-shaped literal sits in the source (see .gitleaksignore)."""
    return prefix + "".join("0123456789abcdef"[i % 16] for i in range(16))


CASES = {
    "authorization": "Authorization: Bearer abcdefghijklmnopQRST1234",
    "proxy-authorization": "proxy-authorization=Basic dXNlcjpzdXBlcnNlY3JldA==",
    "bearer": "calling upstream with bearer abcdefghijklmnopQRST1234",
    "cookie": "Cookie: sb-access-token=abcdefghijklmnop; nlw_ws=1",
    "set-cookie": "Set-Cookie: nlw_session=abcdefghijklmnop; Path=/; HttpOnly",
    "jwt": "id eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlMTIzNDU2",
    "url-credentials": "connecting postgresql://nlw_app:hunter2hunter2@postgres:5432/nlw",
    "slack-webhook": "posting to https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXX",
    "private-key": "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBg\n-----END PRIVATE KEY-----",
    "password-assignment": 'password="hunter2hunter2"',
    "api-key-assignment": "NLW_LLM_API_KEY=" + _fake("sk-"),
    "secret-json": '{"workspace_cookie_secret": "abcdefghijklmnop"}',
}
SECRETS = [
    "abcdefghijklmnopQRST1234",
    "dXNlcjpzdXBlcnNlY3JldA==",
    "abcdefghijklmnop",
    "c2lnbmF0dXJlMTIzNDU2",
    "hunter2hunter2",
    "XXXXXXXXXXXX",
    "MIIBVQIBADANBg",
    _fake("sk-"),
]


def test_the_built_in_canary_self_test_passes_for_all_eleven_canaries() -> None:
    assert len(G._CANARIES) == 11
    assert "typed-password" in G._CANARIES
    assert G.self_test() == []
    assert G.main(["self-test"]) == 0


@pytest.mark.parametrize("name", sorted(CASES))
def test_each_credential_shape_is_redacted_and_the_raw_form_is_detected(name: str) -> None:
    raw = CASES[name]
    assert G.findings(raw, []), f"{name}: raw form not detected"
    redacted = G.redact(raw)
    assert "[REDACTED]" in redacted
    for value in SECRETS:
        assert value not in redacted, (name, "value survived redaction")
    assert G.findings(redacted, SECRETS) == [], (name, "redacted output still flagged")


def test_ordinary_log_lines_are_untouched_and_clean() -> None:
    line = 'INFO GET /api/nlw/workflows 200 duration_ms=12 request_id="r-1"'
    assert G.redact(line) == line
    assert G.findings(line, SECRETS) == []


def test_environment_secret_values_are_detected_wherever_they_appear() -> None:
    env = {
        "POSTGRES_PASSWORD": _fake("ci_owner_"),
        "DATABASE_URL": "postgresql+psycopg://nlw_app:ci_app_xyz@postgres/nlw",
        "SUPABASE_ANON_KEY": _fake("anon-"),
        "E2E_ADMIN_EMAIL": "admin@example.test",  # not credential-named: ignored
        "PATH": "/usr/bin",
        "WORKSPACE_COOKIE_SECRET": "short",  # < 8 chars: ignored
    }
    values = G.secret_env_values(env)
    assert _fake("ci_owner_") in values and _fake("anon-") in values
    assert "admin@example.test" not in values and "/usr/bin" not in values
    assert "short" not in values
    assert G.findings(f"page text {_fake('ci_owner_')} shown", values) == [
        "environment-secret-value"
    ]


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
WEBM = b"\x1a\x45\xdf\xa3" + b"\x00" * 16
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 16


def test_scan_is_an_allowlist_html_reports_traces_zips_and_dumps_are_never_safe(
    tmp_path: Path,
) -> None:
    for rel in (
        "playwright-report/index.html",
        "test-results/t1/trace.zip",
        "test-results/t1/trace",
        "test-results/t1/report.json",
        "test-results/.env",
        "test-results/.env.local",
        "db.dump",
        "globals.sql",
        "id_rsa.key",
        "cookies.txt.bak",
    ):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_bytes(b"x")
    hits = dict(G.scan(tmp_path, []))
    assert set(hits.values()) == {"disallowed-file-type"}
    assert len(hits) == 10


def test_binary_artifacts_must_match_their_format(tmp_path: Path) -> None:
    (tmp_path / "shot.png").write_bytes(PNG)
    (tmp_path / "shot.jpg").write_bytes(JPEG)
    (tmp_path / "video.webm").write_bytes(WEBM)
    (tmp_path / "error-context.md").write_text("# Page snapshot\n- heading 'Connectors'\n")
    assert G.scan(tmp_path, SECRETS) == []
    # A text file disguised as a screenshot (or a truncated signature) is unsafe.
    (tmp_path / "disguised.png").write_bytes(b"\x89PNG password=hunter2hunter2")
    (tmp_path / "fake.webm").write_text("Authorization: Bearer abcdefghijklmnopQRST1234")
    hits = dict(G.scan(tmp_path, SECRETS))
    assert hits == {
        "disguised.png": "unexpected-binary-content",
        "fake.webm": "unexpected-binary-content",
    }


def test_malformed_text_and_symlinks_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "bad.md").write_bytes(b"\xff\xfe not utf-8")
    (tmp_path / "nul.txt").write_bytes(b"ok\x00hidden")
    (tmp_path / "target.md").write_text("fine")
    (tmp_path / "link.md").symlink_to(tmp_path / "target.md")
    hits = dict(G.scan(tmp_path, []))
    assert hits == {"bad.md": "malformed-text", "nul.txt": "malformed-text", "link.md": "symlink"}
    with pytest.raises(ValueError):
        G.redact_tree(tmp_path, [])
    assert G.main(["redact-tree", str(tmp_path)]) == 3


def test_typed_input_arguments_are_redacted_and_detected() -> None:
    for line in (
        '  - locator.fill("hunter2hunter2")',
        "await page.getByLabel('Password').type('hunter2hunter2')",
        "pressSequentially(`hunter2hunter2`)",
        'keyboard.insertText("hunter2hunter2")',
    ):
        assert "typed-input" in G.findings(line, [])
        redacted = G.redact(line)
        assert "hunter2hunter2" not in redacted and "[REDACTED]" in redacted
        assert G.findings(redacted, []) == []


def test_literal_job_secret_values_are_redacted() -> None:
    secret = _fake("e2e-pass-")
    text = f'- textbox "Password" [value={secret}]\nTyped {secret} into the form'
    redacted = G.redact(text, [secret])
    assert secret not in redacted and redacted.count("[REDACTED]") == 2
    assert G.findings(redacted, [secret]) == []


def test_redact_tree_redacts_every_text_artifact_in_place(tmp_path: Path) -> None:
    secret = _fake("e2e-pass-")
    (tmp_path / "t1").mkdir()
    (tmp_path / "t1/error-context.md").write_text(f'locator.fill("{secret}")\nPassword: {secret}')
    (tmp_path / "t1/notes.txt").write_text(f"Cookie: sb={secret}")
    (tmp_path / "t1/shot.png").write_bytes(PNG)
    assert G.redact_tree(tmp_path, [secret]) == 2
    for name in ("t1/error-context.md", "t1/notes.txt"):
        assert secret not in (tmp_path / name).read_text()
    assert (tmp_path / "t1/shot.png").read_bytes() == PNG  # binaries untouched
    assert G.scan(tmp_path, [secret]) == []


def test_diagnostics_name_files_and_rules_but_never_the_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = _fake("ci_owner_")
    monkeypatch.setenv("POSTGRES_PASSWORD", secret)
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs/api.log").write_text(
        f"Authorization: Bearer abcdefghijklmnopQRST1234\nleaked {secret}\n"
    )
    assert G.main(["scan", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "logs/api.log: auth-header" in out
    assert "logs/api.log: environment-secret-value" in out
    assert secret not in out and "abcdefghijklmnopQRST1234" not in out


def test_redact_cli_round_trip(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("Cookie: sb=abcdefghijklmnop\nok\n"))
    assert G.main(["redact"]) == 0
    assert capsys.readouterr().out == "Cookie: [REDACTED]\nok\n"
