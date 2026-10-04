"""scripts/ci/evidence_guard.py: browser-failure evidence never carries credentials.

Redaction removes every canary; raw canaries are detected; the fail-closed scan
looks inside the base64 zip Playwright embeds in its HTML report; diagnostics
name files and rule ids only, never the matched value.
"""

from __future__ import annotations

import base64
import importlib.util
import io
import sys
import zipfile
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


def test_the_built_in_canary_self_test_passes_for_all_ten_canaries() -> None:
    assert len(G._CANARIES) == 10
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


def _report(payload: str) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("report.json", payload)
    b64 = base64.b64encode(buf.getvalue()).decode()
    return (
        "<html><script>window.playwrightReportBase64 = "
        f"'data:application/zip;base64,{b64}';</script></html>"
    )


def test_scan_inspects_the_zip_embedded_in_the_html_report(tmp_path: Path) -> None:
    clean = tmp_path / "clean"
    (clean / "playwright-report").mkdir(parents=True)
    (clean / "playwright-report/index.html").write_text(_report('{"title": "happy path"}'))
    assert G.scan(clean, SECRETS) == []

    dirty = tmp_path / "dirty"
    (dirty / "playwright-report").mkdir(parents=True)
    (dirty / "playwright-report/index.html").write_text(
        _report('{"step": "Authorization: Bearer abcdefghijklmnopQRST1234"}')
    )
    hits = G.scan(dirty, SECRETS)
    assert ("playwright-report/index.html!report.json", "auth-header") in hits


def test_scan_fails_closed_on_traces_archives_and_undecodable_reports(tmp_path: Path) -> None:
    (tmp_path / "test-results/t1").mkdir(parents=True)
    (tmp_path / "test-results/t1/trace.zip").write_bytes(b"PK\x03\x04")
    (tmp_path / "test-results/t1/trace").write_text("{}")
    (tmp_path / "index.html").write_text("data:application/zip;base64,bm90LWEtemlw")
    rules = {rule for _, rule in G.scan(tmp_path, [])}
    assert {"trace-or-archive", "undecodable-report"} <= rules


def test_binary_screenshots_and_video_are_kept_but_not_text_scanned(tmp_path: Path) -> None:
    (tmp_path / "shot.png").write_bytes(b"\x89PNG password=hunter2hunter2")
    (tmp_path / "video.webm").write_bytes(b"\x1aE\xdf\xa3")
    (tmp_path / "error-context.md").write_text("# Page snapshot\n- heading 'Connectors'\n")
    assert G.scan(tmp_path, SECRETS) == []


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
