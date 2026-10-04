"""Regression: authenticated browser-failure evidence never carries credentials.

Runs the REAL ``scripts/ci/collect_browser_evidence.sh`` against a synthetic
failed login test: the E2E password is typed into a login form and shows up in
Playwright's ``error-context.md`` (call log and page snapshot) and in an HTML
report; job secrets sit in the environment; the api/web/worker logs carry
authorization headers, cookies, JWTs, credential-bearing URLs, webhooks and a
private key; traces, ZIPs, JSON, ``.env`` files and dumps are lying around.

The uploaded evidence must keep the useful parts (screenshot, failure video,
the redacted error context and logs) and contain none of the secrets or
forbidden files. Malformed, disguised or oversized evidence and guard errors
must upload nothing.
"""

from __future__ import annotations

import base64
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COLLECTOR = ROOT / "scripts/ci/collect_browser_evidence.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("rsync") is None or shutil.which("bash") is None,
    reason="collector needs bash and rsync (present on CI runners)",
)

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
WEBM = b"\x1a\x45\xdf\xa3" + b"\x00" * 64


def _fake(prefix: str) -> str:
    # Assembled at runtime: no credential-shaped literal in the source.
    return prefix + "".join("0123456789abcdef"[(i * 7) % 16] for i in range(20))


def _jwt() -> str:
    def seg(raw: str) -> str:
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    return ".".join((seg('{"alg":"HS256"}'), seg('{"sub":"e2e-admin"}'), _fake("sig")))


PASSWORD = _fake("e2e-admin-pw-")
SECRETS = {
    "E2E_ADMIN_PASSWORD": PASSWORD,
    "POSTGRES_PASSWORD": _fake("ci_owner_"),
    "DATABASE_URL": "postgresql+psycopg://nlw_app:" + _fake("ci_app_") + "@postgres:5432/nlw",
    "SUPABASE_ANON_KEY": _jwt(),
    "WORKSPACE_COOKIE_SECRET": _fake("cookie-secret-"),
}
SESSION = _fake("sb-session-")
PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n" + _fake("MIIEv") + "\n-----END PRIVATE KEY-----"
WEBHOOK = "https://hooks.slack.com/services/T000/B000/" + _fake("hook")
BEARER = _fake("bearer-")


def _error_context() -> str:
    return "\n".join(
        [
            "# Page snapshot",
            '- heading "Sign in" [level=1]',
            '- textbox "Email": e2e-admin@example.test',
            f'- textbox "Password": {PASSWORD}',
            '- button "Sign in"',
            "# Call log",
            "  - locator.fill(" + '"' + PASSWORD + '"' + ') on getByLabel("Password")',
            f"  - typed {PASSWORD} into the password field",
            f"  - request Authorization: Bearer {BEARER}",
            f"  - Cookie: sb-access-token={SESSION}",
            f"  - token {SECRETS['SUPABASE_ANON_KEY']}",
            f"  - db {SECRETS['DATABASE_URL'].replace('+psycopg', '')}",
            f"  - posting {WEBHOOK}",
            "# Error",
            'expect(locator).toBeVisible() failed: getByRole("cell", { name: "static-e2e" })',
        ]
    )


FAKE_COMPOSE = """#!/usr/bin/env bash
svc="${{*: -1}}"
echo "$svc | INFO GET /api/nlw/connectors 200 duration_ms=12"
echo "$svc | Authorization: Bearer {bearer}"
echo "$svc | Set-Cookie: nlw_session={session}; HttpOnly"
echo "$svc | jwt {jwt}"
echo "$svc | db {db}"
echo "$svc | password={password} webhook={webhook}"
echo "$svc | {pk_line}"
echo "$svc | login form submitted with $E2E_ADMIN_PASSWORD"
echo "$svc | owner pw $POSTGRES_PASSWORD cookie secret $WORKSPACE_COOKIE_SECRET"
"""


def _setup(tmp_path: Path) -> dict[str, str]:
    work = tmp_path / "work"
    test_dir = work / "web/test-results/login-chromium"
    test_dir.mkdir(parents=True)
    (test_dir / "test-failed-1.png").write_bytes(PNG)
    (test_dir / "video.webm").write_bytes(WEBM)
    (test_dir / "error-context.md").write_text(_error_context())
    (test_dir / "trace.zip").write_bytes(b"PK\x03\x04" + PASSWORD.encode())
    (test_dir / "trace").mkdir()
    (test_dir / "trace" / "trace.network").write_text(f"Cookie: {SESSION}")
    (test_dir / "report.json").write_text(f'{{"password": "{PASSWORD}"}}')
    (test_dir / ".env").write_text(f"E2E_ADMIN_PASSWORD={PASSWORD}")
    (test_dir / "db.dump").write_bytes(b"PGDMP" + PASSWORD.encode())
    (test_dir / "page.html").write_text(f"<input value='{PASSWORD}'>")
    report = work / "web/playwright-report"
    report.mkdir(parents=True)
    (report / "index.html").write_text(f"<script>var report='{PASSWORD}'</script>")

    compose = tmp_path / "fake-compose"
    compose.write_text(
        FAKE_COMPOSE.format(
            bearer=BEARER,
            session=SESSION,
            jwt=SECRETS["SUPABASE_ANON_KEY"],
            db=SECRETS["DATABASE_URL"].replace("+psycopg", ""),
            password=PASSWORD,
            webhook=WEBHOOK,
            pk_line=PRIVATE_KEY.replace("\n", " "),
        )
    )
    compose.chmod(compose.stat().st_mode | stat.S_IEXEC)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    if shutil.which("timeout") is None:  # macOS: test-only shim; CI has GNU timeout
        shim = bin_dir / "timeout"
        shim.write_text('#!/usr/bin/env bash\nshift\nexec "$@"\n')
        shim.chmod(0o755)
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "COMPOSE": str(compose),
        "GITHUB_OUTPUT": str(tmp_path / "gh_output"),
        **SECRETS,
    }
    return env


def _collect(tmp_path: Path, env: dict[str, str]) -> tuple[subprocess.CompletedProcess[str], Path]:
    out = tmp_path / "evidence"
    res = subprocess.run(
        ["bash", str(COLLECTOR), str(out)],
        cwd=tmp_path / "work",
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    return res, out


def _ready(tmp_path: Path) -> str:
    return (tmp_path / "gh_output").read_text().strip().splitlines()[-1]


def _forbidden_values() -> list[str]:
    return [
        PASSWORD,
        BEARER,
        SESSION,
        WEBHOOK,
        SECRETS["SUPABASE_ANON_KEY"],
        SECRETS["DATABASE_URL"],
        SECRETS["DATABASE_URL"].replace("+psycopg", ""),
        SECRETS["POSTGRES_PASSWORD"],
        SECRETS["WORKSPACE_COOKIE_SECRET"],
        PRIVATE_KEY.splitlines()[1],
        "BEGIN PRIVATE KEY",
    ]


def test_typed_password_and_every_secret_are_absent_but_useful_evidence_remains(
    tmp_path: Path,
) -> None:
    env = _setup(tmp_path)
    res, out = _collect(tmp_path, env)
    assert res.returncode == 0, res.stdout + res.stderr
    assert _ready(tmp_path) == "ready=true", res.stdout
    files = sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file())
    assert files == [
        "logs/api.log",
        "logs/web.log",
        "logs/worker.log",
        "test-results/login-chromium/error-context.md",
        "test-results/login-chromium/test-failed-1.png",
        "test-results/login-chromium/video.webm",
    ]
    # Never collected: HTML report, traces, ZIP, JSON, .env, dumps, HTML.
    assert not (out / "playwright-report").exists()
    # No forbidden value in ANY byte of ANY uploaded file.
    for path in out.rglob("*"):
        if path.is_file():
            blob = path.read_bytes()
            for value in _forbidden_values():
                assert value.encode() not in blob, (path.name, "leaked value")
    # Useful content survives redaction.
    ctx = (out / "test-results/login-chromium/error-context.md").read_text()
    assert '- heading "Sign in"' in ctx and "static-e2e" in ctx and "[REDACTED]" in ctx
    api = (out / "logs/api.log").read_text()
    assert "GET /api/nlw/connectors 200" in api and "[REDACTED]" in api
    assert (out / "test-results/login-chromium/test-failed-1.png").read_bytes() == PNG
    # Diagnostics never echo a secret.
    for value in _forbidden_values():
        assert value not in res.stdout + res.stderr


def test_malformed_text_artifact_uploads_nothing(tmp_path: Path) -> None:
    env = _setup(tmp_path)
    ctx = tmp_path / "work/web/test-results/login-chromium/error-context.md"
    ctx.write_bytes(b"\xff\xfe" + PASSWORD.encode())
    res, out = _collect(tmp_path, env)
    assert _ready(tmp_path) == "ready=false" and not out.exists()
    assert "text artifact redaction failed: nothing uploaded" in res.stdout


def test_disguised_binary_uploads_nothing(tmp_path: Path) -> None:
    env = _setup(tmp_path)
    shot = tmp_path / "work/web/test-results/login-chromium/test-failed-1.png"
    shot.write_text(f"password={PASSWORD}")
    res, out = _collect(tmp_path, env)
    assert _ready(tmp_path) == "ready=false" and not out.exists()
    assert "unexpected-binary-content" in res.stdout


def test_size_limit_drops_video_first_then_uploads_nothing(tmp_path: Path) -> None:
    env = _setup(tmp_path)
    big = tmp_path / "work/web/test-results/login-chromium/video.webm"
    big.write_bytes(WEBM + b"\x00" * (3 * 1024 * 1024))
    res, out = _collect(tmp_path, {**env, "EVIDENCE_MAX_MB": "2"})
    assert _ready(tmp_path) == "ready=true", res.stdout
    assert not any(out.rglob("*.webm")) and any(out.rglob("*.png"))

    shot = tmp_path / "work/web/test-results/login-chromium/test-failed-1.png"
    shot.write_bytes(PNG + b"\x00" * (3 * 1024 * 1024))
    res, out = _collect(tmp_path, {**env, "EVIDENCE_MAX_MB": "2"})
    assert _ready(tmp_path) == "ready=false" and not out.exists()
    assert "even without video: nothing uploaded" in res.stdout


def test_guard_errors_fail_closed(tmp_path: Path) -> None:
    env = _setup(tmp_path)
    broken = tmp_path / "bin" / "python3"  # every guard call now errors
    broken.write_text("#!/usr/bin/env bash\nexit 3\n")
    broken.chmod(0o755)
    res, out = _collect(tmp_path, env)
    assert _ready(tmp_path) == "ready=false" and not out.exists()
    assert "nothing uploaded" in res.stdout
