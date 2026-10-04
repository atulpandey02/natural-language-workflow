"""Browser-failure evidence guard (CI only, stdlib only).

Staging-validation uploads Playwright failure evidence (screenshots, video,
``error-context.md``, the HTML report) and a bounded slice of api/web/worker
logs. Nothing credential-bearing may leave the runner, so:

    python3 scripts/ci/evidence_guard.py self-test        # canaries must be removed
    ... | python3 scripts/ci/evidence_guard.py redact     # stdin -> stdout
    python3 scripts/ci/evidence_guard.py scan DIR         # exit 1 on any finding

``scan`` fails closed. It reports file names and rule ids only, never the
matched text. It also checks for the LITERAL values of this job's
credential-named environment variables (the throwaway passwords, keys and
tokens the workflow generated), and it opens the base64 zip that Playwright
embeds in its HTML report so that content is scanned too.
"""

from __future__ import annotations

import base64
import io
import os
import re
import sys
import zipfile
from collections.abc import Iterable, Iterator
from pathlib import Path

# --- redaction ------------------------------------------------------------------

_R = "[REDACTED]"
_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Whole header values: Authorization / Cookie / Set-Cookie (any separator).
    (re.compile(r"(?i)(\b(?:proxy-)?authorization\b[\"']?\s*[:=]\s*)[^\r\n]*"), r"\1" + _R),
    (re.compile(r"(?i)(\b(?:set-)?cookie\b[\"']?\s*[:=]\s*)[^\r\n]*"), r"\1" + _R),
    # Bearer / Basic credentials wherever they appear.
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + _R),
    # JWT-shaped values.
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), _R),
    # Credentials embedded in URLs: scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1" + _R + "@"),
    # Webhook URLs.
    (re.compile(r"(?i)https?://hooks\.slack\.com/\S+"), _R),
    (re.compile(r"(?i)https?://\S*/webhooks?/\S+"), _R),
    # name=value / "name": "value" assignments for credential-like names.
    (
        re.compile(
            r"(?i)(\b[A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|apikey|"
            r"access[_-]?key|private[_-]?key|webhook|session)[A-Za-z0-9_.-]*[\"']?\s*[:=]\s*[\"']?)"
            r"([^\s\"',&;}]+)"
        ),
        r"\1" + _R,
    ),
    # PEM private keys.
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
        _R,
    ),
)


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


# --- detection (fail closed) -----------------------------------------------------

_DETECTORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")),
    ("bearer", re.compile(r"(?i)\bbearer\s+(?!\[REDACTED\])[A-Za-z0-9._~+/=-]{8,}")),
    (
        "auth-header",
        re.compile(r"(?i)\b(?:proxy-)?authorization\b[\"']?\s*[:=]\s*(?!\[REDACTED\])\S"),
    ),
    ("cookie-header", re.compile(r"(?i)\b(?:set-)?cookie\b[\"']?\s*[:=]\s*(?!\[REDACTED\])\S")),
    (
        "url-credentials",
        re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://(?!\[REDACTED\])[^/\s:@]+:[^/\s@]+@"),
    ),
    ("slack-webhook", re.compile(r"(?i)hooks\.slack\.com/services/")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "credential-assignment",
        re.compile(
            r"(?i)\b[A-Za-z0-9_.-]*(?:password|passwd|secret|api[_-]?key|access[_-]?key|"
            r"private[_-]?key)[A-Za-z0-9_.-]*[\"']?\s*[:=]\s*[\"']?(?!\[REDACTED\])[^\s\"',&;}]{6,}"
        ),
    ),
)

# Environment variables whose VALUES must never appear in evidence.
_SECRET_ENV_NAME = re.compile(
    r"(?i)(password|passwd|secret|token|api_?key|access_?key|private_?key|"
    r"database_url|migration_url|cookie|jwt|anon_key|service_role)"
)
_TEXT_SUFFIXES = {".md", ".txt", ".log", ".json", ".html", ".htm", ".js", ".css", ".xml", ""}


def secret_env_values(environ: dict[str, str] | None = None) -> list[str]:
    env = os.environ if environ is None else environ
    return sorted(
        {v for k, v in env.items() if _SECRET_ENV_NAME.search(k) and len(v) >= 8},
        key=len,
        reverse=True,
    )


def findings(text: str, secrets: Iterable[str]) -> list[str]:
    hits = [rule for rule, pattern in _DETECTORS if pattern.search(text)]
    if any(s in text for s in secrets):
        hits.append("environment-secret-value")
    return hits


def _report_payloads(html: str) -> Iterator[tuple[str, str]]:
    """Text members of the base64 zip Playwright embeds in its HTML report."""
    for m in re.finditer(r"data:application/zip;base64,([A-Za-z0-9+/=]+)", html):
        try:
            with zipfile.ZipFile(io.BytesIO(base64.b64decode(m.group(1)))) as zf:
                for name in zf.namelist():
                    yield name, zf.read(name).decode("utf-8", errors="replace")
        except (ValueError, zipfile.BadZipFile):
            yield "<embedded-report>", "\x00undecodable-embedded-report"


def scan(root: Path, secrets: Iterable[str]) -> list[tuple[str, str]]:
    """Every (relative path, rule id) finding under ``root``. Trace archives and
    undecodable embedded reports are themselves findings (fail closed)."""
    secrets = list(secrets)
    out: list[tuple[str, str]] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = str(path.relative_to(root))
        if path.suffix == ".zip" or "trace" in path.name.lower():
            out.append((rel, "trace-or-archive"))
            continue
        if path.suffix.lower() not in _TEXT_SUFFIXES:
            continue  # screenshots / video: binary, not text-scannable
        text = path.read_text(encoding="utf-8", errors="replace")
        out.extend((rel, rule) for rule in findings(text, secrets))
        if path.suffix.lower() in (".html", ".htm"):
            for member, payload in _report_payloads(text):
                if payload.startswith("\x00undecodable"):
                    out.append((f"{rel}!{member}", "undecodable-report"))
                    continue
                if member.endswith(".zip") or "trace" in member.lower():
                    out.append((f"{rel}!{member}", "trace-or-archive"))
                out.extend((f"{rel}!{member}", rule) for rule in findings(payload, secrets))
    return out


# --- canary self-test --------------------------------------------------------------


def _canary(tag: str) -> str:
    # Assembled at runtime so no credential-shaped literal sits in the source
    # (repository precedent for synthetic fixtures; see .gitleaksignore).
    return "CANARY" + tag + "".join(str(i) for i in range(10))


def _fake_jwt() -> str:
    def seg(raw: str) -> str:
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    return ".".join((seg('{"alg":"HS256"}'), seg('{"sub":"canary-user"}'), _canary("sig")))


_CANARIES = {
    "authorization": f"Authorization: Bearer {_canary('bearer')}",
    "cookie": f"Cookie: sb-access-token={_canary('cookie')}; nlw_ws=abc",
    "set-cookie": f"set-cookie: nlw_session={_canary('setcookie')}; Path=/; HttpOnly",
    "jwt": f"token {_fake_jwt()}",
    "password": f'password="{_canary("password")}"',
    "db-url": f"postgresql://nlw_app:{_canary('dbpass')}@postgres:5432/nlw",
    "api-key": f"NLW_LLM_API_KEY={_canary('apikey')}",
    "secret": f'{{"workspace_cookie_secret": "{_canary("secret")}"}}',
    "token": f"access_token={_canary('access')}&x=1",
    "webhook": f"posting to https://hooks.slack.com/services/T000/B000/{_canary('webhook')}",
}


def self_test() -> list[str]:
    """Names of canaries that survive redaction or are not caught raw (empty = pass)."""
    failed = []
    for name, line in _CANARIES.items():
        value = re.search(r"CANARY[A-Za-z0-9]+", line)
        assert value is not None
        redacted = redact(line)
        if value.group(0) in redacted or not findings(line, [value.group(0)]):
            failed.append(name)
        elif findings(redacted, [value.group(0)]):
            failed.append(f"{name}(redacted text still flagged)")
    return failed


def main(argv: list[str]) -> int:
    if argv[:1] == ["self-test"]:
        failed = self_test()
        print("self-test:", "PASS" if not failed else f"FAIL {failed}")
        return 0 if not failed else 1
    if argv[:1] == ["redact"]:
        sys.stdout.write(redact(sys.stdin.read()))
        return 0
    if argv[:1] == ["scan"] and len(argv) == 2:
        hits = scan(Path(argv[1]), secret_env_values())
        for rel, rule in hits:
            print(f"finding: {rel}: {rule}")  # never the matched text
        print("scan:", "clean" if not hits else f"{len(hits)} finding(s)")
        return 0 if not hits else 1
    print("usage: evidence_guard.py self-test | redact | scan DIR", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
