"""Browser-failure evidence guard (CI only, stdlib only).

Staging-validation uploads Playwright failure evidence (screenshots, failure
video, ``error-context.md``) and a bounded slice of api/web/worker logs.
Nothing credential-bearing may leave the runner, so:

    python3 scripts/ci/evidence_guard.py self-test        # canaries must be removed
    ... | python3 scripts/ci/evidence_guard.py redact     # stdin -> stdout
    python3 scripts/ci/evidence_guard.py redact-tree DIR  # every text artifact, in place
    python3 scripts/ci/evidence_guard.py scan DIR         # exit 1 on any finding

Redaction removes credential-shaped text (authorization/cookie headers, bearer
and basic credentials, JWTs, URL credentials, webhooks, private keys,
credential assignments), the arguments of typed-input calls (``fill``,
``type``, ``pressSequentially``, ``insertText``) and the LITERAL values of this
job's credential-named environment variables, which is where the synthetic
E2E passwords live.

``scan`` fails closed and is an ALLOWLIST: only screenshots (``.png``,
``.jpg``/``.jpeg``) and video (``.webm``) whose bytes match their format, and
UTF-8 text (``.md``, ``.txt``, ``.log``) are acceptable. Everything else (HTML
reports, traces, ZIPs, JSON, ``.env*``, dumps, keys, unknown or disguised
files) is itself a finding. Diagnostics name files and rule ids only, never the
matched text.
"""

from __future__ import annotations

import base64
import os
import re
import sys
from collections.abc import Iterable, Sequence
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
    # Typed input in call logs / snapshots: fill("..."), type('...'), etc.
    (
        re.compile(
            r"(\b(?:fill|type|pressSequentially|insertText)\s*\(\s*)([\"'`])(?:\\.|(?!\2).)*\2"
        ),
        r"\1\2" + _R + r"\2",
    ),
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


def redact(text: str, secrets: Sequence[str] = ()) -> str:
    """Literal job-secret values first (longest first), then credential shapes."""
    for value in sorted(secrets, key=len, reverse=True):
        text = text.replace(value, _R)
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
        "typed-input",
        re.compile(
            r"\b(?:fill|type|pressSequentially|insertText)\s*\(\s*([\"'`])(?!\[REDACTED\]\1)"
            r"(?:\\.|(?!\1).)+\1"
        ),
    ),
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

# The ONLY artifact types that may be uploaded.
TEXT_SUFFIXES = frozenset({".md", ".txt", ".log"})
BINARY_MAGIC: dict[str, tuple[bytes, ...]] = {
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".webm": (b"\x1a\x45\xdf\xa3",),
}


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


def _read_text(path: Path) -> str | None:
    """UTF-8 text without NUL bytes, or None (malformed)."""
    raw = path.read_bytes()
    if b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def scan(root: Path, secrets: Iterable[str]) -> list[tuple[str, str]]:
    """Every (relative path, rule id) finding under ``root``; empty = safe to upload."""
    secrets = list(secrets)
    out: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if path.is_symlink():
            out.append((rel, "symlink"))
            continue
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix in BINARY_MAGIC:
            head = path.read_bytes()[:16]
            if not any(head.startswith(m) for m in BINARY_MAGIC[suffix]):
                out.append((rel, "unexpected-binary-content"))
            continue  # verified screenshot / video: binary, not text-scannable
        if suffix not in TEXT_SUFFIXES:
            out.append((rel, "disallowed-file-type"))  # html, zip, trace, json, env, dump...
            continue
        text = _read_text(path)
        if text is None:
            out.append((rel, "malformed-text"))
            continue
        out.extend((rel, rule) for rule in findings(text, secrets))
    return out


def redact_tree(root: Path, secrets: Sequence[str]) -> int:
    """Redact every allowed text artifact under ``root`` in place. Returns the number
    of files redacted; raises ValueError on malformed text (caller fails closed)."""
    count = 0
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink() and path.suffix.lower() in TEXT_SUFFIXES:
            text = _read_text(path)
            if text is None:
                raise ValueError("malformed text artifact")
            path.write_text(redact(text, secrets), encoding="utf-8")
            count += 1
    return count


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
    "typed-password": f'  - locator.fill("{_canary("typed")}") on getByLabel("Password")',
}


def self_test() -> list[str]:
    """Names of canaries that survive redaction or are not caught raw (empty = pass).
    Each canary is also checked as a literal job-secret value."""
    failed = []
    for name, line in _CANARIES.items():
        value = re.search(r"CANARY[A-Za-z0-9]+", line)
        assert value is not None
        redacted = redact(line)
        if value.group(0) in redacted or not findings(line, [value.group(0)]):
            failed.append(name)
        elif findings(redacted, [value.group(0)]):
            failed.append(f"{name}(redacted text still flagged)")
        elif value.group(0) in redact(f"value {value.group(0)} shown", [value.group(0)]):
            failed.append(f"{name}(literal secret survived)")
    return failed


def main(argv: list[str]) -> int:
    try:
        if argv[:1] == ["self-test"]:
            failed = self_test()
            print("self-test:", "PASS" if not failed else f"FAIL {failed}")
            return 0 if not failed else 1
        if argv[:1] == ["redact"]:
            sys.stdout.write(redact(sys.stdin.read(), secret_env_values()))
            return 0
        if argv[:1] == ["redact-tree"] and len(argv) == 2:
            n = redact_tree(Path(argv[1]), secret_env_values())
            print(f"redacted {n} text artifact(s)")
            return 0
        if argv[:1] == ["scan"] and len(argv) == 2:
            hits = scan(Path(argv[1]), secret_env_values())
            for rel, rule in hits:
                print(f"finding: {rel}: {rule}")  # never the matched text
            print("scan:", "clean" if not hits else f"{len(hits)} finding(s)")
            return 0 if not hits else 1
    except Exception as exc:  # any guard error fails closed, without echoing content
        print(f"evidence guard error: {type(exc).__name__}")
        return 3
    print(
        "usage: evidence_guard.py self-test | redact | redact-tree DIR | scan DIR", file=sys.stderr
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
