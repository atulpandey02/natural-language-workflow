#!/usr/bin/env bash
# Collect SAFE Playwright failure evidence for upload (staging-validation, CI only).
#
#   collect_browser_evidence.sh OUT_DIR
#
# Kept (synthetic CI identities only):
#   - web/test-results: failure screenshots (.png/.jpg), failure video (.webm),
#     error-context.md and other .md/.txt text — copied by ALLOWLIST;
#   - a bounded (EVIDENCE_LOG_SINCE / EVIDENCE_LOG_TAIL) slice of api/web/worker logs.
# Never collected: the Playwright HTML report (it embeds raw authenticated report
# data), traces, ZIPs, JSON, .env*, dumps, keys or any other file type.
#
# Every text artifact (error-context.md included) and every log is REDACTED
# (evidence_guard.py: credential shapes, typed-input arguments and the literal
# values of this job's credential-named environment variables) BEFORE the final
# fail-closed scan. Fails closed:
#   - redactor self-test fails, a log cannot be read/redacted, or a log is
#     still flagged                                      -> logs are omitted;
#   - redaction of a text artifact fails, the final scan flags anything
#     (credentials, disallowed/disguised/malformed files), the scanner errors,
#     or the evidence exceeds the size bound even without video
#                                                        -> NOTHING is uploaded.
# Writes ready=true|false to $GITHUB_OUTPUT. Never prints matched text.
set -euo pipefail

OUT="${1:?usage: collect_browser_evidence.sh OUT_DIR}"
HERE="$(cd "$(dirname "$0")" && pwd)"
guard() { python3 "${HERE}/evidence_guard.py" "$@"; }
read -r -a DC <<< "${COMPOSE:?COMPOSE must be set}"
LOG_SINCE="${EVIDENCE_LOG_SINCE:-20m}"
LOG_TAIL="${EVIDENCE_LOG_TAIL:-1500}"
MAX_MB="${EVIDENCE_MAX_MB:-200}"

ready() { echo "ready=$1" >> "${GITHUB_OUTPUT:-/dev/null}"; echo "browser evidence ready=$1"; }
nothing() { echo "$1: nothing uploaded"; rm -rf "$OUT"; ready false; exit 0; }

rm -rf "$OUT"
mkdir -p "$OUT"

# Browser artefacts by ALLOWLIST: screenshots, video, text. First match wins, so
# traces and env files are excluded even if they carry an allowed suffix.
if [ -d web/test-results ]; then
  rsync -a --prune-empty-dirs --no-links \
    --exclude='trace*' --exclude='*.trace' --exclude='.env*' \
    --include='*/' \
    --include='*.png' --include='*.jpg' --include='*.jpeg' --include='*.webm' \
    --include='*.md' --include='*.txt' \
    --exclude='*' \
    web/test-results/ "$OUT/test-results/"
fi

# Redact every text artifact (error-context.md included) before anything else.
if ! guard redact-tree "$OUT"; then
  nothing "text artifact redaction failed"
fi

# Bounded, redacted logs — only if the redactor proves itself first.
if guard self-test; then
  mkdir -p "$OUT/logs"
  RAW="$(mktemp)"
  trap 'rm -f "$RAW"' EXIT
  logs_ok=true
  for svc in api web worker; do
    if ! timeout 60 "${DC[@]}" logs --no-color --no-log-prefix \
      --since "$LOG_SINCE" --tail "$LOG_TAIL" "$svc" > "$RAW" 2>/dev/null; then
      echo "logs for $svc unavailable: skipped"
      continue
    fi
    if ! guard redact < "$RAW" > "$OUT/logs/$svc.log"; then
      logs_ok=false
    fi
  done
  rm -f "$RAW"
  if [ "$logs_ok" != true ]; then
    echo "log redaction failed: logs omitted"
    rm -rf "$OUT/logs"
  elif ! guard scan "$OUT/logs"; then
    echo "credential-like content survived redaction: logs omitted"
    rm -rf "$OUT/logs"
  fi
else
  echo "redactor self-test failed: logs omitted"
fi

# Size bound: drop video before anything else, then give up.
if [ "$(du -sm "$OUT" | cut -f1)" -gt "$MAX_MB" ]; then
  find "$OUT" -name '*.webm' -delete
fi
if [ "$(du -sm "$OUT" | cut -f1)" -gt "$MAX_MB" ]; then
  nothing "evidence exceeds ${MAX_MB} MB even without video"
fi

# Final fail-closed scan of EVERYTHING that would be uploaded (any non-zero exit,
# including a scanner error, means nothing is uploaded).
if ! guard scan "$OUT"; then
  nothing "browser evidence is not provably safe"
fi
if [ -z "$(find "$OUT" -type f -print -quit)" ]; then
  echo "no browser evidence was produced"
  ready false; exit 0
fi
ready true
