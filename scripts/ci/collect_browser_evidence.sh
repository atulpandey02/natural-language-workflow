#!/usr/bin/env bash
# Collect SAFE Playwright failure evidence for upload (staging-validation, CI only).
#
#   collect_browser_evidence.sh OUT_DIR
#
# Copies web/test-results (screenshots, video, error-context.md) and
# web/playwright-report, never trace archives; adds a bounded, REDACTED slice of
# api/web/worker logs. Then it scans everything with evidence_guard.py and fails
# closed:
#   - redactor canary self-test fails      -> logs are omitted;
#   - anything credential-like in the logs -> logs are omitted;
#   - anything credential-like elsewhere   -> NOTHING is uploaded.
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

rm -rf "$OUT"
mkdir -p "$OUT"

# Browser artefacts only: no trace archives or trace viewer data, ever.
copy_tree() {
  local src="$1" dst="$2"
  [ -d "$src" ] || return 0
  rsync -a --prune-empty-dirs \
    --exclude='*.zip' --exclude='trace*' --exclude='*.trace' --exclude='.env*' \
    "$src/" "$dst/"
}
copy_tree web/test-results "$OUT/test-results"
copy_tree web/playwright-report "$OUT/playwright-report"

# Bounded, redacted logs — only if the redactor proves itself first.
if guard self-test; then
  mkdir -p "$OUT/logs"
  for svc in api web worker; do
    timeout 60 "${DC[@]}" logs --no-color --no-log-prefix \
      --since "$LOG_SINCE" --tail "$LOG_TAIL" "$svc" 2>/dev/null \
      | guard redact > "$OUT/logs/$svc.log" || true
  done
  if ! guard scan "$OUT/logs"; then
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
  echo "evidence exceeds ${MAX_MB} MB even without video: not uploaded"
  rm -rf "$OUT"; ready false; exit 0
fi

# Final fail-closed scan of EVERYTHING that would be uploaded.
if ! guard scan "$OUT"; then
  echo "credential-like content in browser evidence: nothing uploaded"
  rm -rf "$OUT"; ready false; exit 0
fi
if [ -z "$(find "$OUT" -type f -print -quit)" ]; then
  echo "no browser evidence was produced"
  ready false; exit 0
fi
ready true
