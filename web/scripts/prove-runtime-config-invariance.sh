#!/usr/bin/env bash
# Artifact-invariance proof (PR1 primary acceptance criterion).
#
# Build the web image ONCE, then prove the SAME image:
#   - renders env-specific public config + CSP purely from RUNTIME env (config A),
#   - renders DIFFERENT config + CSP for a different runtime env (config B),
#   - is byte-identical across both runs (same image id),
#   - bakes NEITHER environment's sentinel Supabase URL/key into the image.
#
# Proves:  one web artifact + staging runtime config  -> staging Supabase
#          the SAME artifact + production runtime config -> production Supabase
set -euo pipefail

WEB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${WEB_IMAGE:-nlw-web-invariance:local}"
BUILD="${BUILD_IMAGE:-1}"  # set BUILD_IMAGE=0 to reuse an already-built $IMAGE

A_URL="https://staging-sentinel-aaaa.supabase.co"
A_KEY="anonkey-sentinel-AAAA"
B_URL="https://prod-sentinel-bbbb.supabase.co"
B_KEY="anonkey-sentinel-BBBB"

cid=""
cleanup() { [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1 || true; }
trap cleanup EXIT

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

if [ "$BUILD" = "1" ]; then
  echo "== build web image ONCE =="
  docker build -t "$IMAGE" "$WEB_DIR"
fi
IMAGE_ID="$(docker image inspect -f '{{.Id}}' "$IMAGE")"
echo "image id: $IMAGE_ID"

# Render /login from the running image with the given runtime config; write the
# response headers and body to $3.headers / $3.body.
render() { # url key out
  local url="$1" key="$2" out="$3" hostport
  cid="$(docker run -d -p 127.0.0.1:0:3000 \
    -e SUPABASE_URL="$url" -e SUPABASE_ANON_KEY="$key" \
    -e WORKSPACE_COOKIE_SECRET=invariance-proof-cookie-secret-32bytes \
    -e NLW_API_URL=http://127.0.0.1:8000 \
    "$IMAGE")"
  hostport="$(docker port "$cid" 3000/tcp | head -1 | sed 's/.*://')"
  local ok=0 i
  for i in $(seq 1 60); do
    if curl -fsS -o /dev/null "http://127.0.0.1:${hostport}/login"; then ok=1; break; fi
    sleep 1
  done
  [ "$ok" = "1" ] || { docker logs "$cid" >&2 || true; fail "web server did not become ready"; }
  curl -s -D "${out}.headers" -o "${out}.body" "http://127.0.0.1:${hostport}/login"
  docker rm -f "$cid" >/dev/null; cid=""
}

assert_env() { # label url key headers body other_url
  local label="$1" url="$2" key="$3" headers="$4" body="$5" other="$6"
  grep -qF "__NLW_PUBLIC_CONFIG__" "$body" || fail "$label: config data block missing"
  grep -qF "application/json" "$body" || fail "$label: config block is not application/json"
  grep -qF "$url" "$body" || fail "$label: rendered config missing runtime URL"
  grep -qF "$key" "$body" || fail "$label: rendered config missing runtime anon key"
  grep -qiF "content-security-policy: " "$headers" || fail "$label: no CSP header"
  grep -i "content-security-policy" "$headers" | grep -qF "connect-src 'self' ${url}" \
    || fail "$label: CSP connect-src does not use the runtime Supabase origin"
  grep -qF "$other" "$body" && fail "$label: the OTHER environment's URL leaked into render"
  pass "$label: runtime config + CSP derive from runtime env ($url)"
}

tmp="$(mktemp -d)"; trap 'cleanup; rm -rf "$tmp"' EXIT

echo "== render with runtime config A =="
render "$A_URL" "$A_KEY" "$tmp/a"
assert_env "config A" "$A_URL" "$A_KEY" "$tmp/a.headers" "$tmp/a.body" "$B_URL"

echo "== render with runtime config B (SAME image) =="
render "$B_URL" "$B_KEY" "$tmp/b"
assert_env "config B" "$B_URL" "$B_KEY" "$tmp/b.headers" "$tmp/b.body" "$A_URL"

echo "== prove image identity unchanged across both runs =="
IMAGE_ID_AFTER="$(docker image inspect -f '{{.Id}}' "$IMAGE")"
[ "$IMAGE_ID" = "$IMAGE_ID_AFTER" ] || fail "image id changed between runs"
pass "same immutable image served both environments ($IMAGE_ID_AFTER)"

echo "== prove no environment sentinel is baked into the image =="
if docker run --rm --entrypoint sh "$IMAGE" -c \
    "grep -R -F -e '$A_URL' -e '$B_URL' -e '$A_KEY' -e '$B_KEY' /app 2>/dev/null"; then
  fail "an environment-specific sentinel is embedded in the image/static bundle"
fi
pass "no environment-specific Supabase URL/key is embedded in the image"

echo "ARTIFACT-INVARIANCE PROOF COMPLETE"
