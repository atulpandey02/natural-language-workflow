#!/usr/bin/env bash
# Mac-side READ-ONLY verification of the deployed staging stack. Changes NOTHING.
# Runs host-side checks over SSH as nlwops (docker group => no sudo) and does the
# public TLS/JWKS checks from this Mac. Exits non-zero if any check FLAGs.
#
# PUBLIC-IP CAVEAT: the EC2 IPv4 is auto-assigned; a STOP+START may change it,
# invalidating 32-197-83-193.sslip.io (Caddy cert + Supabase URL config). Do not
# stop the instance during the validation window.
set -euo pipefail

DEPLOY_SHA="5151a2cc54cfb63b276bd3b30cf0e683263525ac"
BACKEND_IMAGE="ghcr.io/atulpandey02/natural-language-workflow@sha256:fef5464b674695050ad4b1ca2e80ca7f03bfdd3b03a6519352e52c8377d7728e"
WEB_IMAGE="ghcr.io/atulpandey02/natural-language-workflow/web@sha256:57276f04e27e350a8eb8044349346af0f426274e9d27750bec904c203a007228"
STAGING_HOST="32-197-83-193.sslip.io"
SUPABASE_JWKS_URL="https://uqjqdfshuwcjftdvxbrm.supabase.co/auth/v1/.well-known/jwks.json"

SSH_HOST="${SSH_HOST:-32.197.83.193}"
SSH_USER="${SSH_USER:-nlwops}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/nlw-staging-key.pem}"
TARGET="${SSH_USER}@${SSH_HOST}"
REMOTE_APP="/opt/nlw/app"
COMPOSE_FILES="-f docker-compose.prod.yml -f docker-compose.staging.yml"
DC="cd '$REMOTE_APP' && docker compose --env-file .env.prod $COMPOSE_FILES"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -i "$SSH_KEY")

FLAGS=0
ok()   { printf '  \033[1;32m[ OK ]\033[0m %s\n' "$*"; }
flag() { printf '  \033[1;31m[FLAG]\033[0m %s\n' "$*"; FLAGS=$((FLAGS+1)); }
info() { printf '  \033[1;34m[info]\033[0m %s\n' "$*"; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
rsh() { ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }

# Expected role model — name:<canlogin><super><bypassrls> as t/f. Pure + testable.
EXPECTED_ROLES=(
  "nlw_app:tff"
  "nlw_worker:tff"
  "nlw_scheduler:tff"
  "nlw_rls_bypass:fft"
  "nlw_workspace_bootstrap:fft"
)
# True iff the normalized roles block contains a line EXACTLY equal to $1.
assert_role() { printf '%s\n' "$2" | grep -qx "$1"; }

# When sourced (e.g. by tests), define helpers only — do NOT run the live checks.
if [ "${BASH_SOURCE[0]}" != "${0}" ]; then return 0 2>/dev/null || true; fi

rsh 'true' || { echo "cannot SSH to $TARGET"; exit 2; }
rsh 'docker info >/dev/null 2>&1' || { echo "docker not usable as nlwops (fresh login needed?)"; exit 2; }

section "Deployment identity"
sha="$(rsh "git -C '$REMOTE_APP' rev-parse HEAD 2>/dev/null" | tr -d '\r')"
info "config Git SHA: ${sha:-<none>}"
[ "$sha" = "$DEPLOY_SHA" ] && ok "pinned deployment SHA matches" || flag "config SHA != pinned ($DEPLOY_SHA)"
dirty="$(rsh "git -C '$REMOTE_APP' status --porcelain 2>/dev/null" | tr -d '\r')"
[ -z "$dirty" ] && ok "config tree clean" || flag "config tree has local modifications"
envimg="$(rsh "grep -E '^NLW_IMAGE=|^NLW_WEB_IMAGE=' '$REMOTE_APP/.env.prod' 2>/dev/null" | tr -d '\r')"
grep -q "^NLW_IMAGE=$BACKEND_IMAGE$"   <<<"$envimg" && ok "backend digest pinned" || flag "backend NLW_IMAGE != pinned digest"
grep -q "^NLW_WEB_IMAGE=$WEB_IMAGE$"    <<<"$envimg" && ok "web digest pinned"     || flag "web NLW_WEB_IMAGE != pinned digest"

section "Compose services / status / health"
ps="$(rsh "$DC ps 2>/dev/null" | tr -d '\r')"
printf '%s\n' "$ps" | sed 's/^/    /'
for svc in postgres redis api worker scheduler web prometheus caddy; do
  line="$(grep -E "(^|[ /-])$svc( |\$)" <<<"$ps" | head -1)"
  if [ -z "$line" ]; then flag "$svc not present"; continue; fi
  case "$line" in
    *nhealthy*|*Exit*|*exited*|*Restarting*) flag "$svc unhealthy/exited" ;;
    *healthy*|*running*|*Up*)                ok "$svc up" ;;
    *)                                        info "$svc: $line" ;;
  esac
done

section "Published port bindings (exposure)"
ports="$(rsh "$DC ps --format '{{.Service}}\t{{.Ports}}' 2>/dev/null" | tr -d '\r')"
printf '%s\n' "$ports" | sed 's/^/    /'
# Only caddy may bind 0.0.0.0:80/443; api must be 127.0.0.1:8000 only; web/pg/
# redis/metrics must not publish to a public address.
if grep -E '(0\.0\.0\.0|\[::\]):(3000|5432|6379|9090|9100)' <<<"$ports" >/dev/null; then
  flag "a web/db/metrics port is published on a public address"
else
  ok "no public web/db/metrics binding (3000/5432/6379/9090/9100)"
fi
apiports="$(grep -E '(^|[[:space:]])api([[:space:]]|$)' <<<"$ports" || true)"
if grep -Eq '0\.0\.0\.0:8000|\[::\]:8000' <<<"$apiports"; then flag "API published on a public address"; \
  elif grep -q '127.0.0.1:8000' <<<"$apiports"; then ok "API bound 127.0.0.1:8000 only"; \
  else info "API ports: ${apiports:-<none published>}"; fi
caddyports="$(grep -E '(^|[[:space:]])caddy([[:space:]]|$)' <<<"$ports" || true)"
grep -Eq ':80(->| )|:443' <<<"$caddyports" && ok "caddy publishes 80/443" || flag "caddy 80/443 not published"

section "Host-local API readiness"
rd="$(rsh 'curl -fsS --max-time 10 http://127.0.0.1:8000/health/ready 2>/dev/null' | tr -d '\r' || true)"
info "${rd:-<no response>}"
grep -q '"status":"ready"' <<<"$rd" && ok "host-local /health/ready is ready" || flag "host-local readiness not ready"

section "Database roles + schema"
# Deterministic t/f normalization: boolean||text yields 'true'/'false', NOT
# 't'/'f', so CASE expressions render each flag explicitly as t/f.
roles="$(rsh "$DC exec -T postgres psql -U nlw -d nlw -tAc \"SELECT rolname||':'||CASE WHEN rolcanlogin THEN 't' ELSE 'f' END||CASE WHEN rolsuper THEN 't' ELSE 'f' END||CASE WHEN rolbypassrls THEN 't' ELSE 'f' END FROM pg_roles WHERE rolname LIKE 'nlw\\_%' ORDER BY rolname\"" 2>/dev/null | tr -d '\r')"
printf '%s\n' "$roles" | sed 's/^/    /'
for r in "${EXPECTED_ROLES[@]}"; do
  if assert_role "$r" "$roles"; then ok "role ${r%%:*} attributes correct (${r#*:})"; else flag "role ${r%%:*} missing/attrs wrong (want ${r#*:} = canlogin/super/bypassrls)"; fi
done
# Deterministic (NOT a hex-only grep): head derived in-image via Alembic
# ScriptDirectory; current read as a scalar. Works with named revisions like
# 0010_readiness_schema_grant. Empty values are failures.
alv="$(rsh "$DC exec -T postgres psql -U nlw -d nlw -tAc 'SELECT version_num FROM alembic_version'" 2>/dev/null | tr -d '[:space:]')"
alhead="$(rsh "$DC run --rm -T api python -c 'from alembic.config import Config; from alembic.script import ScriptDirectory; h=ScriptDirectory.from_config(Config(\"alembic.ini\")).get_current_head(); assert h; print(\"HEAD=%s\" % h)' 2>/dev/null" | sed -n 's/^HEAD=//p' | head -1 | tr -d '[:space:]')"
info "alembic_version='$alv' ; head='$alhead'"
if [ -n "$alv" ] && [ -n "$alhead" ] && [ "$alv" = "$alhead" ]; then ok "schema at head ($alv)"; else flag "schema not at head (current='$alv' head='$alhead')"; fi

section "Public edge (from this Mac; TLS validated)"
code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "https://${STAGING_HOST}/login" 2>/dev/null || true)"
verify="$(curl -sS -o /dev/null -w '%{ssl_verify_result}' --max-time 20 "https://${STAGING_HOST}/login" 2>/dev/null || echo 99)"
info "GET https://${STAGING_HOST}/login -> HTTP $code ; ssl_verify_result=$verify"
[ "$code" = "200" ] && ok "public /login serves 200" || flag "public /login not 200"
[ "$verify" = "0" ] && ok "TLS certificate validates (no bypass)" || flag "TLS certificate did not validate"
if command -v openssl >/dev/null 2>&1; then
  dates="$(echo | openssl s_client -servername "$STAGING_HOST" -connect "${STAGING_HOST}:443" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null | tr '\n' ' ')"
  [ -n "$dates" ] && info "cert validity: $dates"
fi

section "Supabase JWKS reachability"
jcode="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$SUPABASE_JWKS_URL" 2>/dev/null || true)"
[ "$jcode" = "200" ] && ok "Supabase JWKS reachable (200)" || flag "Supabase JWKS not reachable ($jcode)"

section "Caddy log summary (no secrets)"
rsh "$DC logs --tail=20 --no-color caddy 2>/dev/null" | tr -d '\r' \
  | grep -iE 'certificate|obtain|renew|error|tls|serving|ready' | tail -12 | sed 's/^/    /' || true

section "Result"
if [ "$FLAGS" -eq 0 ]; then
  printf '\033[1;32mALL CHECKS PASSED\033[0m — staging deployment looks healthy.\n'; exit 0
else
  printf '\033[1;31m%d CHECK(S) FLAGGED\033[0m — review the [FLAG] lines above.\n' "$FLAGS"; exit 1
fi
