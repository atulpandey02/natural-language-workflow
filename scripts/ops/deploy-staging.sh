#!/usr/bin/env bash
# Mac-side Stage-2 deployment for the AWS EC2 staging host. Drives the host over
# SSH as nlwops (docker group => NO sudo needed). Source of truth:
# docker-compose.prod.yml + docker-compose.staging.yml (NEVER e2e),
# docker/caddy/Caddyfile, .env.prod.example, docs/staging/real-vps-checklist.md,
# docs/ops/vps-provisioning.md.
#
# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC-IP CAVEAT (read before every run):
#   The EC2 IPv4 (32.197.83.193) is auto-assigned. A plain REBOOT keeps it, but
#   a STOP + START may assign a DIFFERENT IPv4. If the public IP changes, the
#   hostname 32-197-83-193.sslip.io becomes invalid and BOTH Caddy's certificate
#   and the Supabase URL configuration must be updated. During this staging
#   validation window: DO NOT stop the EC2 instance.
# ─────────────────────────────────────────────────────────────────────────────
#
# Secrets model: DB passwords + the workspace cookie secret are generated ON the
# HOST with `openssl rand -hex 32` and written only into /opt/nlw/app/.env.prod
# (chmod 600, git-ignored, never printed). The Supabase PUBLISHABLE (anon) key is
# supplied interactively (or via SUPABASE_ANON_KEY_FILE) and transmitted over the
# SSH channel on STDIN only — never argv, never logged, never committed. This
# script handles NO sb_secret_*, service_role, GitHub PAT, or LLM keys.
set -euo pipefail

# --- Pinned deployment references (immutable) -------------------------------
DEPLOY_SHA="6a169e82e5e72a331e858ddde69c6d177bb3d991"
BACKEND_IMAGE="ghcr.io/atulpandey02/natural-language-workflow@sha256:ec0f33832f5a5de484c0cb795b08135f7548a14255154d3d5d8e18813d4e5792"
WEB_IMAGE="ghcr.io/atulpandey02/natural-language-workflow/web@sha256:ed477cad1a0e3a55a6a04d968d7ed807ff6307c14078e42215f257135ac742da"
STAGING_HOST="32-197-83-193.sslip.io"
SUPABASE_URL="https://uqjqdfshuwcjftdvxbrm.supabase.co"
SUPABASE_JWKS_URL="${SUPABASE_URL}/auth/v1/.well-known/jwks.json"
SUPABASE_ISSUER="${SUPABASE_URL}/auth/v1"
REPO_URL="https://github.com/atulpandey02/natural-language-workflow.git"

# --- Target (override via env) ---------------------------------------------
SSH_HOST="${SSH_HOST:-32.197.83.193}"
SSH_USER="${SSH_USER:-nlwops}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/nlw-staging-key.pem}"
TARGET="${SSH_USER}@${SSH_HOST}"
REMOTE_APP="/opt/nlw/app"
COMPOSE_FILES="-f docker-compose.prod.yml -f docker-compose.staging.yml"
DC="cd '$REMOTE_APP' && docker compose --env-file .env.prod $COMPOSE_FILES"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -i "$SSH_KEY")

log()  { printf '\033[1;34m[deploy]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[deploy]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[deploy] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
rsh()  { ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }

# On any failure past startup: bounded logs, NO volume destruction, NO migration
# rollback. Only wired active during the startup/verify phases (see main).
COLLECT_LOGS=0
fail_report() {
  [ "$COLLECT_LOGS" = "1" ] || return 0
  warn "Deployment failed — collecting bounded diagnostics (no volumes/migrations touched)."
  rsh "$DC ps" 2>/dev/null || true
  for svc in caddy web api worker scheduler postgres; do
    warn "---- last 60 log lines: $svc ----"
    rsh "$DC logs --tail=60 --no-color $svc" 2>/dev/null || true
  done
  warn "Volumes preserved; migrations NOT rolled back. Investigate, then re-run."
}
trap fail_report EXIT

# --- 1/2. Preflight ---------------------------------------------------------
log "Preflight: SSH connectivity …"
rsh 'true' || die "cannot SSH to $TARGET with $SSH_KEY."
log "Preflight: docker usable without sudo (nlwops in docker group) …"
rsh 'docker info >/dev/null 2>&1' \
  || die "docker not usable as nlwops. Open a FRESH SSH session (docker group applies on next login), or check the daemon."
log "Preflight: /opt/nlw/app present …"
rsh "test -d '$REMOTE_APP'" || die "$REMOTE_APP missing — run bootstrap-staging-host.sh first."
log "Preflight: free disk ≥ 10 GiB on / …"
free_kb="$(rsh "df -Pk / | awk 'NR==2{print \$4}'")"
[ "${free_kb:-0}" -ge 10000000 ] || die "insufficient free disk (${free_kb} kB)."
log "Preflight: nothing already bound to :80/:443 on the host …"
if rsh "ss -H -tln '( sport = :80 or sport = :443 )' | grep -q ."; then
  warn "Something already listens on :80/:443 — if that is a prior Caddy, this deploy will replace it on 'up'."
fi
log "Preflight: 80/443 AWS SG path reachable from here (Caddy not up yet → refused is OK) …"
for p in 80 443; do
  if nc -G 5 -z "$SSH_HOST" "$p" 2>/dev/null; then warn "port $p already answering (unexpected pre-deploy)"; fi
done

# --- IMDSv2 public-IP preflight (STOP on any mismatch) ----------------------
# The host's ACTUAL public IPv4 (from EC2 IMDSv2) must equal the pinned IP, and
# the sslip.io hostname must encode that same IP. Runs BEFORE any secret
# generation, pull, migration, or container startup — a mismatch means the
# Elastic IP/hostname assumption is wrong; STOP rather than deploy to the wrong
# identity.
EXPECTED_IP="32.197.83.193"
log "Preflight: IMDSv2 public-ipv4 must equal $EXPECTED_IP …"
host_pubip="$(rsh 'set -e
  T=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" --max-time 5)
  curl -sS -H "X-aws-ec2-metadata-token: $T" --max-time 5 http://169.254.169.254/latest/meta-data/public-ipv4' | tr -d '\r')"
[ "$host_pubip" = "$EXPECTED_IP" ] \
  || die "IMDSv2 public-ipv4 is '${host_pubip:-<none>}', expected $EXPECTED_IP — STOP (the Elastic IP may have changed; do not deploy)."
host_from_name="$(printf '%s' "$STAGING_HOST" | sed 's/\.sslip\.io$//; s/-/./g')"
[ "$host_from_name" = "$EXPECTED_IP" ] \
  || die "hostname $STAGING_HOST encodes '$host_from_name', not $EXPECTED_IP — STOP."
log "IMDSv2 public IP and hostname both resolve to $EXPECTED_IP."

# --- Manual preconditions that cannot be auto-verified ----------------------
cat >/dev/tty <<TXT
Manual preconditions (cannot be verified programmatically):
  1) Supabase → Authentication → URL Configuration:
        Site URL:     https://${STAGING_HOST}
        Redirect URL: https://${STAGING_HOST}/**
  2) On the VPS: 'docker login ghcr.io' with a read:packages token
     (verified below by pulling the pinned images).
TXT
if [ "${CONFIRM_MANUAL_PREREQS:-}" != "yes" ]; then
  printf 'Have you completed Supabase URL Configuration (#1)? [y/N]: ' >/dev/tty
  IFS= read -r _ans </dev/tty || true
  case "${_ans:-}" in y|Y|yes|YES) ;; *) die "aborted: complete the Supabase URL configuration first (or set CONFIRM_MANUAL_PREREQS=yes)." ;; esac
fi

# --- 3. Fetch deployment config at the EXACT pinned SHA (never `git pull`) ---
log "Fetching deployment config at ${DEPLOY_SHA:0:12} into $REMOTE_APP …"
rsh "set -e
  if [ ! -d '$REMOTE_APP/.git' ]; then
    git clone '$REPO_URL' '$REMOTE_APP'
  fi
  cd '$REMOTE_APP'
  git fetch origin
  test -z \"\$(git status --porcelain)\" || { echo 'STOP: working tree not clean before checkout' >&2; git status --porcelain >&2; exit 3; }
  git checkout --detach '$DEPLOY_SHA'
  test \"\$(git rev-parse HEAD)\" = '$DEPLOY_SHA' || { echo 'STOP: HEAD != pinned SHA' >&2; exit 3; }
  test -z \"\$(git status --porcelain)\" || { echo 'STOP: tree dirty after checkout' >&2; exit 3; }
" || die "failed to pin $REMOTE_APP to $DEPLOY_SHA."
log "Config pinned: $(rsh "git -C '$REMOTE_APP' rev-parse HEAD")"

# --- 5/6/7. Generate .env.prod ON-HOST (secrets never leave the host) -------
log "Preparing .env.prod (STOP if one already exists) …"
# Collect the Supabase PUBLISHABLE (anon) key locally — never printed/committed.
if [ -n "${SUPABASE_ANON_KEY_FILE:-}" ]; then
  [ -r "$SUPABASE_ANON_KEY_FILE" ] || die "SUPABASE_ANON_KEY_FILE not readable."
  SUPABASE_ANON_KEY="$(cat "$SUPABASE_ANON_KEY_FILE")"
else
  printf 'Enter the Supabase PUBLISHABLE (anon) key (hidden): ' >/dev/tty
  IFS= read -rs SUPABASE_ANON_KEY </dev/tty || true
  printf '\n' >/dev/tty
fi
[ -n "${SUPABASE_ANON_KEY:-}" ] || die "no Supabase publishable key provided."

# Remote env-builder: reads ONLY the anon key from stdin, generates the DB/cookie
# secrets on-host, writes .env.prod (chmod 600). Non-secret constants are baked
# in from the Mac; nothing here is echoed.
IFS= read -r -d '' MK_CONTENT <<EOF || true
#!/usr/bin/env bash
set -euo pipefail
umask 077                               # secrets files are 600 from creation
ENVF='$REMOTE_APP/.env.prod'
TMP="\$ENVF.tmp"
# Remove the temp file on ANY exit/interrupt so no partial secrets remain.
cleanup_tmp() { rm -f "\$TMP" 2>/dev/null || true; }
trap cleanup_tmp EXIT INT TERM
# Never overwrite an existing .env.prod — STOP for operator review.
if [ -e "\$ENVF" ]; then echo "STOP: \$ENVF already exists — review/rotate manually; not overwriting." >&2; exit 3; fi
IFS= read -r ANON || true
[ -n "\${ANON:-}" ] || { echo "STOP: no Supabase publishable key on stdin." >&2; exit 3; }
PGPW="\$(openssl rand -hex 32)"; APPPW="\$(openssl rand -hex 32)"
WORKERPW="\$(openssl rand -hex 32)"; SCHEDPW="\$(openssl rand -hex 32)"
COOKIE="\$(openssl rand -hex 32)"
# Validate every required value is non-empty BEFORE writing anything.
for pair in "SUPABASE_ANON_KEY=\$ANON" "POSTGRES_PASSWORD=\$PGPW" "NLW_APP_DB_PASSWORD=\$APPPW" \\
            "NLW_WORKER_DB_PASSWORD=\$WORKERPW" "NLW_SCHEDULER_DB_PASSWORD=\$SCHEDPW" \\
            "WORKSPACE_COOKIE_SECRET=\$COOKIE"; do
  case "\$pair" in *=) echo "STOP: required value \${pair%%=*} is empty." >&2; exit 3;; esac
done
# Build the FULL file in .env.prod.tmp; only a complete, validated file is
# atomically promoted to .env.prod.
{
  printf 'POSTGRES_PASSWORD=%s\n' "\$PGPW"
  printf 'NLW_APP_DB_PASSWORD=%s\n' "\$APPPW"
  printf 'NLW_WORKER_DB_PASSWORD=%s\n' "\$WORKERPW"
  printf 'NLW_SCHEDULER_DB_PASSWORD=%s\n' "\$SCHEDPW"
  printf 'DATABASE_URL=postgresql+psycopg://nlw_app:%s@postgres:5432/nlw\n' "\$APPPW"
  printf 'WORKER_DATABASE_URL=postgresql+psycopg://nlw_worker:%s@postgres:5432/nlw\n' "\$WORKERPW"
  printf 'SCHEDULER_DATABASE_URL=postgresql+psycopg://nlw_scheduler:%s@postgres:5432/nlw\n' "\$SCHEDPW"
  printf 'DATABASE_MIGRATION_URL=postgresql+psycopg://nlw:%s@postgres:5432/nlw\n' "\$PGPW"
  printf 'REDIS_URL=redis://redis:6379/0\n'
  printf 'NLW_IMAGE=%s\n' '$BACKEND_IMAGE'
  printf 'NLW_WEB_IMAGE=%s\n' '$WEB_IMAGE'
  printf 'PUBLIC_HOSTNAME=%s\n' '$STAGING_HOST'
  printf 'WORKSPACE_COOKIE_SECRET=%s\n' "\$COOKIE"
  printf 'SUPABASE_URL=%s\n' '$SUPABASE_URL'
  printf 'SUPABASE_ANON_KEY=%s\n' "\$ANON"
  printf 'SUPABASE_JWKS_URL=%s\n' '$SUPABASE_JWKS_URL'
  printf 'SUPABASE_JWT_ISSUER=%s\n' '$SUPABASE_ISSUER'
} > "\$TMP"
# Re-check no required line ended up empty in the file (defense in depth).
for k in POSTGRES_PASSWORD NLW_APP_DB_PASSWORD NLW_WORKER_DB_PASSWORD NLW_SCHEDULER_DB_PASSWORD \\
         DATABASE_URL WORKER_DATABASE_URL SCHEDULER_DATABASE_URL DATABASE_MIGRATION_URL \\
         WORKSPACE_COOKIE_SECRET SUPABASE_URL SUPABASE_ANON_KEY SUPABASE_JWKS_URL SUPABASE_JWT_ISSUER \\
         NLW_IMAGE NLW_WEB_IMAGE PUBLIC_HOSTNAME; do
  grep -qE "^\$k=.+" "\$TMP" || { echo "STOP: \$k missing/empty in generated file." >&2; exit 3; }
done
# Atomic promotion only after a fully valid file exists.
mv "\$TMP" "\$ENVF"
chmod 600 "\$ENVF"
trap - EXIT INT TERM
echo "wrote \$ENVF (chmod 600) via atomic .env.prod.tmp -> .env.prod"
EOF
REMOTE_MK="$(rsh 'mktemp /tmp/nlw-mkenv.XXXXXX.sh')" || die "could not create remote env-builder temp."
printf '%s\n' "$MK_CONTENT" | rsh "cat > '$REMOTE_MK' && chmod 700 '$REMOTE_MK'" || die "could not upload env-builder."
# Feed ONLY the anon key on stdin (never argv/log); then remove the builder.
if ! printf '%s' "$SUPABASE_ANON_KEY" | rsh "bash '$REMOTE_MK'"; then
  rsh "rm -f '$REMOTE_MK'" || true
  die ".env.prod generation stopped (see message above; an existing .env.prod requires manual review)."
fi
rsh "rm -f '$REMOTE_MK'" || true
unset SUPABASE_ANON_KEY

# --- 10. Render compose (abort on failure) ----------------------------------
log "Rendering compose config …"
rsh "$DC config >/dev/null" || die "compose config render failed — check .env.prod and the compose files."

# --- 9/11. Pull the EXACT immutable images (also verifies GHCR auth) --------
log "Pulling pinned images (verifies GHCR authentication) …"
rsh "$DC pull" || die "image pull failed. On the VPS run 'docker login ghcr.io' with a read:packages token, then retry."

COLLECT_LOGS=1   # from here on, failures collect bounded logs (no destructive ops)

# --- 12. Fresh DB: datastores → healthy → bootstrap check → migrate ---------
log "Starting datastores (postgres, redis) …"
rsh "$DC up -d postgres redis"
log "Waiting for postgres health …"
rsh "cd '$REMOTE_APP' && for i in \$(seq 1 60); do docker compose --env-file .env.prod $COMPOSE_FILES exec -T postgres pg_isready -U nlw -d nlw >/dev/null 2>&1 && exit 0; sleep 2; done; exit 1" \
  || die "postgres did not become ready."
log "Verifying fresh role bootstrap (00-roles.sh created the runtime roles) …"
roles="$(rsh "$DC exec -T postgres psql -U nlw -d nlw -tAc \"SELECT string_agg(rolname, ',' ORDER BY rolname) FROM pg_roles WHERE rolname LIKE 'nlw\\_%'\"" | tr -d '\r')"
for r in nlw_app nlw_worker nlw_scheduler nlw_rls_bypass nlw_workspace_bootstrap; do
  case ",$roles," in *",$r,"*) ;; *) die "expected role '$r' not found (roles: $roles). Is this a FRESH volume? Not destroying anything." ;; esac
done
log "Roles present: $roles"
log "Applying Alembic migrations to head (owner connection) …"
rsh "$DC run --rm api alembic upgrade head" || die "alembic upgrade failed (volumes preserved; no rollback)."

# --- 13. Verify migration head before app startup ---------------------------
log "Verifying Alembic current == head …"
cur="$(rsh "$DC run --rm api alembic current 2>/dev/null" | grep -oE '[0-9a-f]{12,}' | head -1 || true)"
head="$(rsh "$DC run --rm api alembic heads 2>/dev/null" | grep -oE '[0-9a-f]{12,}' | head -1 || true)"
[ -n "$cur" ] && [ "$cur" = "$head" ] || die "Alembic head check failed (current='$cur' head='$head')."
log "Schema at head: $cur"

# --- 14. Start application services explicitly (NO e2e overlay) -------------
log "Starting api, worker, scheduler, web, prometheus, caddy …"
rsh "$DC up -d api worker scheduler web prometheus caddy"

# --- 16. Host-local readiness (staging loopback seam) -----------------------
log "Waiting for host-local API readiness (127.0.0.1:8000/health/ready) …"
rsh "for i in \$(seq 1 60); do curl -fsS http://127.0.0.1:8000/health/ready >/dev/null 2>&1 && exit 0; sleep 2; done; exit 1" \
  || die "API /health/ready did not become healthy."
log "Readiness OK: $(rsh 'curl -fsS http://127.0.0.1:8000/health/ready' | tr -d '\r')"

# --- 17. Public /login over validated TLS (from the Mac; cert NOT bypassed) --
log "Waiting for public https://${STAGING_HOST}/login (Caddy ACME may take ~30–60s) …"
ok=0
for i in $(seq 1 40); do
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "https://${STAGING_HOST}/login" 2>/dev/null || true)"
  if [ "$code" = "200" ]; then ok=1; break; fi
  sleep 5
done
[ "$ok" = "1" ] || die "public https://${STAGING_HOST}/login not serving 200 with a valid certificate yet. TLS/cert may still be issuing; diagnostics collected."

COLLECT_LOGS=0
trap - EXIT
log "STAGE-2 DEPLOY COMPLETE."
log "  config SHA:   $DEPLOY_SHA"
log "  backend:      $BACKEND_IMAGE"
log "  web:          $WEB_IMAGE"
log "  public:       https://${STAGING_HOST}/login (200, TLS-validated)"
log "Next: scripts/ops/verify-staging-deployment.sh for the full read-only report."
log "REMINDER: do NOT stop the EC2 instance (a STOP+START may change the public IP)."
