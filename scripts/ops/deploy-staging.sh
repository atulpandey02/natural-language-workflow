#!/usr/bin/env bash
# Mac-side Stage-2 deployment for the AWS EC2 staging host. Drives the host over
# SSH as nlwops (docker group => NO sudo needed). Source of truth:
# docker-compose.prod.yml + docker-compose.staging.yml (NEVER e2e),
# docker/caddy/Caddyfile, .env.prod.example, docs/staging/real-vps-checklist.md,
# docs/ops/vps-provisioning.md.
#
# Modes:
#   ./deploy-staging.sh            first deployment (creates .env.prod once)
#   ./deploy-staging.sh --resume   continue an existing partial deployment;
#                                   NEVER regenerates secrets or touches state.
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
DEPLOY_SHA="5151a2cc54cfb63b276bd3b30cf0e683263525ac"
BACKEND_IMAGE="ghcr.io/atulpandey02/natural-language-workflow@sha256:fef5464b674695050ad4b1ca2e80ca7f03bfdd3b03a6519352e52c8377d7728e"
WEB_IMAGE="ghcr.io/atulpandey02/natural-language-workflow/web@sha256:57276f04e27e350a8eb8044349346af0f426274e9d27750bec904c203a007228"
STAGING_HOST="32-197-83-193.sslip.io"
EXPECTED_IP="32.197.83.193"
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

# ── Pure, testable helpers (no I/O; safe to source) ─────────────────────────
# Extract the head printed by the in-image derivation ('HEAD=<rev>' on stdin).
parse_head_line() { sed -n 's/^HEAD=//p' | head -1 | tr -d '[:space:]'; }
# Normalize a psql -tA scalar (strip all whitespace / CR).
parse_current()   { tr -d '[:space:]'; }
# Assert both revisions are non-empty AND equal. Empty => hard failure.
assert_revisions() {
  local expected="$1" current="$2"
  [ -n "$expected" ] || { echo "assert_revisions: expected head is EMPTY" >&2; return 1; }
  [ -n "$current" ]  || { echo "assert_revisions: current revision is EMPTY" >&2; return 1; }
  [ "$expected" = "$current" ] \
    || { echo "assert_revisions: MISMATCH current='$current' head='$expected'" >&2; return 1; }
  return 0
}
# Supabase PUBLISHABLE key must be non-empty, start with sb_publishable_, and
# have at least one char after the prefix. (Never prints the key.)
valid_supabase_anon_key() {
  case "${1:-}" in sb_publishable_?*) return 0 ;; *) return 1 ;; esac
}
# The LLM key is required ONLY when the provider is anthropic. (Never prints it.)
require_llm_key_ok() {
  local provider="${1:-}" key="${2:-}"
  [ "$provider" = "anthropic" ] || return 0
  [ -n "$key" ]
}

# ── Phase tracking + accurate failure report ────────────────────────────────
PHASE="init"
PHASES_DONE=""
SUCCESS=0
mark() { PHASE="$1"; PHASES_DONE="${PHASES_DONE}${1} "; log "[phase] $1"; }
phase_done() { case " $PHASES_DONE " in *" $1 "*) return 0;; *) return 1;; esac; }

fail_report() {
  [ "$SUCCESS" = "1" ] && return 0
  warn "──────────────────────────────────────────────────────────────"
  warn "Deployment STOPPED at phase: ${PHASE}"
  warn "Phases completed:${PHASES_DONE:+ ${PHASES_DONE}}"
  # State-accurate statements — never claim something was untouched after it ran.
  phase_done env_created  && warn "NOTE: .env.prod was CREATED this run (secrets generated)."
  phase_done migrations_applied && warn "NOTE: 'alembic upgrade head' WAS executed (idempotent; NOT rolled back)."
  warn "PRESERVED: .env.prod, pgdata volume, DB roles, Redis state."
  warn "No volumes destroyed, no Postgres recreated, no migrations downgraded."
  if phase_done postgres_started; then
    rsh "$DC ps" 2>/dev/null || true
    for svc in caddy web api worker scheduler postgres; do
      warn "---- last 60 log lines: $svc ----"
      rsh "$DC logs --tail=60 --no-color $svc" 2>/dev/null || true
    done
  fi
  warn "Fix the cause, then re-run with --resume (state is intact)."
}

# ── Deployment steps ────────────────────────────────────────────────────────
preflight() {
  log "Preflight: SSH connectivity …"
  rsh 'true' || die "cannot SSH to $TARGET with $SSH_KEY."
  log "Preflight: docker usable without sudo (nlwops in docker group) …"
  rsh 'docker info >/dev/null 2>&1' \
    || die "docker not usable as nlwops. Open a FRESH SSH session (docker group applies on next login), or check the daemon."
  log "Preflight: /opt/nlw/app present …"
  rsh "test -d '$REMOTE_APP'" || die "$REMOTE_APP missing — run bootstrap-staging-host.sh first."
  log "Preflight: free disk ≥ 10 GiB on / …"
  local free_kb
  free_kb="$(rsh "df -Pk / | awk 'NR==2{print \$4}'")"
  [ "${free_kb:-0}" -ge 10000000 ] || die "insufficient free disk (${free_kb} kB)."
}

imdsv2_check() {
  # The host's ACTUAL public IPv4 (EC2 IMDSv2) must equal the pinned IP, and the
  # sslip.io hostname must encode that same IP. Runs BEFORE any secret gen, pull,
  # migration, or startup. Mismatch => STOP (wrong identity).
  log "Preflight: IMDSv2 public-ipv4 must equal $EXPECTED_IP …"
  local host_pubip host_from_name
  host_pubip="$(rsh 'set -e
    T=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" --max-time 5)
    curl -sS -H "X-aws-ec2-metadata-token: $T" --max-time 5 http://169.254.169.254/latest/meta-data/public-ipv4' | tr -d '\r')"
  [ "$host_pubip" = "$EXPECTED_IP" ] \
    || die "IMDSv2 public-ipv4 is '${host_pubip:-<none>}', expected $EXPECTED_IP — STOP (Elastic IP may have changed; do not deploy)."
  host_from_name="$(printf '%s' "$STAGING_HOST" | sed 's/\.sslip\.io$//; s/-/./g')"
  [ "$host_from_name" = "$EXPECTED_IP" ] \
    || die "hostname $STAGING_HOST encodes '$host_from_name', not $EXPECTED_IP — STOP."
  log "IMDSv2 public IP and hostname both resolve to $EXPECTED_IP."
}

confirm_manual_prereqs() {
  cat >/dev/tty <<TXT
Manual preconditions (cannot be verified programmatically):
  1) Supabase → Authentication → URL Configuration:
        Site URL:     https://${STAGING_HOST}
        Redirect URL: https://${STAGING_HOST}/**
  2) On the VPS: 'docker login ghcr.io' with a read:packages token
     (verified below by pulling the pinned images).
TXT
  [ "${CONFIRM_MANUAL_PREREQS:-}" = "yes" ] && return 0
  printf 'Have you completed Supabase URL Configuration (#1)? [y/N]: ' >/dev/tty
  local a; IFS= read -r a </dev/tty || true
  case "${a:-}" in y|Y|yes|YES) ;; *) die "aborted: complete the Supabase URL configuration first (or set CONFIRM_MANUAL_PREREQS=yes)." ;; esac
}

pin_config() {
  log "Pinning deployment config to ${DEPLOY_SHA:0:12} in $REMOTE_APP …"
  rsh "set -e
    if [ ! -d '$REMOTE_APP/.git' ]; then git clone '$REPO_URL' '$REMOTE_APP'; fi
    cd '$REMOTE_APP'
    git fetch origin
    test -z \"\$(git status --porcelain)\" || { echo 'STOP: working tree not clean before checkout' >&2; git status --porcelain >&2; exit 3; }
    git checkout --detach '$DEPLOY_SHA'
    test \"\$(git rev-parse HEAD)\" = '$DEPLOY_SHA' || { echo 'STOP: HEAD != pinned SHA' >&2; exit 3; }
  " || die "failed to pin $REMOTE_APP to $DEPLOY_SHA."
  local sha; sha="$(rsh "git -C '$REMOTE_APP' rev-parse HEAD" | tr -d '\r')"
  [ "$sha" = "$DEPLOY_SHA" ] || die "config SHA '$sha' != pinned $DEPLOY_SHA."
  mark config_pinned
}

create_env_first() {
  # FIRST-DEPLOY only. STOP if .env.prod exists; generate secrets ONCE; atomic
  # create. See atomic .env.prod.tmp -> .env.prod inside the remote builder.
  log "Preparing .env.prod (first deploy; STOP if one already exists) …"
  if rsh "test -e '$REMOTE_APP/.env.prod'"; then
    die "first-deploy: $REMOTE_APP/.env.prod already exists. Use --resume (never overwrite secrets)."
  fi
  local anon
  if [ -n "${SUPABASE_ANON_KEY_FILE:-}" ]; then
    [ -r "$SUPABASE_ANON_KEY_FILE" ] || die "SUPABASE_ANON_KEY_FILE not readable."
    anon="$(cat "$SUPABASE_ANON_KEY_FILE")"
  else
    printf 'Enter the Supabase PUBLISHABLE (anon) key (hidden): ' >/dev/tty
    IFS= read -rs anon </dev/tty || true
    printf '\n' >/dev/tty
  fi
  [ -n "${anon:-}" ] || die "no Supabase publishable key provided."
  valid_supabase_anon_key "$anon" \
    || die "SUPABASE_ANON_KEY is invalid — must start with 'sb_publishable_' and include a suffix. (Key not printed.)"

  local mk
  IFS= read -r -d '' mk <<EOF || true
#!/usr/bin/env bash
set -euo pipefail
umask 077
ENVF='$REMOTE_APP/.env.prod'
TMP="\$ENVF.tmp"
cleanup_tmp() { rm -f "\$TMP" 2>/dev/null || true; }
trap cleanup_tmp EXIT INT TERM
if [ -e "\$ENVF" ]; then echo "STOP: \$ENVF already exists — not overwriting." >&2; exit 3; fi
IFS= read -r ANON || true
[ -n "\${ANON:-}" ] || { echo "STOP: no Supabase publishable key on stdin." >&2; exit 3; }
PGPW="\$(openssl rand -hex 32)"; APPPW="\$(openssl rand -hex 32)"
WORKERPW="\$(openssl rand -hex 32)"; SCHEDPW="\$(openssl rand -hex 32)"
COOKIE="\$(openssl rand -hex 32)"
for pair in "SUPABASE_ANON_KEY=\$ANON" "POSTGRES_PASSWORD=\$PGPW" "NLW_APP_DB_PASSWORD=\$APPPW" \\
            "NLW_WORKER_DB_PASSWORD=\$WORKERPW" "NLW_SCHEDULER_DB_PASSWORD=\$SCHEDPW" \\
            "WORKSPACE_COOKIE_SECRET=\$COOKIE"; do
  case "\$pair" in *=) echo "STOP: required value \${pair%%=*} is empty." >&2; exit 3;; esac
done
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
for k in POSTGRES_PASSWORD NLW_APP_DB_PASSWORD NLW_WORKER_DB_PASSWORD NLW_SCHEDULER_DB_PASSWORD \\
         DATABASE_URL WORKER_DATABASE_URL SCHEDULER_DATABASE_URL DATABASE_MIGRATION_URL \\
         WORKSPACE_COOKIE_SECRET SUPABASE_URL SUPABASE_ANON_KEY SUPABASE_JWKS_URL SUPABASE_JWT_ISSUER \\
         NLW_IMAGE NLW_WEB_IMAGE PUBLIC_HOSTNAME; do
  grep -qE "^\$k=.+" "\$TMP" || { echo "STOP: \$k missing/empty in generated file." >&2; exit 3; }
done
mv "\$TMP" "\$ENVF"        # atomic promotion only after a fully valid file
chmod 600 "\$ENVF"
trap - EXIT INT TERM
echo "wrote \$ENVF (chmod 600) via atomic .env.prod.tmp -> .env.prod"
EOF

  local remote_mk
  remote_mk="$(rsh 'mktemp /tmp/nlw-mkenv.XXXXXX.sh')" || die "could not create remote env-builder temp."
  printf '%s\n' "$mk" | rsh "cat > '$remote_mk' && chmod 700 '$remote_mk'" || { rsh "rm -f '$remote_mk'" || true; die "could not upload env-builder."; }
  if ! printf '%s' "$anon" | rsh "bash '$remote_mk'"; then
    rsh "rm -f '$remote_mk'" || true
    die ".env.prod generation stopped (an existing .env.prod requires manual review)."
  fi
  rsh "rm -f '$remote_mk'" || true
  unset anon
  mark env_created
}

verify_env_resume() {
  # RESUME only. NEVER regenerates/overwrites; verifies the existing state.
  log "Resume: verifying existing .env.prod (exists + mode 600) …"
  rsh "test -e '$REMOTE_APP/.env.prod'" || die "resume: $REMOTE_APP/.env.prod does not exist. Run first deploy instead."
  local mode; mode="$(rsh "stat -c '%a' '$REMOTE_APP/.env.prod' 2>/dev/null" | tr -d '\r')"
  [ "$mode" = "600" ] || die "resume: .env.prod mode is '${mode:-missing}', expected 600."
  log "Resume: verifying pinned image digests + hostname in .env.prod …"
  local envp
  envp="$(rsh "grep -E '^(NLW_IMAGE|NLW_WEB_IMAGE|PUBLIC_HOSTNAME)=' '$REMOTE_APP/.env.prod'" | tr -d '\r')"
  grep -qx "NLW_IMAGE=$BACKEND_IMAGE"      <<<"$envp" || die "resume: NLW_IMAGE != pinned backend digest."
  grep -qx "NLW_WEB_IMAGE=$WEB_IMAGE"      <<<"$envp" || die "resume: NLW_WEB_IMAGE != pinned web digest."
  grep -qx "PUBLIC_HOSTNAME=$STAGING_HOST" <<<"$envp" || die "resume: PUBLIC_HOSTNAME != $STAGING_HOST."
  mark env_verified
}

verify_secrets_config() {
  # Validate secrets that already live in .env.prod WITHOUT bringing values to the
  # Mac or printing them: anon-key format, and LLM key iff provider=anthropic.
  log "Validating .env.prod secrets (format only; values never printed) …"
  rsh "cd '$REMOTE_APP'
    v=\$(grep -m1 '^SUPABASE_ANON_KEY=' .env.prod | cut -d= -f2-)
    case \"\$v\" in sb_publishable_?*) ;; *) echo 'STOP: SUPABASE_ANON_KEY must start with sb_publishable_ and have a suffix.' >&2; exit 4;; esac
    provider=\$(grep -m1 '^NLW_LLM_PROVIDER=' .env.prod | cut -d= -f2- | tr -d '[:space:]'); provider=\${provider:-stub}
    if [ \"\$provider\" = anthropic ]; then
      grep -qE '^NLW_LLM_API_KEY=.+' .env.prod || { echo 'STOP: NLW_LLM_PROVIDER=anthropic but NLW_LLM_API_KEY is empty/missing. Add the key on the host (never commit it), then re-run --resume.' >&2; exit 4; }
    fi
  " || die "secrets validation failed (see STOP message above)."
  mark secrets_verified
}

render_config() {
  log "Rendering compose config …"
  rsh "$DC config >/dev/null" || die "compose config render failed — check .env.prod and the compose files."
}

pull_images() {
  log "Pulling pinned images (verifies GHCR authentication) …"
  rsh "$DC pull" || die "image pull failed. On the VPS run 'docker login ghcr.io' with a read:packages token, then retry."
  mark images_pulled
}

start_datastores() {
  # --no-recreate protects an existing pgdata/redis from being recreated on
  # resume; on first deploy the containers are created fresh (initdb runs).
  log "Starting datastores (postgres, redis; --no-recreate protects state) …"
  rsh "$DC up -d --no-recreate postgres redis"
  mark postgres_started; mark redis_started
  log "Waiting for postgres health …"
  rsh "cd '$REMOTE_APP' && for i in \$(seq 1 60); do docker compose --env-file .env.prod $COMPOSE_FILES exec -T postgres pg_isready -U nlw -d nlw >/dev/null 2>&1 && exit 0; sleep 2; done; exit 1" \
    || die "postgres did not become ready."
}

verify_roles() {
  log "Verifying runtime roles exist (00-roles.sh bootstrap) …"
  local roles
  roles="$(rsh "$DC exec -T postgres psql -U nlw -d nlw -tAc \"SELECT string_agg(rolname, ',' ORDER BY rolname) FROM pg_roles WHERE rolname LIKE 'nlw\\_%'\"" | tr -d '\r')"
  local r
  for r in nlw_app nlw_worker nlw_scheduler nlw_rls_bypass nlw_workspace_bootstrap; do
    case ",$roles," in *",$r,"*) ;; *) die "expected role '$r' not found (roles: $roles). Not destroying anything." ;; esac
  done
  log "Roles present: $roles"
  mark role_bootstrap_verified
}

run_migrations() {
  # Idempotent: a no-op when already at head. NEVER downgrades. Runs via the
  # dedicated one-shot `migrate` service (the ONLY holder of the owner credential;
  # api/worker/scheduler never receive it).
  log "Applying Alembic migrations to head (dedicated migrate service; idempotent) …"
  rsh "$DC --profile migration run --rm migrate" || die "alembic upgrade failed (volumes preserved; NO rollback)."
  mark migrations_applied
}

verify_migration() {
  # DETERMINISTIC — no hex-only grep. Expected head is derived INSIDE the pinned
  # image via Alembic's ScriptDirectory; the current revision is a scalar SQL
  # read from the owner connection. Empty values are hard failures.
  log "Deriving expected Alembic head from the pinned image …"
  local raw_head expected_head raw_cur current_rev
  raw_head="$(rsh "$DC run --rm -T api python -c 'from alembic.config import Config; from alembic.script import ScriptDirectory; h=ScriptDirectory.from_config(Config(\"alembic.ini\")).get_current_head(); assert h, \"no head\"; print(\"HEAD=%s\" % h)' 2>/dev/null")"
  expected_head="$(printf '%s' "$raw_head" | parse_head_line)"
  log "Reading current DB revision (owner scalar query) …"
  raw_cur="$(rsh "$DC exec -T postgres psql -U nlw -d nlw -tAc 'SELECT version_num FROM alembic_version'" 2>/dev/null || true)"
  current_rev="$(printf '%s' "$raw_cur" | parse_current)"
  assert_revisions "$expected_head" "$current_rev" || die "migration verification failed (current='$current_rev' head='$expected_head')."
  log "Schema at head: $current_rev"
  mark migrations_verified
}

start_app_services() {
  log "Starting api, worker, scheduler, web, prometheus, caddy (NO e2e overlay) …"
  rsh "$DC up -d api worker scheduler web prometheus caddy"
  mark application_services_started
}

verify_readiness() {
  log "Waiting for host-local API readiness (127.0.0.1:8000/health/ready) …"
  rsh "for i in \$(seq 1 60); do curl -fsS http://127.0.0.1:8000/health/ready >/dev/null 2>&1 && exit 0; sleep 2; done; exit 1" \
    || die "API /health/ready did not become healthy."
  log "Readiness OK: $(rsh 'curl -fsS http://127.0.0.1:8000/health/ready' | tr -d '\r')"
  mark readiness_verified
}

verify_public_login() {
  log "Waiting for public https://${STAGING_HOST}/login (Caddy ACME may take ~30–60s) …"
  local ok=0 i code
  for i in $(seq 1 40); do
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "https://${STAGING_HOST}/login" 2>/dev/null || true)"
    if [ "$code" = "200" ]; then ok=1; break; fi
    sleep 5
  done
  [ "$ok" = "1" ] || die "public https://${STAGING_HOST}/login not serving 200 with a valid certificate yet (TLS may still be issuing; diagnostics collected)."
  mark tls_verified
}

main() {
  local mode="first"
  case "${1:-}" in
    "") mode="first" ;;
    --resume) mode="resume" ;;
    *) die "unknown argument '$1' (use no args for first deploy, or --resume)." ;;
  esac
  log "Mode: $mode"
  trap fail_report EXIT

  preflight
  imdsv2_check
  pin_config
  if [ "$mode" = "first" ]; then
    confirm_manual_prereqs
    create_env_first
  else
    verify_env_resume
  fi
  verify_secrets_config
  render_config
  pull_images
  start_datastores
  verify_roles
  run_migrations
  verify_migration
  start_app_services
  verify_readiness
  verify_public_login

  SUCCESS=1
  trap - EXIT
  log "STAGE-2 DEPLOY COMPLETE (mode: $mode)."
  log "  config SHA:   $DEPLOY_SHA"
  log "  backend:      $BACKEND_IMAGE"
  log "  web:          $WEB_IMAGE"
  log "  public:       https://${STAGING_HOST}/login (200, TLS-validated)"
  log "Next: scripts/ops/verify-staging-deployment.sh for the full read-only report."
  log "REMINDER: do NOT stop the EC2 instance (a STOP+START may change the public IP)."
}

# Run only when executed directly; allow tests to source the pure helpers.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main "$@"
fi
