#!/usr/bin/env bash
# DISPOSABLE upgrade rehearsal: M11 runtime + schema 0010  ->  P3B runtime + schema 0016
# (M12A-Prep §N, revised for the release-manifest / backup-first sequencing).
# Everything is local and thrown away; NOTHING touches a real host, a real
# backup provider, or production keys.
#
# What it mirrors — the SAME external-manifest flow and phase order the real
# rollout runs on the host, plus the negative proofs the design demands:
#   1  a throwaway registry (digest pins, like GHCR); an OLD backend image built
#      from the pinned M11 commit (no release label — it predates the tooling),
#      NEW backend + web images built with NLW_GIT_SHA=<release sha>;
#   2  an ops root laid out like /opt/nlw: `app` = the ACTIVE M11 checkout with
#      its .env.prod; `.env.backup`; releases/ + current + rollout/ do not exist yet;
#   3  release manifests produced by the SAME generator CI uses
#      (`nlw.ops.release_manifest generate --generated-by local-rehearsal`):
#      the committed example is REJECTED; a local-rehearsal manifest is NOT
#      authority without --local; a manifest pointing at the OLD image is REJECTED
#      by verify-release (no label / no tooling) — the current image passes;
#   4  a Postgres bootstrapped by the M11 role script (5 roles) and migrated to
#      0010 by the M11 image; representative disposable data; OLD runtimes serving;
#   5  rollout phases (--local): preflight -> verify-release -> prepare-keys ->
#      verify-escrow -> stage-release (inactive <ops_root>/releases/<sha>) ->
#      TWO forced backup failures (no evidence yet; broken repository credentials)
#      each proving: no roles, no migration, no active-config switch, old runtime
#      still serving, drain/prepare-roles/migrate refused -> real P2 backup into
#      the MinIO FIXTURE -> verify-backup (fixture refused unless the rehearsal-only
#      switch is given) -> drain -> prepare-roles -> migrate -> install keys ->
#      recreate-runtime (activation) -> validate -> reopen (records the OPEN
#      launch gate "alert delivery unverified": the null receiver) -> go-check
#      FAILS (NO-GO) — and neither checkout is dirtied by rollout state;
#   6  post-upgrade proofs: invitation accept + four-eyes approval under signed
#      contexts, a worker-executed synthetic run, one scheduler occurrence,
#      Prometheus rule groups loaded;
#   7  a SEPARATE disposable downgrade 0016 -> 0015 proving the legacy policies
#      come back (documented rollback warning), then cleanup of keys, manifests,
#      volumes and the registry.
#
# Requires: docker (Desktop/Engine), uv, git. Takes ~10-15 minutes (two backend
# builds + one web build + the backup image).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

OLD_SHA="5151a2cc54cfb63b276bd3b30cf0e683263525ac"   # the M11 pin the staging host runs
TS="$(date +%Y%m%d%H%M%S)"
PROJ="nlwrehearsal${TS}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/${PROJ}.XXXXXX")"
chmod 700 "$TMP"
OPS="$TMP/ops"; APP="$OPS/app"; OLD="$TMP/old"; SRC="$TMP/src"
KEYS_PARENT="$TMP/keys"; KEYS="$KEYS_PARENT/ctx-keys"
MANIFEST="$TMP/release-manifest.json"; OLD_IMAGE_MANIFEST="$TMP/release-old-image.json"
REG="127.0.0.1:5000"; REGNAME="${PROJ}-registry"
AUTH="AUTHORIZE_M12A_SIGNED_CONTEXT_STAGING_DEPLOYMENT"
ESC="SIGNED_CONTEXT_KEYS_ESCROWED_AND_RECOVERY_TESTED"
ROLLOUT=(uv run python -m nlw.ops.rollout --local --release "$MANIFEST" --target "$TMP/target.env" --keys-dir "$KEYS")

log() { printf '\n\033[1;34m=== %s ===\033[0m\n' "$*"; }
ok()  { printf '  \033[1;32m[ok]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mREHEARSAL FAIL:\033[0m %s\n' "$*" >&2; exit 1; }
# must_fail <label> <cmd...>: the command must exit non-zero; its output is kept
# in $LAST_OUT for message assertions.
must_fail() {
  local label="$1"; shift
  if LAST_OUT="$("$@" 2>&1)"; then printf '%s\n' "$LAST_OUT"; die "$label — expected a STOP, but it succeeded"; fi
}
OVERLAY="$TMP/docker-compose.rehearsal.yml"
DC_OLD="docker compose -p $PROJ --env-file $APP/.env.prod -f $APP/docker-compose.prod.yml -f $APP/docker-compose.staging.yml -f $OVERLAY"
DC="$DC_OLD"  # switched to the activated release after recreate-runtime
psql_owner() { $DC exec -T postgres psql -U nlw -d nlw -tAc "$1" | tr -d '[:space:]'; }
running_api_image() { docker inspect --format '{{index .Config.Image}}' "$(docker ps -q --filter "label=com.docker.compose.project=$PROJ" --filter "label=com.docker.compose.service=api")" 2>/dev/null || true; }
assert_untouched() {  # the M11 side is exactly as before: schema, roles, config, runtime
  [ "$(psql_owner "SELECT version_num FROM alembic_version")" = "0010_readiness_schema_grant" ] || die "$1: schema changed"
  [ "$(psql_owner "SELECT count(*) FROM pg_roles WHERE rolname IN ('nlw_membership_admin','nlw_ctx_verifier')")" = "0" ] || die "$1: roles were created"
  [ ! -e "$OPS/current" ] || die "$1: active release switched"
  [ "$(git -C "$APP" rev-parse HEAD)" = "$OLD_SHA" ] || die "$1: active checkout moved"
  [ "$(shasum -a 256 "$APP/.env.prod" | cut -d' ' -f1)" = "$ACTIVE_ENV_HASH" ] || die "$1: active .env.prod changed"
  [ "$(running_api_image)" = "$OLD_BACKEND" ] || die "$1: running api is not the OLD image ($(running_api_image))"
  curl -fsS http://127.0.0.1:8000/health/ready | grep -q '"status":"ready"' || die "$1: old runtime stopped serving"
  ok "$1: no roles, no migration, no active-config switch; OLD runtime still serving"
}

cleanup() {
  log "cleanup (${PROJ}) — keys, manifests, volumes, registry, worktrees"
  docker compose -p "$PROJ" --env-file "$APP/.env.prod" -f "$APP/docker-compose.prod.yml" -f "$OVERLAY" down -v --remove-orphans >/dev/null 2>&1 || true
  docker volume ls -q --filter "label=com.docker.compose.project=$PROJ" | xargs docker volume rm >/dev/null 2>&1 || true
  docker rm -f "$REGNAME" >/dev/null 2>&1 || true
  docker run --rm --user 0:0 -v "$KEYS_PARENT:/k" alpine:3.20 sh -c 'rm -rf /k/ctx-keys' >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

log "1/10 local throwaway registry (digest-pinned images, like GHCR)"
docker run -d --rm --name "$REGNAME" -p "${REG}:5000" registry:2 >/dev/null
sleep 2

log "2/10 build + push images: OLD backend (${OLD_SHA:0:7}, unlabelled), NEW backend + web (HEAD, labelled)"
# The NEW side is the WORKING TREE (including uncommitted changes under review):
# it is committed into a THROWAWAY clone so the rollout can check out a real
# release SHA, exactly as it will on the host. The active app dir is a CLONE of
# that repository pinned at the OLD commit (old compose files, old Caddyfile),
# with `origin` pointing at it — exactly like /opt/nlw/app today.
git clone -q "$REPO" "$SRC"
rsync -a --exclude .git --exclude .venv --exclude node_modules --exclude "web/.next" \
  --exclude "docker/ctx-keys" --exclude ".env*" --exclude "/supabase/" --exclude ".rollout" "$REPO/" "$SRC/"
git -C "$SRC" add -A >/dev/null && git -C "$SRC" -c user.name=rehearsal -c user.email=r@localhost commit -q -m "rehearsal snapshot" --allow-empty
NEW_SHA="$(git -C "$SRC" rev-parse HEAD)"
git -C "$SRC" worktree add -q --detach "$OLD" "$OLD_SHA"
mkdir -p "$OPS"
git clone -q "$SRC" "$APP" && git -C "$APP" checkout -q --detach "$OLD_SHA"
cp "$SRC/docker-compose.rehearsal.yml" "$OVERLAY"
docker build -q -t "$REG/nlw:old" "$OLD" >/dev/null                                   # predates ARG NLW_GIT_SHA: no label
docker build -q -t "$REG/nlw:new" --build-arg "NLW_GIT_SHA=$NEW_SHA" "$SRC" >/dev/null
docker build -q -t "$REG/nlw-web:new" --build-arg "NLW_GIT_SHA=$NEW_SHA" "$SRC/web" >/dev/null
for t in nlw:old nlw:new nlw-web:new; do docker push -q "$REG/$t" >/dev/null; done
digest() { docker inspect --format '{{index .RepoDigests 0}}' "$REG/$1"; }
OLD_BACKEND="$(digest nlw:old)"; NEW_BACKEND="$(digest nlw:new)"; NEW_WEB="$(digest nlw-web:new)"
ok "old backend  $OLD_BACKEND"; ok "new backend  $NEW_BACKEND"; ok "new web      $NEW_WEB"

log "3/10 ops root mirroring the VPS: active app dir, .env.prod (old pins), .env.backup, target.env"
pw() { openssl rand -hex 32; }
PGPW="$(pw)"; APPPW="$(pw)"; WPW="$(pw)"; SPW="$(pw)"; RESTIC_PW="$(pw)"
umask 077
cat > "$APP/.env.prod" <<EOF
COMPOSE_PROJECT_NAME=$PROJ
POSTGRES_PASSWORD=$PGPW
NLW_APP_DB_PASSWORD=$APPPW
NLW_WORKER_DB_PASSWORD=$WPW
NLW_SCHEDULER_DB_PASSWORD=$SPW
DATABASE_URL=postgresql+psycopg://nlw_app:$APPPW@postgres:5432/nlw
WORKER_DATABASE_URL=postgresql+psycopg://nlw_worker:$WPW@postgres:5432/nlw
SCHEDULER_DATABASE_URL=postgresql+psycopg://nlw_scheduler:$SPW@postgres:5432/nlw
DATABASE_MIGRATION_URL=postgresql+psycopg://nlw:$PGPW@postgres:5432/nlw
REDIS_URL=redis://redis:6379/0
NLW_IMAGE=$OLD_BACKEND
NLW_WEB_IMAGE=$NEW_WEB
NLW_BACKUP_IMAGE=nlw-backup:$PROJ
PUBLIC_HOSTNAME=rehearsal.localhost
WORKSPACE_COOKIE_SECRET=$(pw)
SUPABASE_URL=https://proj.supabase.co
SUPABASE_ANON_KEY=sb_publishable_rehearsal
SUPABASE_JWKS_URL=https://proj.supabase.co/auth/v1/.well-known/jwks.json
SUPABASE_JWT_ISSUER=https://proj.supabase.co/auth/v1
EOF
ACTIVE_ENV_HASH="$(shasum -a 256 "$APP/.env.prod" | cut -d' ' -f1)"
write_backup_env() {  # $1 = dump credential (a WRONG one forces the backup job to fail at once)
  cat > "$OPS/.env.backup" <<EOF
APP_ENV=local
RESTIC_REPOSITORY=s3:http://minio:9000/rehearsal-fixture/nlw
RESTIC_PASSWORD=$RESTIC_PW
BACKUP_AWS_ACCESS_KEY_ID=rehearsal-fixture
BACKUP_AWS_SECRET_ACCESS_KEY=rehearsal-fixture-not-a-secret
BACKUP_AWS_REGION=us-east-1
NLW_BACKUP_DATABASE_URL=postgresql://nlw:$1@postgres:5432/nlw
EOF
}
write_backup_env "$PGPW"
cat > "$TMP/target.env" <<EOF
NLW_STAGING_ENVIRONMENT=staging
NLW_STAGING_INSTANCE_ID=i-0000000000000001
NLW_STAGING_REGION=us-east-1
NLW_STAGING_SSH_HOST=127.0.0.1
NLW_STAGING_SSH_USER=nobody
NLW_STAGING_PUBLIC_HOSTNAME=rehearsal.localhost
NLW_STAGING_OPS_ROOT=$OPS
NLW_STAGING_REMOTE_APP=$APP
NLW_STAGING_COMPOSE_PROJECT=$PROJ
NLW_STAGING_COMPOSE_FILES=docker-compose.prod.yml docker-compose.staging.yml $OVERLAY
NLW_STAGING_BACKUP_ENV_FILE=$OPS/.env.backup
NLW_STAGING_CURRENT_REVISION=0010_readiness_schema_grant
NLW_STAGING_KEY_ID_API=rehearsal-api
NLW_STAGING_KEY_ID_WORKER=rehearsal-worker
NLW_STAGING_KEY_ID_SCHEDULER=rehearsal-scheduler
EOF
umask 022
mkdir -p "$KEYS_PARENT"
# The rollout reads host identity from IMDS on a real target; the LOCAL executor
# answers with this canned identity instead (see nlw.ops.rollout.remote).
export NLW_REHEARSAL_IDENTITY="instance-id=i-0000000000000001
placement/region=us-east-1
public-ipv4=127.0.0.1"

log "4/10 release manifests: the SAME generator CI runs; example + non-local + old-image are REJECTED"
GEN=(uv run python -m nlw.ops.release_manifest)
must_fail "committed example accepted" "${GEN[@]}" validate deploy/staging/release.example.json
must_fail "committed example accepted (--local)" "${GEN[@]}" validate --local deploy/staging/release.example.json
grep -q "not a deployable" <<<"$LAST_OUT" || die "example rejected for the wrong reason: $LAST_OUT"
ok "deploy/staging/release.example.json is rejected as release authority (with and without --local)"
"${GEN[@]}" generate --target-env "$TMP/target.env" --release-sha "$NEW_SHA" \
  --backend-image "$NEW_BACKEND" --web-image "$NEW_WEB" --generated-by local-rehearsal --out "$MANIFEST" >/dev/null
"${GEN[@]}" generate --target-env "$TMP/target.env" --release-sha "$NEW_SHA" \
  --backend-image "$OLD_BACKEND" --web-image "$NEW_WEB" --generated-by local-rehearsal --out "$OLD_IMAGE_MANIFEST" >/dev/null
must_fail "local-rehearsal manifest accepted without --local" "${GEN[@]}" validate "$MANIFEST"
grep -q "local-rehearsal" <<<"$LAST_OUT" || die "local manifest rejected for the wrong reason: $LAST_OUT"
"${GEN[@]}" validate --local "$MANIFEST" | grep -q "\"release_sha\": \"$NEW_SHA\"" || die "manifest does not carry the release sha"
! grep -Eiq 'password|secret|token|aws_' "$MANIFEST" || die "manifest carries a secret-like key"
ok "local-rehearsal manifest validates ONLY with --local (never authority for a real target); no secrets inside"
must_fail "rollout accepted the example" uv run python -m nlw.ops.rollout --local --release deploy/staging/release.example.json --target "$TMP/target.env" preflight
must_fail "rollout accepted a local manifest for a non-local target" uv run python -m nlw.ops.rollout --release "$MANIFEST" --target "$TMP/target.env" preflight
grep -q "local-rehearsal" <<<"$LAST_OUT" || die "non-local rollout rejected for the wrong reason: $LAST_OUT"
ok "rollout refuses the example, and refuses a local-rehearsal manifest without --local (before touching any target)"

log "5/10 OLD stack: datastores -> migrate to 0010 with the M11 image -> old runtimes -> seed"
$DC up -d postgres redis minio >/dev/null
for _ in $(seq 1 60); do $DC exec -T postgres pg_isready -U nlw -d nlw >/dev/null 2>&1 && break; sleep 2; done
# The provider bucket exists before the first backup (as on a configured
# provider; same fixture provisioning as scripts/ops/dr-drill.sh). restic 0.18
# retries a MISSING bucket for up to 15 minutes instead of failing.
docker run --rm --network "${PROJ}_internal" --entrypoint sh minio/mc -c \
  "mc alias set d http://minio:9000 rehearsal-fixture rehearsal-fixture-not-a-secret >/dev/null && mc mb -p d/rehearsal-fixture" >/dev/null
ok "fixture bucket provisioned (empty: no repository, no snapshot yet)"
# M11 had no migrate profile: migrations ran through the api image (which then
# still received the owner credential) — reproduce that exactly.
$DC run --rm -T api alembic upgrade head >/dev/null
[ "$(psql_owner "SELECT version_num FROM alembic_version")" = "0010_readiness_schema_grant" ] || die "old image did not migrate to 0010"
[ "$(psql_owner "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'nlw\\_%'")" = "5" ] || die "expected the 5 M11 roles"
ok "schema 0010, 5 M11 roles (no membership_admin / ctx_verifier) — same as the VPS"
$DC up -d api worker scheduler web caddy prometheus >/dev/null  # M11 overlay: no alertmanager yet
for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:8000/health/ready >/dev/null 2>&1 && break; sleep 2; done
curl -fsS http://127.0.0.1:8000/health/ready | grep -q '"status":"ready"' || die "old runtime not ready"
[ "$(running_api_image)" = "$OLD_BACKEND" ] || die "old runtime is not running the OLD image"
ok "OLD runtime (pre-P3B) is serving from the OLD image"
WS=$(uuidgen | tr A-F a-f); UA=$(uuidgen | tr A-F a-f); UB=$(uuidgen | tr A-F a-f); WF=$(uuidgen | tr A-F a-f); VER=$(uuidgen | tr A-F a-f); RUN=$(uuidgen | tr A-F a-f)
$DC exec -T postgres psql -U nlw -d nlw -q <<EOF
INSERT INTO workspaces (id, name, slug) VALUES ('$WS','rehearsal','rehearsal-$WS');
INSERT INTO users (id, auth_provider_id, email) VALUES ('$UA','rehearsal-a','a@rehearsal.test'),('$UB','rehearsal-b','b@rehearsal.test');
INSERT INTO memberships (id, user_id, workspace_id, role) VALUES (gen_random_uuid(),'$UA','$WS','owner');
INSERT INTO workflows (id, tenant_id, name) VALUES ('$WF','$WS','wf');
INSERT INTO workflow_versions (id, tenant_id, workflow_id, version, plan) VALUES ('$VER','$WS','$WF',1,'{"steps":[{"id":"a","tool":"fake.echo","args":{}}]}'::jsonb);
INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status) VALUES ('$RUN','$WS','$WF','$VER','COMPLETED');
EOF
ok "seeded user/workspace/workflow/terminal run"

log "6/10 ROLLOUT: preflight -> verify-release (OLD image REJECTED, current image OK) -> prepare-keys -> verify-escrow"
"${ROLLOUT[@]}" preflight
must_fail "verify-release accepted the OLD image" uv run python -m nlw.ops.rollout --local \
  --release "$OLD_IMAGE_MANIFEST" --target "$TMP/target.env" --keys-dir "$KEYS" verify-release --authorize "$AUTH"
grep -q "revision label" <<<"$LAST_OUT" || die "old image rejected for the wrong reason: $LAST_OUT"
ok "verify-release: a manifest naming the OLD (unlabelled, pre-tooling) image is REJECTED"
"${ROLLOUT[@]}" verify-release --authorize "$AUTH"
grep -q '"verify-release"' "$OPS/rollout/$NEW_SHA.json" || die "verify-release not recorded"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["evidence"]["verify-release"]; assert d["image_git_sha"]==sys.argv[2], d; assert len(d["commands_verified"])==6, d' "$OPS/rollout/$NEW_SHA.json" "$NEW_SHA"
ok "verify-release: current image carries the release SHA, migrations 0011-0016, head 0016, all 6 required commands"
"${ROLLOUT[@]}" prepare-keys --authorize "$AUTH"
# The OPERATOR writes the escrow attestation after copying the files off-host.
# Here the rehearsal plays the operator: fingerprints only, never material.
FPS="$(docker run --rm --user 0:0 --network none -v "$KEYS:/keys:ro" "$NEW_BACKEND" python -m nlw.ctxkeys fingerprint --dir /keys --key-id-api rehearsal-api --key-id-worker rehearsal-worker --key-id-scheduler rehearsal-scheduler --owner 10001)"
if [ "$(uname -s)" = "Linux" ]; then
  grep -qE '^[0-9a-f]{64}$' "$KEYS/api.key" 2>/dev/null && die "key files must not be readable by the rehearsal user (0400 uid 10001)" || true
else
  ok "host-side key readability check skipped (Docker Desktop maps bind-mount ownership); container view enforced 0400/uid 10001"
fi
python3 - "$TMP/attestation.json" "$NEW_SHA" <<EOF
import json, sys, datetime
fps = {l.split()[0]: l.split() for l in """$FPS""".splitlines() if len(l.split()) == 3}
doc = {"format_version": 1, "environment": "staging", "release_sha": sys.argv[2],
       "keys": [{"purpose_class": c, "key_id": fps[c][1], "sha256_fingerprint": fps[c][2]} for c in ("api", "worker", "scheduler")],
       "escrow_verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
       "operator": "rehearsal-operator", "recovery_test_confirmed": True,
       "escrow_location_label": "REHEARSAL fixture vault - not real escrow"}
open(sys.argv[1], "w").write(json.dumps(doc, indent=2))
EOF
"${ROLLOUT[@]}" verify-escrow --authorize "$AUTH" --escrow-confirm "$ESC" --attestation "$TMP/attestation.json"
assert_untouched "after verify-escrow"

log "7/10 stage-release (INACTIVE) -> forced backup failures -> real backup -> verify-backup; roles come AFTER"
"${ROLLOUT[@]}" stage-release --authorize "$AUTH"
STAGED="$OPS/releases/$NEW_SHA"
[ "$(git -C "$STAGED" rev-parse HEAD)" = "$NEW_SHA" ] || die "staged release is not at the release SHA"
grep -q "^NLW_IMAGE=$NEW_BACKEND$" "$STAGED/.env.prod" || die "staged .env.prod not pinned to the new digest"
assert_untouched "after stage-release (release staged inactive)"
# Forced failure 1: verify-backup with NO backup evidence yet.
must_fail "verify-backup passed without any backup" "${ROLLOUT[@]}" verify-backup --authorize "$AUTH" --allow-fixture-repository
grep -q "backup gate failed\|evidence" <<<"$LAST_OUT" || die "verify-backup refused for the wrong reason: $LAST_OUT"
for ph in drain prepare-roles migrate; do
  must_fail "$ph ran without a verified backup" "${ROLLOUT[@]}" "$ph" --authorize "$AUTH"
  grep -q "verify-backup" <<<"$LAST_OUT" || die "$ph refused for the wrong reason: $LAST_OUT"
done
assert_untouched "forced failure 1 (no evidence): drain/prepare-roles/migrate refused"
# Forced failure 2: the backup job itself FAILS (wrong dump credential; fails at once).
write_backup_env "wrong-credential-forces-failure"
must_fail "backup succeeded with a broken repository credential" "${ROLLOUT[@]}" backup --authorize "$AUTH"
must_fail "verify-backup passed after a failed backup" "${ROLLOUT[@]}" verify-backup --authorize "$AUTH" --allow-fixture-repository
for ph in drain prepare-roles migrate; do must_fail "$ph ran after a failed backup" "${ROLLOUT[@]}" "$ph" --authorize "$AUTH"; done
assert_untouched "forced failure 2 (backup job failed): drain/prepare-roles/migrate refused"
write_backup_env "$PGPW"
"${ROLLOUT[@]}" backup --authorize "$AUTH"
ok "P2 backup of the PRE-UPGRADE database (rev 0010, bound to instance/environment/db/release) into the MinIO FIXTURE"
must_fail "fixture repository accepted without the rehearsal switch" "${ROLLOUT[@]}" verify-backup --authorize "$AUTH"
grep -qi "fixture\|off-host\|https" <<<"$LAST_OUT" || die "fixture refused for the wrong reason: $LAST_OUT"
"${ROLLOUT[@]}" verify-backup --authorize "$AUTH" --allow-fixture-repository
assert_untouched "after verify-backup (backup verified BEFORE any role/migration)"

log "8/10 drain -> prepare-roles -> migrate 0010->0016 -> install keys -> recreate (ACTIVATE) -> validate -> reopen -> go-check"
"${ROLLOUT[@]}" drain --authorize "$AUTH"
curl -sS -o /dev/null -w '%{http_code}' -k --resolve rehearsal.localhost:8443:127.0.0.1 https://rehearsal.localhost:8443/login | grep -q '^503$' && ok "maintenance mode: edge serves 503" || die "maintenance 503 not served"
"${ROLLOUT[@]}" prepare-roles --authorize "$AUTH"
[ "$(psql_owner "SELECT count(*) FROM pg_roles WHERE rolname IN ('nlw_membership_admin','nlw_ctx_verifier')")" = "2" ] || die "roles not provisioned"
ok "roles provisioned — only after the verified backup"
"${ROLLOUT[@]}" migrate --authorize "$AUTH"
[ "$(psql_owner "SELECT version_num FROM alembic_version")" = "0016_signed_database_context" ] || die "not at 0016"
[ "$(psql_owner "SELECT count(*) FROM pg_policies")" = "51" ] || die "policy count != 51"
ok "schema 0016; 51 signed policies"
"${ROLLOUT[@]}" install-context-keys --authorize "$AUTH"
[ ! -e "$OPS/current" ] || die "active release switched before recreate-runtime"
"${ROLLOUT[@]}" recreate-runtime --authorize "$AUTH"
[ "$(readlink "$OPS/current")" = "$STAGED" ] || die "current symlink does not point at the staged release"
[ "$(running_api_image)" = "$NEW_BACKEND" ] || die "api is not running the NEW image after activation"
[ "$(git -C "$APP" rev-parse HEAD)" = "$OLD_SHA" ] || die "the old checkout was modified (it must stay available for rollback)"
ok "ACTIVATED: current -> releases/$NEW_SHA; api runs the NEW digest; old checkout intact"
DC="docker compose -p $PROJ --env-file $STAGED/.env.prod -f $STAGED/docker-compose.prod.yml -f $STAGED/docker-compose.staging.yml -f $OVERLAY"
"${ROLLOUT[@]}" validate --authorize "$AUTH"
REOPEN_OUT="$("${ROLLOUT[@]}" reopen --authorize "$AUTH" 2>&1)"; printf '%s\n' "$REOPEN_OUT"
grep -q "LAUNCH GATE OPEN: alert delivery unverified" <<<"$REOPEN_OUT" || die "reopen did not record the open alert-delivery gate"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["evidence"]["reopen"]; assert d["launch_gates_open"]==["alert delivery unverified"], d; a=d["alerting"]; assert a["rules_loaded"] and a["alertmanager_reachable"] and a["receiver_is_null"] and not a["delivery_verified"], a' "$OPS/rollout/$NEW_SHA.json"
ok "reopen: traffic reopened; state records rules loaded + Alertmanager reachable + receiver null + delivery NOT verified"
must_fail "go-check passed on the null receiver" "${ROLLOUT[@]}" go-check
grep -q "null receiver" <<<"$LAST_OUT" || die "go-check failed for the wrong reason: $LAST_OUT"
ok "go-check: NO-GO — the null receiver is never 'alert delivery configured'"
[ -z "$(git -C "$APP" status --porcelain)" ] && [ -z "$(git -C "$STAGED" status --porcelain)" ] || die "rollout state dirtied a git checkout"
ok "rollout state lives in $OPS/rollout (outside both checkouts); both checkouts are clean"
curl -fsS http://127.0.0.1:8000/health/ready | grep -q '"signed_context":"ok"' || die "signed_context not ok"
ok "NEW runtime ready with signed_context: ok"

log "9/10 post-upgrade proofs: invitation + four-eyes (signed), worker run, scheduler occurrence, rules"
APPR=$(uuidgen | tr A-F a-f); RUN2=$(uuidgen | tr A-F a-f); TOKEN="$(openssl rand -hex 24)"
TOKEN_HASH="$(printf '%s' "$TOKEN" | shasum -a 256 | cut -d' ' -f1)"
$DC exec -T postgres psql -U nlw -d nlw -q <<EOF
INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status, initiated_by_user_id) VALUES ('$RUN2','$WS','$WF','$VER','WAITING_APPROVAL','$UA');
INSERT INTO approvals (id, tenant_id, run_id, step_id, connector_id, connector_name, tool, status, requested_by_user_id) VALUES ('$APPR','$WS','$RUN2','a',gen_random_uuid(),'hook','webhook.send','pending','$UA');
INSERT INTO workspace_invitations (id, tenant_id, email, role, invited_by, token_hash, status, expires_at) VALUES (gen_random_uuid(),'$WS','b@rehearsal.test','admin','$UA','$TOKEN_HASH','pending',now() + interval '1 day');
EOF
printf '%s\n' "$TOKEN" | $DC exec -T api python -m nlw.ops.rollout.smoke --workspace "$WS" --user-a "$UA" --user-b "$UB" --approval "$APPR" --invitation-token-stdin
ok "unsigned forgery denied; signed context scoped; invitation accepted; self-approval blocked; four-eyes approval ok"
RUN3=$(uuidgen | tr A-F a-f)
psql_owner "INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status) VALUES ('$RUN3','$WS','$WF','$VER','PENDING')" >/dev/null
$DC exec -T api python -c "from nlw.worker.actors import advance_run; advance_run.send('$RUN3')"
for _ in $(seq 1 30); do [ "$(psql_owner "SELECT status FROM workflow_runs WHERE id='$RUN3'")" = "COMPLETED" ] && break; sleep 2; done
[ "$(psql_owner "SELECT status FROM workflow_runs WHERE id='$RUN3'")" = "COMPLETED" ] || die "worker did not complete the synthetic run"
ok "worker completed a synthetic run under signed worker_execution context"
SID=$(uuidgen | tr A-F a-f)
psql_owner "INSERT INTO schedules (id, tenant_id, workflow_id, workflow_version_id, timezone, frequency, minute, hour, enabled, next_run_at, created_by) VALUES ('$SID','$WS','$WF','$VER','UTC','daily',extract(minute from now())::int,extract(hour from now())::int,true,now(),'$UA')" >/dev/null
for _ in $(seq 1 60); do [ "$(psql_owner "SELECT count(*) FROM workflow_runs WHERE schedule_id='$SID'")" = "1" ] && break; sleep 2; done
[ "$(psql_owner "SELECT count(*) FROM workflow_runs WHERE schedule_id='$SID'")" = "1" ] || die "scheduler did not create exactly one occurrence"
ok "scheduler created exactly one occurrence under signed scheduler_reconcile context"
RULE_GROUPS="$($DC exec -T prometheus wget -qO- http://127.0.0.1:9090/api/v1/rules | python3 -c 'import sys,json; print(",".join(sorted(g["name"] for g in json.load(sys.stdin)["data"]["groups"])))')"
[ "$RULE_GROUPS" = "nlw-backup,nlw-signed-context" ] || die "prometheus rule groups loaded: '$RULE_GROUPS'"
$DC exec -T alertmanager wget -qO- http://127.0.0.1:9093/-/healthy | grep -qi ok || die "alertmanager unhealthy"
ok "prometheus rule groups loaded (nlw-backup, nlw-signed-context); alertmanager healthy (null receiver: delivery UNVERIFIED)"

log "10/10 SEPARATE disposable downgrade 0016 -> 0015: legacy policies return (documented rollback warning)"
$DC stop api worker scheduler >/dev/null
$DC --profile migration run --rm -T migrate sh -c 'alembic downgrade 0015_membership_approval_sod' >/dev/null
LEGACY="$(psql_owner "SELECT count(*) FROM pg_policies WHERE qual LIKE '%app.user_id%' OR qual LIKE '%app.tenant_id%' OR with_check LIKE '%app.user_id%' OR with_check LIKE '%app.tenant_id%'")"
[ "$LEGACY" -gt 0 ] || die "downgrade did not restore legacy policies"
ok "downgrade re-installs $LEGACY legacy unsigned-GUC policies — exactly why downgrade below 0016 is security-sensitive"
$DC --profile migration run --rm -T migrate >/dev/null
[ "$(psql_owner "SELECT version_num FROM alembic_version")" = "0016_signed_database_context" ] || die "re-upgrade failed"
ok "re-upgraded to 0016 (up -> down -> up)"

printf '\n\033[1;32mREHEARSAL PASSED\033[0m — local, disposable, MinIO fixture (NOT DR evidence), null Alertmanager (delivery UNVERIFIED); keys, manifests and volumes are removed on exit.\n'
