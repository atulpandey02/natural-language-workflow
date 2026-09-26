#!/usr/bin/env bash
# DISPOSABLE upgrade rehearsal: M11 runtime + schema 0010  ->  the CURRENT release
# (target head derived from the working tree's migrations; the file name keeps the
# historical 0010->0016 boundary it was written for, the checks are head-agnostic).
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
#      (`nlw.ops.release_manifest generate --generated-by local-rehearsal`) with
#      FIXTURE provenance (`nlw.ops.release_provenance fixture`: an UNSIGNED
#      envelope with a non-GitHub identity, accepted only under --local; it makes
#      NO GitHub trust claim). Proofs: the committed example is REJECTED; a
#      hand-written `generated_by: ci` manifest passes SCHEMA validation but is
#      rejected as release authority (no provenance); an unattested rehearsal
#      manifest is rejected; the fixture is rejected without --local; a manifest
#      modified after its fixture was issued is rejected; a manifest pointing at
#      the OLD image is REJECTED by verify-release (no label / no tooling) — the
#      current image passes; replacing the manifest after phases ran invalidates
#      the recorded state (digest binding);
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
#   7  post-rollout hotfix proofs (reproduced on the first REAL staging rollout):
#      the root-0700 key directory is never mounted (each one-shot mounts only its
#      key file; kernel-semantics proof through a Docker volume); the OPERATOR
#      Alertmanager files (config root:root 0644, secrets root:65534 0750/0640,
#      Compose override) outside every checkout are required, permission-checked,
#      and evaluated from the RUNNING container; a null operator config, an
#      inline/world-readable credential and a missing override are refused; a
#      bare recreation without the override is caught ("mount disagreement");
#      the HUMAN delivery record (scripts/ops/record-alert-delivery.sh) closes
#      the launch gate and go-check passes — stale/mismatched/malformed records
#      do not;
#   8  a SECOND, CODE-ONLY release (N -> N+1: same schema head, same keys — the
#      shape of the post-rollout hotfix itself) rolled out THROUGH <ops_root>/current
#      with target.env pointing at it — migrate is a verified no-op, no duplicate
#      project/volumes, no live database recreation, operator Alertmanager kept;
#   9  a SEPARATE disposable downgrade <head> -> 0015 proving the legacy policies
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
PROV="$TMP/provenance-fixture.json"; OLD_IMAGE_PROV="$TMP/provenance-old-image.json"
REG="127.0.0.1:5000"; REGNAME="${PROJ}-registry"
AUTH="AUTHORIZE_M12A_SIGNED_CONTEXT_STAGING_DEPLOYMENT"
ESC="SIGNED_CONTEXT_KEYS_ESCROWED_AND_RECOVERY_TESTED"
ROLLOUT=(uv run python -m nlw.ops.rollout --local --release "$MANIFEST" --provenance-fixture "$PROV" --target "$TMP/target.env" --keys-dir "$KEYS")

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

# The rollout must never recreate the live datastores nor create a second Compose
# project / database volume (explicit -p on both sides; --no-deps on one-shots).
# Only Compose-labelled volumes are compared: an anonymous volume created by an
# unrelated container on the developer machine (e.g. an image VOLUME) must not
# fail the invariant, which is about a SECOND project / database volume.
snapshot_docker() { docker volume ls -q --filter label=com.docker.compose.project | sort > "$TMP/volumes.$1"; docker compose ls -aq 2>/dev/null | sort > "$TMP/projects.$1"; }
assert_datastores_untouched() {
  local pg redis
  pg="$(docker ps -q --no-trunc --filter "label=com.docker.compose.project=$PROJ" --filter "label=com.docker.compose.service=postgres")"
  redis="$(docker ps -q --no-trunc --filter "label=com.docker.compose.project=$PROJ" --filter "label=com.docker.compose.service=redis")"
  [ "$pg" = "$PG_CID" ] || die "$1: the postgres CONTAINER was recreated (${PG_CID:0:12} -> ${pg:0:12})"
  [ "$redis" = "$REDIS_CID" ] || die "$1: the redis CONTAINER was recreated"
  snapshot_docker after
  local added; added="$(comm -13 "$TMP/volumes.before" "$TMP/volumes.after")"
  ! grep -q '_pgdata$' <<<"$added" || die "$1: a NEW database volume appeared: $added"
  [ -z "$(grep -v "^${PROJ}_" <<<"$added" | grep -v '^$')" ] || die "$1: Compose volumes outside the project were created: $added"
  [ -z "$(comm -13 "$TMP/projects.before" "$TMP/projects.after")" ] || die "$1: a second Compose project appeared"
  [ "$(docker volume ls -q | grep -c "^${PROJ}_pgdata$")" = "1" ] || die "$1: pgdata volume count != 1"
  ok "$1: postgres/redis containers, the single pgdata volume and the project are untouched"
}

# Root-owned operator files (Alertmanager config/secrets/override, like the VPS)
# are created and edited through a root container; $TMP is mounted at /t.
as_root() { docker run --rm --user 0:0 -v "$TMP:/t" alpine:3.20 sh -ec "$1"; }
AMDIR="$OPS/alertmanager"; AMSEC="$OPS/alertmanager.secrets"; OVR="$OPS/docker-compose.operator.yml"

cleanup() {
  log "cleanup (${PROJ}) — keys, manifests, volumes, registry, worktrees"
  docker compose -p "$PROJ" --env-file "$APP/.env.prod" -f "$APP/docker-compose.prod.yml" -f "$OVERLAY" down -v --remove-orphans >/dev/null 2>&1 || true
  docker volume ls -q --filter "label=com.docker.compose.project=$PROJ" | xargs docker volume rm >/dev/null 2>&1 || true
  docker rm -f "$REGNAME" >/dev/null 2>&1 || true
  docker run --rm --user 0:0 -v "$KEYS_PARENT:/k" alpine:3.20 sh -c 'rm -rf /k/ctx-keys' >/dev/null 2>&1 || true
  docker run --rm --user 0:0 -v "$TMP:/t" alpine:3.20 sh -c 'rm -rf /t/ops/alertmanager /t/ops/alertmanager.secrets /t/ops/docker-compose.operator.yml /t/am-operator.yml' >/dev/null 2>&1 || true
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
  --exclude ".mypy_cache" --exclude ".ruff_cache" --exclude ".pytest_cache" --exclude "__pycache__" \
  --exclude "docker/ctx-keys" --exclude ".env*" --exclude "/supabase/" --exclude ".rollout" "$REPO/" "$SRC/"
git -C "$SRC" add -A >/dev/null && git -C "$SRC" -c user.name=rehearsal -c user.email=r@localhost commit -q -m "rehearsal snapshot" --allow-empty
NEW_SHA="$(git -C "$SRC" rev-parse HEAD)"
# The rollout is head-agnostic (migrate -> `alembic upgrade head`, verified against the
# manifest's target_revision, which the generator derives from the migrations). The
# rehearsal asserts the SAME derived values instead of a hard-coded revision.
TARGET_HEAD="$(uv run python -c 'from nlw.ops.release_manifest import alembic_head; print(alembic_head())')"
EXPECTED_POLICIES="$(uv run python -c 'from nlw.ops.rollout.phases import EXPECTED_SIGNED_POLICIES as n; print(n)')"
ok "target head ${TARGET_HEAD} (expected signed policies after migrate: ${EXPECTED_POLICIES})"
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
# The legacy host keeps the worker's connector secrets in a git-IGNORED env file
# that `git clone` never carries; the rollout must stage it explicitly.
printf 'NLW_SECRET_REHEARSAL=rehearsal-not-a-secret\n' > "$APP/docker/worker.secrets.env"
chmod 600 "$APP/docker/worker.secrets.env"
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
NLW_STAGING_GIT_REMOTE=$SRC
NLW_STAGING_ALERTMANAGER_CONFIG=$AMDIR/alertmanager.yml
NLW_STAGING_ALERTMANAGER_SECRETS_DIR=$AMSEC
NLW_STAGING_COMPOSE_OVERRIDE=$OVR
NLW_STAGING_KEY_ID_API=rehearsal-api
NLW_STAGING_KEY_ID_WORKER=rehearsal-worker
NLW_STAGING_KEY_ID_SCHEDULER=rehearsal-scheduler
EOF
umask 022
# OPERATOR Alertmanager authority, laid out like the VPS (docs/ops/alerting.md):
# a real (webhook) receiver whose credential is a *_file under the secrets mount.
# The webhook target is an unroutable placeholder: delivery is proved by a HUMAN
# record, never by this fixture. Ownership/modes are set through a root container
# so the container view is exactly the host's (config root:root 0644, secrets
# root:65534 0750, credential root:65534 0640).
mkdir -p "$AMDIR" "$AMSEC"
cat > "$TMP/am-operator.yml" <<'EOF'
route:
  receiver: ops-webhook
  group_by: ["alertname", "component", "role"]
  routes:
    - matchers: ["severity = critical"]
      receiver: ops-webhook
receivers:
  - name: "null"
  - name: ops-webhook
    webhook_configs:
      - url_file: /etc/alertmanager/secrets/webhook.url
EOF
cp "$TMP/am-operator.yml" "$AMDIR/alertmanager.yml"
printf 'http://127.0.0.1:9/rehearsal-placeholder-not-a-secret\n' > "$AMSEC/webhook.url"
cat > "$OVR" <<EOF
services:
  alertmanager:
    volumes:
      - $AMDIR/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro
      - $AMSEC:/etc/alertmanager/secrets:ro
EOF
as_root 'chown 0:0 /t/ops/alertmanager /t/ops/alertmanager/alertmanager.yml /t/ops/docker-compose.operator.yml; chmod 755 /t/ops/alertmanager; chmod 644 /t/ops/alertmanager/alertmanager.yml /t/ops/docker-compose.operator.yml; chown 0:65534 /t/ops/alertmanager.secrets /t/ops/alertmanager.secrets/webhook.url; chmod 750 /t/ops/alertmanager.secrets; chmod 640 /t/ops/alertmanager.secrets/webhook.url'
ok "operator Alertmanager authority laid out outside every checkout: config root:root 0644, secrets root:65534 0750/0640, override"
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
must_fail "rollout accepted the example" uv run python -m nlw.ops.rollout --local --release deploy/staging/release.example.json --provenance-fixture "$PROV" --target "$TMP/target.env" preflight
must_fail "rollout accepted a local manifest for a non-local target" uv run python -m nlw.ops.rollout --release "$MANIFEST" --target "$TMP/target.env" preflight
grep -q "local-rehearsal" <<<"$LAST_OUT" || die "non-local rollout rejected for the wrong reason: $LAST_OUT"
ok "rollout refuses the example, and refuses a local-rehearsal manifest without --local (before touching any target)"
# --- PROVENANCE (ADR-025): schema validity is not authority -----------------------
PV=(uv run python -m nlw.ops.release_provenance)
# A hand-written `generated_by: ci` manifest: full SHA, real digests, expected
# identity, a plausible ci block. SCHEMA-valid — and nothing more.
python3 - "$MANIFEST" "$TMP/hand-written-ci.json" <<'PYEOF2'
import json, sys
d = json.load(open(sys.argv[1])); d["generated_by"] = "ci"
d["ci"] = {"workflow": "Delivery", "run_id": "424242", "run_url": "https://github.com/atulpandey02/natural-language-workflow/actions/runs/424242", "actor": "someone"}
json.dump(d, open(sys.argv[2], "w"), indent=2, sort_keys=True)
PYEOF2
"${GEN[@]}" validate "$TMP/hand-written-ci.json" >/dev/null || die "hand-written ci manifest should pass SCHEMA validation (that is the point)"
must_fail "hand-written ci manifest accepted as authority (--local)" uv run python -m nlw.ops.rollout --local --release "$TMP/hand-written-ci.json" --provenance-fixture "$PROV" --target "$TMP/target.env" preflight
must_fail "hand-written ci manifest accepted as authority (real target path)" uv run python -m nlw.ops.rollout --release "$TMP/hand-written-ci.json" --target "$TMP/target.env" preflight
grep -q "provenance REJECTED" <<<"$LAST_OUT" || die "hand-written manifest rejected for the wrong reason: $LAST_OUT"
ok "a hand-written generated_by=ci manifest passes SCHEMA validation but is NOT release authority (provenance rejected; no host contacted)"
must_fail "unattested rehearsal manifest accepted" uv run python -m nlw.ops.rollout --local --release "$MANIFEST" --target "$TMP/target.env" preflight
grep -q "requires --provenance-fixture" <<<"$LAST_OUT" || die "unattested manifest rejected for the wrong reason: $LAST_OUT"
"${PV[@]}" fixture "$MANIFEST" --out "$PROV" >/dev/null
"${PV[@]}" fixture "$OLD_IMAGE_MANIFEST" --out "$OLD_IMAGE_PROV" >/dev/null
"${PV[@]}" verify "$MANIFEST" --local --fixture "$PROV" | grep -q '"fixture": true' || die "fixture provenance did not verify under --local"
must_fail "fixture provenance accepted without --local" "${PV[@]}" verify "$MANIFEST" --fixture "$PROV"
must_fail "rollout accepted fixture provenance without --local" uv run python -m nlw.ops.rollout --release "$MANIFEST" --provenance-fixture "$PROV" --target "$TMP/target.env" preflight
grep -q "rehearsal-only" <<<"$LAST_OUT" || die "fixture rejected for the wrong reason: $LAST_OUT"
cp "$MANIFEST" "$TMP/modified.json"; printf '\n' >> "$TMP/modified.json"
must_fail "manifest modified after attestation accepted" "${PV[@]}" verify "$TMP/modified.json" --local --fixture "$PROV"
grep -q "does not match the manifest bytes" <<<"$LAST_OUT" || die "modified manifest rejected for the wrong reason: $LAST_OUT"
ok "PROVENANCE: unattested manifest rejected; fixture accepted ONLY under --local (never a GitHub trust claim); a byte changed after attestation is rejected"

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
T_ROLLOUT_START=$(date +%s)
"${ROLLOUT[@]}" preflight
PG_CID="$(docker ps -q --no-trunc --filter "label=com.docker.compose.project=$PROJ" --filter "label=com.docker.compose.service=postgres")"
REDIS_CID="$(docker ps -q --no-trunc --filter "label=com.docker.compose.project=$PROJ" --filter "label=com.docker.compose.service=redis")"
snapshot_docker before
# The backup env file is read CLIENT-SIDE by the rollout user: unreadable or
# world-readable files stop the rollout at preflight, before anything is staged.
chmod 000 "$OPS/.env.backup"
must_fail "preflight passed with an unreadable backup env file" "${ROLLOUT[@]}" preflight
grep -q "not readable" <<<"$LAST_OUT" || die "unreadable backup env rejected for the wrong reason: $LAST_OUT"
chmod 644 "$OPS/.env.backup"
must_fail "preflight passed with a world-readable backup env file" "${ROLLOUT[@]}" preflight
grep -q "world-readable" <<<"$LAST_OUT" || die "world-readable backup env rejected for the wrong reason: $LAST_OUT"
chmod 600 "$OPS/.env.backup"
: > "$OPS/.env.backup"   # the live host's starting state: present, root-created, EMPTY
must_fail "preflight passed with an EMPTY backup env file" "${ROLLOUT[@]}" preflight
grep -q "is empty" <<<"$LAST_OUT" || die "empty backup env rejected for the wrong reason: $LAST_OUT"
write_backup_env "$PGPW"
ok "preflight: backup env file must be readable by the rollout user, not world-readable, and non-empty (contents never read)"
# --- Operator Alertmanager authority is checked at preflight (read-only), before anything is staged.
as_root 'cp /t/src/docker/alertmanager/alertmanager.yml /t/ops/alertmanager/alertmanager.yml'
must_fail "preflight accepted the committed NULL config as operator authority" "${ROLLOUT[@]}" preflight
grep -q "null receiver" <<<"$LAST_OUT" || die "null operator config rejected for the wrong reason: $LAST_OUT"
as_root 'printf "route:\n  receiver: s\nreceivers:\n  - name: s\n    slack_configs:\n      - api_url: https://hooks.example.invalid/placeholder-not-a-secret\n" > /t/ops/alertmanager/alertmanager.yml'
must_fail "preflight accepted an INLINE credential" "${ROLLOUT[@]}" preflight
grep -q "inline credential" <<<"$LAST_OUT" || die "inline credential rejected for the wrong reason: $LAST_OUT"
as_root 'cp /t/am-operator.yml /t/ops/alertmanager/alertmanager.yml; chown 0:0 /t/ops/alertmanager/alertmanager.yml; chmod 644 /t/ops/alertmanager/alertmanager.yml'
as_root 'chmod 644 /t/ops/alertmanager.secrets/webhook.url'
must_fail "preflight accepted a WORLD-READABLE credential" "${ROLLOUT[@]}" preflight
grep -q "world-readable" <<<"$LAST_OUT" || die "world-readable credential rejected for the wrong reason: $LAST_OUT"
as_root 'chmod 640 /t/ops/alertmanager.secrets/webhook.url'
if [ "$(uname -s)" = "Linux" ]; then
  # The previously documented layout (root:root 0700 dir, root:root 0600 file): unreadable as uid 65534.
  as_root 'chown 0:0 /t/ops/alertmanager.secrets /t/ops/alertmanager.secrets/webhook.url; chmod 700 /t/ops/alertmanager.secrets; chmod 600 /t/ops/alertmanager.secrets/webhook.url'
  must_fail "preflight accepted a root-only credential Alertmanager (uid 65534) cannot read" "${ROLLOUT[@]}" preflight
  grep -q "readable by the Alertmanager user" <<<"$LAST_OUT" || die "root-only credential rejected for the wrong reason: $LAST_OUT"
  as_root 'chown 0:65534 /t/ops/alertmanager.secrets /t/ops/alertmanager.secrets/webhook.url; chmod 750 /t/ops/alertmanager.secrets; chmod 640 /t/ops/alertmanager.secrets/webhook.url'
  ok "preflight: root:root 0700/0600 secrets are refused (unreadable as uid 65534); root:65534 0750/0640 pass"
else
  ok "host bind-mount uid-65534 probe skipped on Docker Desktop (bind mounts do not enforce uid/mode); kernel-semantics proof follows"
fi
as_root 'mv /t/ops/docker-compose.operator.yml /t/ops/docker-compose.operator.yml.off'
must_fail "preflight passed WITHOUT the operator Compose override" "${ROLLOUT[@]}" preflight
grep -q "override" <<<"$LAST_OUT" || die "missing override rejected for the wrong reason: $LAST_OUT"
as_root 'mv /t/ops/docker-compose.operator.yml.off /t/ops/docker-compose.operator.yml'
"${ROLLOUT[@]}" preflight | grep -q '"receiver": "ops-webhook"' || die "preflight does not report the operator receiver"
ok "preflight: null operator config, inline credential, world-readable credential and missing override are refused; the real receiver is reported"
# --- Kernel-semantics reproductions (a Docker VOLUME lives in the Linux VM, so uid/mode are enforced
# exactly as on the VPS even under Docker Desktop): defect 1 (key dir) and defect 4 (secrets layout).
KV="${PROJ}-kernel-proof"; docker volume create "$KV" >/dev/null
docker run --rm --user 0:0 -v "$KV:/v" alpine:3.20 sh -ec '
mkdir -p /v/ctx-keys /v/bad /v/good
head -c 32 /dev/urandom | od -An -tx1 | tr -d " \n" > /v/ctx-keys/api.key; chown 0:0 /v/ctx-keys; chmod 700 /v/ctx-keys; chown 10001:10001 /v/ctx-keys/api.key; chmod 400 /v/ctx-keys/api.key
echo placeholder > /v/bad/cred;  chown 0:0 /v/bad /v/bad/cred;       chmod 700 /v/bad;  chmod 600 /v/bad/cred
echo placeholder > /v/good/cred; chown 0:65534 /v/good /v/good/cred; chmod 750 /v/good; chmod 640 /v/good/cred' >/dev/null
! docker run --rm --user 10001:10001 --mount "type=volume,src=$KV,dst=/run/nlw/keys,volume-subpath=ctx-keys,readonly" alpine:3.20 cat /run/nlw/keys/api.key >/dev/null 2>&1 || die "kernel proof: uid 10001 could read a key through the mounted root-0700 directory"
docker run --rm --user 10001:10001 --mount "type=volume,src=$KV,dst=/run/nlw/keys/api.key,volume-subpath=ctx-keys/api.key,readonly" alpine:3.20 sh -c '[ "$(wc -c < /run/nlw/keys/api.key)" -ge 64 ]' >/dev/null 2>&1 || die "kernel proof: uid 10001 could NOT read the individually mounted key file"
! docker run --rm --user 65534:65534 --mount "type=volume,src=$KV,dst=/etc/alertmanager/secrets,volume-subpath=bad,readonly" alpine:3.20 cat /etc/alertmanager/secrets/cred >/dev/null 2>&1 || die "kernel proof: uid 65534 could read a root:root 0600 credential"
docker run --rm --user 65534:65534 --mount "type=volume,src=$KV,dst=/etc/alertmanager/secrets,volume-subpath=good,readonly" alpine:3.20 cat /etc/alertmanager/secrets/cred >/dev/null 2>&1 || die "kernel proof: uid 65534 could NOT read a root:65534 0640 credential"
docker volume rm "$KV" >/dev/null
ok "KERNEL SEMANTICS: root-0700 key dir mounted whole -> unreadable for uid 10001; the key FILE mounted alone -> readable; root:root 0600 secret -> unreadable for uid 65534; root:65534 0640 -> readable"
must_fail "verify-release accepted the OLD image" uv run python -m nlw.ops.rollout --local \
  --release "$OLD_IMAGE_MANIFEST" --provenance-fixture "$OLD_IMAGE_PROV" --target "$TMP/target.env" --keys-dir "$KEYS" verify-release --authorize "$AUTH"
grep -q "revision label" <<<"$LAST_OUT" || die "old image rejected for the wrong reason: $LAST_OUT"
ok "verify-release: a manifest naming the OLD (unlabelled, pre-tooling) image is REJECTED"
"${ROLLOUT[@]}" verify-release --authorize "$AUTH"
grep -q '"verify-release"' "$OPS/rollout/$NEW_SHA.json" || die "verify-release not recorded"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["evidence"]["verify-release"]; assert d["image_git_sha"]==sys.argv[2], d; assert len(d["commands_verified"])==6, d' "$OPS/rollout/$NEW_SHA.json" "$NEW_SHA"
ok "verify-release: current image carries the release SHA, migrations 0011-${TARGET_HEAD:0:4}, head ${TARGET_HEAD}, all 6 required commands"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["manifest_sha256"]==sys.argv[2], d; assert d["evidence"]["verify-release"]["provenance"]["fixture"] is True' "$OPS/rollout/$NEW_SHA.json" "$(shasum -a 256 "$MANIFEST" | cut -d" " -f1)"
[ -f "$OPS/rollout/$NEW_SHA.receipt.json" ] && cmp -s "$OPS/rollout/$NEW_SHA.manifest.json" "$MANIFEST" || die "verified manifest + receipt not stored as evidence"
ok "state bound to the manifest digest; verified manifest + provenance receipt stored under $OPS/rollout (evidence dir, outside checkouts)"
# Replacing the manifest (same release SHA, different bytes) invalidates the recorded state.
cp "$MANIFEST" "$TMP/original.json"
python3 - "$MANIFEST" <<'PYEOF2'
import json, sys
d = json.load(open(sys.argv[1])); d["created_at"] = "2026-01-01T00:00:00+00:00"
open(sys.argv[1], "w").write(json.dumps(d, indent=2, sort_keys=True) + "\n")
PYEOF2
"${PV[@]}" fixture "$MANIFEST" --out "$TMP/provenance-replaced.json" >/dev/null
must_fail "replaced manifest reused earlier phase evidence" uv run python -m nlw.ops.rollout --local --release "$MANIFEST" --provenance-fixture "$TMP/provenance-replaced.json" --target "$TMP/target.env" --keys-dir "$KEYS" prepare-keys --authorize "$AUTH"
grep -q "different release manifest" <<<"$LAST_OUT" || die "replaced manifest rejected for the wrong reason: $LAST_OUT"
cp "$TMP/original.json" "$MANIFEST"; rm -f "$TMP/provenance-replaced.json"
ok "a replaced manifest (new digest) invalidates all earlier phase evidence on the host — STOP"
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
[ -f "$STAGED/docker/worker.secrets.env" ] || die "worker connector secrets file was NOT carried into the staged release"
[ "$(stat -f %Lp "$STAGED/docker/worker.secrets.env" 2>/dev/null || stat -c %a "$STAGED/docker/worker.secrets.env")" = "600" ] || die "staged worker secrets file is not 0600"
cmp -s "$APP/docker/worker.secrets.env" "$STAGED/docker/worker.secrets.env" || die "staged worker secrets file differs from the active one"
[ -z "$(git -C "$STAGED" status --porcelain)" ] || die "staging the worker secrets file dirtied the release checkout"
ok "worker connector secrets file staged (0600, git-ignored, checkout still clean)"
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
assert_datastores_untouched "after verify-backup"

log "8/10 drain -> prepare-roles -> migrate 0010->${TARGET_HEAD} -> install keys -> recreate (ACTIVATE) -> validate -> reopen -> go-check"
"${ROLLOUT[@]}" drain --authorize "$AUTH"
curl -sS -o /dev/null -w '%{http_code}' -k --resolve rehearsal.localhost:8443:127.0.0.1 https://rehearsal.localhost:8443/login | grep -q '^503$' && ok "maintenance mode: edge serves 503" || die "maintenance 503 not served"
"${ROLLOUT[@]}" prepare-roles --authorize "$AUTH"
[ "$(psql_owner "SELECT count(*) FROM pg_roles WHERE rolname IN ('nlw_membership_admin','nlw_ctx_verifier')")" = "2" ] || die "roles not provisioned"
ok "roles provisioned — only after the verified backup"
"${ROLLOUT[@]}" migrate --authorize "$AUTH"
[ "$(psql_owner "SELECT version_num FROM alembic_version")" = "$TARGET_HEAD" ] || die "not at ${TARGET_HEAD}"
[ "$(psql_owner "SELECT count(*) FROM pg_policies")" = "$EXPECTED_POLICIES" ] || die "policy count != ${EXPECTED_POLICIES}"
ok "schema ${TARGET_HEAD}; ${EXPECTED_POLICIES} signed policies"
assert_datastores_untouched "after prepare-roles + migrate (one-shot runs use --no-deps)"
"${ROLLOUT[@]}" install-context-keys --authorize "$AUTH"
KD="$(docker run --rm --user 0:0 --network none --entrypoint stat -v "$KEYS:/k:ro" "$NEW_BACKEND" -c '%a %u' /k/.)"
[ "$KD" = "700 0" ] || die "key directory was loosened during install-context-keys (want 700 root, got $KD)"
ok "install-context-keys: keys installed with the directory still root 0700 (each one-shot mounted only its key file; no chmod workaround)"
[ ! -e "$OPS/current" ] || die "active release switched before recreate-runtime"
# A real DIRECTORY at <ops_root>/current must refuse activation (a link would
# otherwise be created INSIDE it and nothing would actually switch).
mkdir "$OPS/current"
must_fail "activated over a directory at current" "${ROLLOUT[@]}" recreate-runtime --authorize "$AUTH"
grep -q "not a symlink" <<<"$LAST_OUT" || die "directory at current rejected for the wrong reason: $LAST_OUT"
rmdir "$OPS/current"
# api/worker are STOPPED since drain; the (stopped) api container must still be the OLD image
[ "$(docker inspect --format '{{index .Config.Image}}' "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJ" --filter "label=com.docker.compose.service=api" | head -1)")" = "$OLD_BACKEND" ] || die "runtimes were recreated despite the refused activation"
ok "recreate-runtime refuses a directory at current; nothing recreated"
"${ROLLOUT[@]}" recreate-runtime --authorize "$AUTH"
[ "$(readlink "$OPS/current")" = "$STAGED" ] || die "current symlink does not point at the staged release"
[ "$(running_api_image)" = "$NEW_BACKEND" ] || die "api is not running the NEW image after activation"
[ "$(git -C "$APP" rev-parse HEAD)" = "$OLD_SHA" ] || die "the old checkout was modified (it must stay available for rollback)"
ok "ACTIVATED: current -> releases/$NEW_SHA; api runs the NEW digest; old checkout intact"
assert_datastores_untouched "after activation"
WORKER_CID="$(docker ps -q --filter "label=com.docker.compose.project=$PROJ" --filter "label=com.docker.compose.service=worker")"
docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$WORKER_CID" | grep -q '^NLW_SECRET_REHEARSAL=' || die "recreated worker lost its connector secrets env file"
ok "recreated worker carries the connector secrets env file (variable name checked, value never printed)"
DC_BARE="docker compose -p $PROJ --env-file $STAGED/.env.prod -f $STAGED/docker-compose.prod.yml -f $STAGED/docker-compose.staging.yml -f $OVERLAY"
DC="$DC_BARE -f $OVR"   # the reviewed invocation: the operator override on every call from a release dir
am_mounts() { docker inspect --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' "$(docker ps -q --filter "label=com.docker.compose.project=$PROJ" --filter "label=com.docker.compose.service=alertmanager")"; }
# am_has_mount <host path> <container path>: the daemon reports the RESOLVED source
# (Docker Desktop: /host_mnt<realpath>); compare realpaths, exactly as the rollout does.
am_has_mount() { python3 - "$1" "$2" "$(am_mounts)" <<'PYEOF2'
import os, sys
want, dest = os.path.realpath(sys.argv[1]), sys.argv[2]
for item in sys.argv[3].split():
    src, _, d = item.rpartition(":")
    if src.startswith("/host_mnt/"):
        src = src[len("/host_mnt"):]
    if d == dest and os.path.realpath(src) == want:
        sys.exit(0)
sys.exit(1)
PYEOF2
}
am_loaded_receiver() { $DC exec -T alertmanager wget -qO- http://127.0.0.1:9093/api/v2/status | uv run python -c 'import sys,json,yaml; print(yaml.safe_load(json.load(sys.stdin)["config"]["original"])["route"]["receiver"])'; }
am_has_mount "$AMDIR/alertmanager.yml" /etc/alertmanager/alertmanager.yml && am_has_mount "$AMSEC" /etc/alertmanager/secrets || die "recreated Alertmanager does not mount the operator config/secrets: $(am_mounts)"
[ "$(am_loaded_receiver)" = "ops-webhook" ] || die "running Alertmanager loaded receiver $(am_loaded_receiver), not the operator's"
python3 -c 'import json,sys; a=json.load(open(sys.argv[1]))["evidence"]["recreate-runtime"]["alertmanager"]; assert a["receiver"]=="ops-webhook" and a["config_source"]=="running-alertmanager", a; assert "secret" not in json.dumps(a)' "$OPS/rollout/$NEW_SHA.json"
ok "recreate-runtime: the RUNNING Alertmanager mounts the operator config + secrets (not the committed file) and LOADED the operator receiver"
"${ROLLOUT[@]}" validate --authorize "$AUTH"
REOPEN_OUT="$("${ROLLOUT[@]}" reopen --authorize "$AUTH" 2>&1)"; printf '%s\n' "$REOPEN_OUT"
grep -q "LAUNCH GATE OPEN: alert delivery unverified" <<<"$REOPEN_OUT" || die "reopen did not record the open alert-delivery gate"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["evidence"]["reopen"]; assert d["launch_gates_open"]==["alert delivery unverified"], d; a=d["alerting"]; assert a["rules_loaded"] and a["alertmanager_reachable"] and not a["receiver_is_null"] and a["receiver"]=="ops-webhook" and a["credential_files_present"] and not a["delivery_verified"] and a["config_source"]=="running-alertmanager" and a["delivery_status"]=="absent", a' "$OPS/rollout/$NEW_SHA.json"
ok "reopen: traffic reopened; evidence = rules loaded + Alertmanager reachable + REAL receiver (running config) + delivery NOT verified (no human record)"
must_fail "go-check passed without a controlled-delivery record" "${ROLLOUT[@]}" go-check
grep -q "no verified controlled test" <<<"$LAST_OUT" || die "go-check failed for the wrong reason: $LAST_OUT"
ok "go-check: NO-GO — a reachable Alertmanager with a real receiver is still not delivery proof"
# --- The HUMAN delivery record (never written by the rollout). Here the rehearsal plays the
# operator; the record is a labelled FIXTURE — no alert was delivered anywhere.
REC=(bash scripts/ops/record-alert-delivery.sh --dir "$OPS/rollout" --owner "$(id -un)" --group "$(id -gn)")
ROLLOUT_DIR_BEFORE="$(ls -ldn "$OPS/rollout" | awk '{print $1, $3, $4}')"
"${REC[@]}" --receiver ops-webhook --confirmed-by "rehearsal-operator FIXTURE nothing was delivered" >/dev/null
[ "$(ls -ldn "$OPS/rollout" | awk '{print $1, $3, $4}')" = "$ROLLOUT_DIR_BEFORE" ] || die "recording the delivery changed the rollout directory ownership/mode"
[ "$(stat -f %Lp "$OPS/rollout/alert-delivery.json" 2>/dev/null || stat -c %a "$OPS/rollout/alert-delivery.json")" = "640" ] || die "delivery record is not 0640"
"${ROLLOUT[@]}" go-check 2>&1 | grep -q "M12 GO check: PASS" || die "go-check did not pass with a fresh, matching, confirmed record"
ok "go-check: PASS only after the HUMAN record (receiver ops-webhook, confirmed, fresh) — REHEARSAL FIXTURE, not a delivery claim; rollout dir untouched"
"${REC[@]}" --receiver ops-webhook --confirmed-by rehearsal-operator --delivered-at "$(date -u -v-10d +%Y-%m-%dT%H:%M:%S+00:00 2>/dev/null || date -u -d '10 days ago' +%Y-%m-%dT%H:%M:%S+00:00)" >/dev/null
must_fail "go-check passed on a STALE record" "${ROLLOUT[@]}" go-check; grep -q "stale" <<<"$LAST_OUT" || die "stale record rejected for the wrong reason: $LAST_OUT"
"${REC[@]}" --receiver other-team --confirmed-by rehearsal-operator >/dev/null
must_fail "go-check passed on a record naming ANOTHER receiver" "${ROLLOUT[@]}" go-check; grep -q "receiver-mismatch" <<<"$LAST_OUT" || die "mismatched record rejected for the wrong reason: $LAST_OUT"
printf '{"receiver": ' > "$OPS/rollout/alert-delivery.json"
must_fail "go-check passed on a MALFORMED record" "${ROLLOUT[@]}" go-check; grep -q "malformed" <<<"$LAST_OUT" || die "malformed record rejected for the wrong reason: $LAST_OUT"
must_fail "reopen passed on a MALFORMED record" "${ROLLOUT[@]}" reopen --authorize "$AUTH"; grep -q "malformed" <<<"$LAST_OUT" || die "reopen: malformed record rejected for the wrong reason: $LAST_OUT"
"${REC[@]}" --receiver ops-webhook --confirmed-by "rehearsal-operator FIXTURE nothing was delivered" >/dev/null
ok "delivery record: stale, other-receiver and malformed records never verify (malformed stops reopen too); a fresh record is back"
# --- A bare recreation WITHOUT the override (what an operator might type) reverts the container
# to the committed null file; the rollout catches it instead of reporting a null pipeline.
$DC_BARE up -d --force-recreate --no-deps alertmanager >/dev/null 2>&1
am_has_mount "$STAGED/docker/alertmanager/alertmanager.yml" /etc/alertmanager/alertmanager.yml || die "bare recreation did not mount the committed file (test setup)"
must_fail "go-check passed after the override was dropped by a bare recreation" "${ROLLOUT[@]}" go-check
grep -q "mount disagreement" <<<"$LAST_OUT" || die "dropped override caught for the wrong reason: $LAST_OUT"
$DC up -d --force-recreate --no-deps alertmanager >/dev/null 2>&1   # the reviewed invocation restores it
for _ in $(seq 1 30); do $DC exec -T alertmanager wget -qO- http://127.0.0.1:9093/-/healthy >/dev/null 2>&1 && break; sleep 1; done
am_has_mount "$AMDIR/alertmanager.yml" /etc/alertmanager/alertmanager.yml || die "recreation with the override did not restore the operator mounts"
"${ROLLOUT[@]}" go-check 2>&1 | grep -q "M12 GO check: PASS" || die "go-check did not pass after the operator mounts were restored"
ok "a recreation that drops the override is caught (mount disagreement -> NO-GO); recreating with the reviewed invocation keeps the operator Alertmanager"
[ -z "$(git -C "$APP" status --porcelain)" ] && [ -z "$(git -C "$STAGED" status --porcelain)" ] || die "rollout state dirtied a git checkout"
ok "rollout state lives in $OPS/rollout (outside both checkouts); both checkouts are clean"
curl -fsS http://127.0.0.1:8000/health/ready | grep -q '"signed_context":"ok"' || die "signed_context not ok"
ok "NEW runtime ready with signed_context: ok"
assert_datastores_untouched "after reopen"
# Layout/target mismatch guard: a LEGACY target (remote_app = app) on a host whose
# current -> another release is a configuration error naming the fix, not a rollout.
"${ROLLOUT[@]}" preflight >/dev/null   # current -> THIS release: still fine
ln -sfn "$OPS/releases/0000000000000000000000000000000000000000" "$OPS/current"
must_fail "preflight accepted a legacy target on a host activated for another release" "${ROLLOUT[@]}" preflight
grep -q "NLW_STAGING_REMOTE_APP=$OPS/current" <<<"$LAST_OUT" || die "layout mismatch rejected for the wrong reason: $LAST_OUT"
ln -sfn "$STAGED" "$OPS/current"
[ "$(readlink "$OPS/current")" = "$STAGED" ] || die "current not restored"
ok "layout guard: a legacy target on an activated host stops and names NLW_STAGING_REMOTE_APP=<ops_root>/current (nothing changed)"
ok "LOCAL TIMING: preflight -> reopen took $(( $(date +%s) - T_ROLLOUT_START )) s (local rehearsal, not the VPS)"

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

log "9b/10 SECOND, CODE-ONLY release (N -> N+1, same schema head) rolled out THROUGH current: same keys, operator Alertmanager kept"
# Step 9 left synthetic work in flight (the approved four-eyes run); N+1's drain
# gate refuses non-terminal work — proven above for N. On the host the operator
# waits for the queue; the rehearsal settles its own fixtures by hand.
LEFT="$(psql_owner "SELECT count(*) FROM workflow_runs WHERE status IN ('PENDING','RUNNING','WAITING_APPROVAL')")"
psql_owner "UPDATE workflow_runs SET status='FAILED', error='rehearsal: settled by hand before N+1', finished_at=now() WHERE status IN ('PENDING','RUNNING','WAITING_APPROVAL')" >/dev/null
psql_owner "UPDATE external_actions SET status='failed', lease_expires_at=NULL WHERE status='pending' OR lease_expires_at > now()" >/dev/null 2>&1 || true
ok "synthetic in-flight work from step 9 settled by hand ($LEFT run(s)); the drain gate itself is proven in step 8"
# A code-only change (no migration): exactly what a hotfix release looks like.
printf '\n<!-- rehearsal: N+1 code-only release marker -->\n' >> "$SRC/README.md"
git -C "$SRC" add -A >/dev/null && git -C "$SRC" -c user.name=rehearsal -c user.email=r@localhost commit -q -m "rehearsal: N+1 code-only release"
NEW2_SHA="$(git -C "$SRC" rev-parse HEAD)"
docker build -q -t "$REG/nlw:new2" --build-arg "NLW_GIT_SHA=$NEW2_SHA" "$SRC" >/dev/null
docker build -q -t "$REG/nlw-web:new2" --build-arg "NLW_GIT_SHA=$NEW2_SHA" "$SRC/web" >/dev/null
docker push -q "$REG/nlw:new2" >/dev/null; docker push -q "$REG/nlw-web:new2" >/dev/null
NEW2_BACKEND="$(digest nlw:new2)"; NEW2_WEB="$(digest nlw-web:new2)"
# target.env for the NEXT rollout: the active checkout IS current; the live revision is the head we just reached.
sed -i.bak -e "s#^NLW_STAGING_REMOTE_APP=.*#NLW_STAGING_REMOTE_APP=$OPS/current#" -e "s#^NLW_STAGING_CURRENT_REVISION=.*#NLW_STAGING_CURRENT_REVISION=$TARGET_HEAD#" "$TMP/target.env"
MANIFEST2="$TMP/release-manifest-2.json"; PROV2="$TMP/provenance-fixture-2.json"
"${GEN[@]}" generate --target-env "$TMP/target.env" --release-sha "$NEW2_SHA" --backend-image "$NEW2_BACKEND" --web-image "$NEW2_WEB" \
  --generated-by local-rehearsal --out "$MANIFEST2" >/dev/null
grep -q "\"expected_current_revision\": \"$TARGET_HEAD\"" "$MANIFEST2" && grep -q "\"target_revision\": \"$TARGET_HEAD\"" "$MANIFEST2" || die "N+1 manifest is not a same-revision (code-only) release"
ok "N+1 manifest generated by the SAME generator CI runs: expected == target == ${TARGET_HEAD} (code-only release; nothing is refused)"
"${PV[@]}" fixture "$MANIFEST2" --out "$PROV2" >/dev/null
ROLLOUT2=(uv run python -m nlw.ops.rollout --local --release "$MANIFEST2" --provenance-fixture "$PROV2" --target "$TMP/target.env" --keys-dir "$KEYS")
STAGED2="$OPS/releases/$NEW2_SHA"
T2_START=$(date +%s)
PRE2="$("${ROLLOUT2[@]}" preflight 2>&1)"; printf '%s\n' "$PRE2"
grep -q '"current_link": "PREVIOUS_RELEASE"' <<<"$PRE2" && grep -q "\"active_checkout\": \"$NEW_SHA\"" <<<"$PRE2" && grep -q "\"current_revision\": \"$TARGET_HEAD\"" <<<"$PRE2" || die "N+1 preflight did not read the active release through current"
ok "N+1 preflight: active checkout read THROUGH current (release N = $NEW_SHA), live revision $TARGET_HEAD, operator receiver reported"
"${ROLLOUT2[@]}" verify-release --authorize "$AUTH"
"${ROLLOUT2[@]}" prepare-keys --authorize "$AUTH"
python3 -c 'import json,sys; e=json.load(open(sys.argv[1]))["evidence"]["prepare-keys"]; assert e["reused_existing"] is True and len(e["fingerprints"])==3, e' "$OPS/rollout/$NEW2_SHA.json"
ok "N+1 prepare-keys: existing keys verified + fingerprinted (not regenerated, never overwritten)"
python3 - "$TMP/attestation-2.json" "$NEW2_SHA" <<EOF
import json, sys, datetime
fps = {l.split()[0]: l.split() for l in """$FPS""".splitlines() if len(l.split()) == 3}
doc = {"format_version": 1, "environment": "staging", "release_sha": sys.argv[2],
       "keys": [{"purpose_class": c, "key_id": fps[c][1], "sha256_fingerprint": fps[c][2]} for c in ("api", "worker", "scheduler")],
       "escrow_verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
       "operator": "rehearsal-operator", "recovery_test_confirmed": True,
       "escrow_location_label": "REHEARSAL fixture vault - not real escrow"}
open(sys.argv[1], "w").write(json.dumps(doc, indent=2))
EOF
"${ROLLOUT2[@]}" verify-escrow --authorize "$AUTH" --escrow-confirm "$ESC" --attestation "$TMP/attestation-2.json"
"${ROLLOUT2[@]}" stage-release --authorize "$AUTH"
[ "$(git -C "$STAGED2" rev-parse HEAD)" = "$NEW2_SHA" ] || die "N+1 staged release is not at the release SHA (fetched from the reviewed git remote)"
grep -q "^NLW_IMAGE=$NEW2_BACKEND$" "$STAGED2/.env.prod" || die "N+1 staged .env.prod not pinned to the new digest"
cmp -s "$STAGED/docker/worker.secrets.env" "$STAGED2/docker/worker.secrets.env" || die "N+1 worker secrets were not carried from the active release"
[ "$(readlink "$OPS/current")" = "$STAGED" ] || die "N+1 staging switched current"
ok "N+1 stage-release: cloned from current, release fetched from NLW_STAGING_GIT_REMOTE, env derived from release N, current untouched"
"${ROLLOUT2[@]}" backup --authorize "$AUTH"
"${ROLLOUT2[@]}" verify-backup --authorize "$AUTH" --allow-fixture-repository
assert_datastores_untouched "N+1: after verify-backup"
"${ROLLOUT2[@]}" drain --authorize "$AUTH"
"${ROLLOUT2[@]}" prepare-roles --authorize "$AUTH"
"${ROLLOUT2[@]}" migrate --authorize "$AUTH"
[ "$(psql_owner "SELECT version_num FROM alembic_version")" = "$TARGET_HEAD" ] || die "N+1: schema moved off ${TARGET_HEAD} on a code-only release"
[ "$(psql_owner "SELECT count(*) FROM pg_policies")" = "$EXPECTED_POLICIES" ] || die "N+1: policy count changed"
ok "N+1 migrate: verified no-op — schema stays ${TARGET_HEAD}, ${EXPECTED_POLICIES} policies"
"${ROLLOUT2[@]}" install-context-keys --authorize "$AUTH"
"${ROLLOUT2[@]}" recreate-runtime --authorize "$AUTH"
[ "$(readlink "$OPS/current")" = "$STAGED2" ] || die "N+1: current does not point at the new release"
[ "$(running_api_image)" = "$NEW2_BACKEND" ] || die "N+1: api is not running the N+1 digest"
[ "$(git -C "$STAGED" rev-parse HEAD)" = "$NEW_SHA" ] && [ "$(git -C "$APP" rev-parse HEAD)" = "$OLD_SHA" ] || die "N+1: a previous checkout was modified"
DC="docker compose -p $PROJ --env-file $STAGED2/.env.prod -f $STAGED2/docker-compose.prod.yml -f $STAGED2/docker-compose.staging.yml -f $OVERLAY -f $OVR"
am_has_mount "$AMDIR/alertmanager.yml" /etc/alertmanager/alertmanager.yml && am_has_mount "$AMSEC" /etc/alertmanager/secrets || die "N+1: operator Alertmanager mounts lost on recreation"
[ "$(am_loaded_receiver)" = "ops-webhook" ] || die "N+1: Alertmanager loaded receiver changed"
"${ROLLOUT2[@]}" validate --authorize "$AUTH"
REOPEN2="$("${ROLLOUT2[@]}" reopen --authorize "$AUTH" 2>&1)"
! grep -q "LAUNCH GATE OPEN" <<<"$REOPEN2" || die "N+1 reopen left a launch gate open despite the fresh record: $REOPEN2"
"${ROLLOUT2[@]}" go-check 2>&1 | grep -q "M12 GO check: PASS" || die "N+1 go-check did not pass"
assert_datastores_untouched "N+1: after reopen (same project, same pgdata, live postgres/redis never recreated)"
curl -fsS http://127.0.0.1:8000/health/ready | grep -q '"signed_context":"ok"' || die "N+1: signed_context not ok"
ok "N+1 ACTIVATED through current: releases/$NEW_SHA -> releases/$NEW2_SHA, code-only release at schema ${TARGET_HEAD}, keys unchanged, operator Alertmanager kept, go-check PASS (fixture record)"
ok "LOCAL TIMING: N+1 preflight -> reopen took $(( $(date +%s) - T2_START )) s"
log "10/10 SEPARATE disposable downgrade ${TARGET_HEAD} -> 0015: legacy policies return (documented rollback warning)"
$DC stop api worker scheduler >/dev/null
$DC --profile migration run --rm -T migrate sh -c 'alembic downgrade 0015_membership_approval_sod' >/dev/null
LEGACY="$(psql_owner "SELECT count(*) FROM pg_policies WHERE qual LIKE '%app.user_id%' OR qual LIKE '%app.tenant_id%' OR with_check LIKE '%app.user_id%' OR with_check LIKE '%app.tenant_id%'")"
[ "$LEGACY" -gt 0 ] || die "downgrade did not restore legacy policies"
ok "downgrade re-installs $LEGACY legacy unsigned-GUC policies — exactly why downgrade below 0016 is security-sensitive"
$DC --profile migration run --rm -T migrate >/dev/null
[ "$(psql_owner "SELECT version_num FROM alembic_version")" = "$TARGET_HEAD" ] || die "re-upgrade failed"
ok "re-upgraded to ${TARGET_HEAD} (up -> down -> up)"

printf '\n\033[1;32mREHEARSAL PASSED\033[0m — local, disposable, MinIO fixture (NOT DR evidence), webhook receiver + FIXTURE delivery record (NOT a delivery claim); N -> N+1 rolled out through current; keys, manifests and volumes are removed on exit.\n'
