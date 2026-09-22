#!/usr/bin/env bash
# DISPOSABLE upgrade rehearsal: M11 runtime + schema 0010  ->  P3B runtime + schema 0016
# (M12A-Prep §N). Everything is local and thrown away; NOTHING touches a real host,
# a real backup provider, or production keys.
#
# What it mirrors (in this order — the same phases the real rollout runs):
#   1  a Postgres that was bootstrapped by the M11 role script (5 roles) and
#      migrated to 0010 by the M11 image (built from the pinned commit);
#   2  representative disposable data (user/workspace/membership, workflow,
#      terminal run, pending approval, invitation) under the OLD unsigned model;
#   3  the OLD runtimes serving (api/worker/scheduler/web/caddy);
#   4  the P2 encrypted backup path against a MinIO FIXTURE (labelled; the
#      production gate rejects it — the rollout is told --allow-fixture-repository);
#   5  `python -m nlw.ops.rollout --local` phases: preflight, prepare-roles,
#      prepare-keys (0700/0400, uid 10001 — container view), verify-escrow (this
#      script plays the operator and writes the attestation from fingerprints),
#      verify-backup, drain, migrate (0010->0016 with the NEW image), install keys,
#      recreate runtime, validate (signed_context readiness, unsigned forgery
#      denied, mounts), reopen;
#   6  post-upgrade proofs: invitation accept + four-eyes approval under signed
#      contexts, a worker-executed synthetic run, one scheduler occurrence,
#      Prometheus rule groups loaded;
#   7  a SEPARATE disposable downgrade 0016 -> 0015 proving the legacy policies
#      come back (documented rollback warning), then cleanup of keys + volumes.
#
# Requires: docker (Desktop/Engine), uv, git. Takes ~10-15 minutes (two backend
# builds + one web build).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

OLD_SHA="5151a2cc54cfb63b276bd3b30cf0e683263525ac"   # the M11 pin the staging host runs
TS="$(date +%Y%m%d%H%M%S)"
PROJ="nlwrehearsal${TS}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/${PROJ}.XXXXXX")"
chmod 700 "$TMP"
APP="$TMP/app"; OLD="$TMP/old"; KEYS_PARENT="$TMP/keys"; KEYS="$KEYS_PARENT/ctx-keys"
REG="127.0.0.1:5000"; REGNAME="${PROJ}-registry"
AUTH="AUTHORIZE_M12A_SIGNED_CONTEXT_STAGING_DEPLOYMENT"
ESC="SIGNED_CONTEXT_KEYS_ESCROWED_AND_RECOVERY_TESTED"
ROLLOUT=(uv run python -m nlw.ops.rollout --local --release "$TMP/release.json" --target "$TMP/target.env" --keys-dir "$KEYS")

log() { printf '\n\033[1;34m=== %s ===\033[0m\n' "$*"; }
ok()  { printf '  \033[1;32m[ok]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mREHEARSAL FAIL:\033[0m %s\n' "$*" >&2; exit 1; }
DC="docker compose --env-file $APP/.env.prod -f $APP/docker-compose.prod.yml -f $APP/docker-compose.staging.yml -f $TMP/docker-compose.rehearsal.yml"
psql_owner() { $DC exec -T postgres psql -U nlw -d nlw -tAc "$1" | tr -d '[:space:]'; }

cleanup() {
  log "cleanup (${PROJ}) — keys, volumes, worktrees, registry"
  $DC down -v --remove-orphans >/dev/null 2>&1 || true
  docker rm -f "$REGNAME" >/dev/null 2>&1 || true
  docker run --rm --user 0:0 -v "$KEYS_PARENT:/k" alpine:3.20 sh -c 'rm -rf /k/ctx-keys' >/dev/null 2>&1 || true
  git -C "$REPO" worktree remove --force "$OLD" >/dev/null 2>&1 || true
  git -C "$SRC" worktree remove --force "$APP" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

log "1/9 local throwaway registry (digest-pinned images, like GHCR)"
docker run -d --rm --name "$REGNAME" -p "${REG}:5000" registry:2 >/dev/null
sleep 2

log "2/9 build + push images: OLD backend (${OLD_SHA:0:7}), NEW backend + web (HEAD), backup"
git worktree add -q --detach "$OLD" "$OLD_SHA"
# The NEW side is the WORKING TREE (including uncommitted changes under review):
# it is committed into a THROWAWAY clone so the rollout can `git checkout` a real
# release SHA, exactly as it will on the host (pin-release phase). The app dir is
# a worktree of that clone at the OLD pin — old compose files, old Caddyfile —
# again exactly like /opt/nlw/app today.
SRC="$TMP/src"
git clone -q "$REPO" "$SRC"
rsync -a --exclude .git --exclude .venv --exclude node_modules --exclude "web/.next" \
  --exclude "docker/ctx-keys" --exclude ".env*" --exclude "/supabase/" --exclude ".rollout" "$REPO/" "$SRC/"
git -C "$SRC" add -A >/dev/null && git -C "$SRC" -c user.name=rehearsal -c user.email=r@localhost commit -q -m "rehearsal snapshot" --allow-empty
NEW_SHA="$(git -C "$SRC" rev-parse HEAD)"
git -C "$SRC" worktree add -q --detach "$APP" "$OLD_SHA"
cp "$SRC/docker-compose.rehearsal.yml" "$TMP/docker-compose.rehearsal.yml"
docker build -q -t "$REG/nlw:old" "$OLD" >/dev/null
docker build -q -t "$REG/nlw:new" "$SRC" >/dev/null
docker build -q -t "$REG/nlw-web:new" "$SRC/web" >/dev/null
docker build -q -t "$REG/nlw-backup:new" -f "$SRC/docker/backup/Dockerfile" --build-arg "NLW_IMAGE=$REG/nlw:new" "$SRC" >/dev/null
for t in nlw:old nlw:new nlw-web:new nlw-backup:new; do docker push -q "$REG/$t" >/dev/null; done
digest() { docker inspect --format '{{index .RepoDigests 0}}' "$REG/$1"; }
OLD_BACKEND="$(digest nlw:old)"; NEW_BACKEND="$(digest nlw:new)"; NEW_WEB="$(digest nlw-web:new)"
ok "old backend  $OLD_BACKEND"; ok "new backend  $NEW_BACKEND"; ok "new web      $NEW_WEB"

log "3/9 app dir mirroring the VPS: M11 role bootstrap, .env.prod (old pins), backup env"
# The VPS Postgres was initialised by the M11 role script (5 roles) — reproduce that.
git show "$OLD_SHA:docker/postgres/initdb/00-roles.sh" > "$APP/docker/postgres/initdb/00-roles.sh"
pw() { openssl rand -hex 32; }
PGPW="$(pw)"; APPPW="$(pw)"; WPW="$(pw)"; SPW="$(pw)"
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
NLW_BACKUP_IMAGE=$REG/nlw-backup:new
PUBLIC_HOSTNAME=rehearsal.localhost
WORKSPACE_COOKIE_SECRET=$(pw)
SUPABASE_URL=https://proj.supabase.co
SUPABASE_ANON_KEY=sb_publishable_rehearsal
SUPABASE_JWKS_URL=https://proj.supabase.co/auth/v1/.well-known/jwks.json
SUPABASE_JWT_ISSUER=https://proj.supabase.co/auth/v1
EOF
cat > "$TMP/.env.backup" <<EOF
APP_ENV=local
RESTIC_REPOSITORY=s3:http://minio:9000/rehearsal-fixture/nlw
RESTIC_PASSWORD=$(pw)
BACKUP_AWS_ACCESS_KEY_ID=rehearsal-fixture
BACKUP_AWS_SECRET_ACCESS_KEY=rehearsal-fixture-not-a-secret
BACKUP_AWS_REGION=us-east-1
NLW_BACKUP_DATABASE_URL=postgresql://nlw:$PGPW@postgres:5432/nlw
EOF
cat > "$TMP/target.env" <<EOF
NLW_STAGING_INSTANCE_ID=i-0000000000000001
NLW_STAGING_REGION=us-east-1
NLW_STAGING_SSH_HOST=127.0.0.1
NLW_STAGING_SSH_USER=nobody
NLW_STAGING_PUBLIC_HOSTNAME=rehearsal.localhost
NLW_STAGING_REMOTE_APP=$APP
NLW_STAGING_COMPOSE_PROJECT=$PROJ
NLW_STAGING_COMPOSE_FILES=docker-compose.prod.yml docker-compose.staging.yml $TMP/docker-compose.rehearsal.yml
NLW_STAGING_BACKUP_ENV_FILE=$TMP/.env.backup
EOF
cat > "$TMP/release.json" <<EOF
{"format_version": 1, "environment": "staging",
 "release_sha": "$NEW_SHA",
 "backend_image": "$NEW_BACKEND", "web_image": "$NEW_WEB",
 "expected_current_revision": "0010_readiness_schema_grant",
 "target_revision": "0016_signed_database_context",
 "instance_id": "i-0000000000000001", "region": "us-east-1",
 "compose_project": "$PROJ", "public_hostname": "rehearsal.localhost",
 "key_ids": {"api": "rehearsal-api", "worker": "rehearsal-worker", "scheduler": "rehearsal-scheduler"}}
EOF
umask 022
mkdir -p "$KEYS_PARENT"
# The rollout reads host identity from IMDS on a real target; the LOCAL executor
# answers with this canned identity instead (see nlw.ops.rollout.remote).
export NLW_REHEARSAL_IDENTITY="instance-id=i-0000000000000001
placement/region=us-east-1
public-ipv4=127.0.0.1"

log "4/9 OLD stack: datastores -> migrate to 0010 with the M11 image -> old runtimes -> seed"
$DC up -d postgres redis minio >/dev/null
for _ in $(seq 1 60); do $DC exec -T postgres pg_isready -U nlw -d nlw >/dev/null 2>&1 && break; sleep 2; done
# M11 had no migrate profile: migrations ran through the api image (which then
# still received the owner credential) — reproduce that exactly.
$DC run --rm -T api alembic upgrade head >/dev/null
[ "$(psql_owner "SELECT version_num FROM alembic_version")" = "0010_readiness_schema_grant" ] || die "old image did not migrate to 0010"
[ "$(psql_owner "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'nlw\\_%'")" = "5" ] || die "expected the 5 M11 roles"
ok "schema 0010, 5 M11 roles (no membership_admin / ctx_verifier) — same as the VPS"
$DC up -d api worker scheduler web caddy prometheus >/dev/null  # M11 overlay: no alertmanager yet
for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:8000/health/ready >/dev/null 2>&1 && break; sleep 2; done
curl -fsS http://127.0.0.1:8000/health/ready | grep -q '"status":"ready"' || die "old runtime not ready"
ok "OLD runtime (pre-P3B) is serving"
# Representative disposable data (owner): user A owns a workspace; a terminal run.
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

log "5/9 ROLLOUT phases (--local): preflight -> prepare-keys"
"${ROLLOUT[@]}" preflight
"${ROLLOUT[@]}" prepare-keys --authorize "$AUTH"
# The OPERATOR writes the escrow attestation after copying the files off-host.
# Here the rehearsal plays the operator: fingerprints only, never material.
FPS="$(docker run --rm --user 0:0 --network none -v "$KEYS:/keys:ro" "$NEW_BACKEND" python -m nlw.ctxkeys fingerprint --dir /keys --key-id-api rehearsal-api --key-id-worker rehearsal-worker --key-id-scheduler rehearsal-scheduler --owner 10001)"
# Host-side ownership: on Linux the 0400/uid-10001 files are unreadable to the
# rehearsal user. Docker Desktop (macOS) maps bind-mount ownership to the host
# user, so only the CONTAINER view (verified by prepare-keys/fingerprint) applies.
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
log "6/9 pin-release (checkout release + pins) -> P2 backup of the PRE-UPGRADE db into the MinIO FIXTURE (NOT DR evidence)"
"${ROLLOUT[@]}" pin-release --authorize "$AUTH"
[ "$(git -C "$APP" rev-parse HEAD)" = "$NEW_SHA" ] || die "app dir not at the release SHA after pin-release"
"${ROLLOUT[@]}" prepare-roles --authorize "$AUTH"
[ "$(psql_owner "SELECT count(*) FROM pg_roles WHERE rolname IN ('nlw_membership_admin','nlw_ctx_verifier')")" = "2" ] || die "roles not provisioned"
docker compose --env-file "$APP/.env.prod" --env-file "$TMP/.env.backup" -f "$APP/docker-compose.prod.yml" -f "$TMP/docker-compose.rehearsal.yml" --profile backup run --rm -T backup >/dev/null
ok "backup job completed against the fixture (snapshot tagged rev-0010)"
"${ROLLOUT[@]}" verify-backup --authorize "$AUTH" --allow-fixture-repository
# Negative: without the rehearsal switch the fixture repository is REFUSED.
if "${ROLLOUT[@]}" verify-backup --authorize "$AUTH" 2>/dev/null; then die "fixture backup must be refused without --allow-fixture-repository"; fi
ok "backup gate refuses the MinIO fixture unless explicitly allowed (rehearsal only)"

log "7/9 drain -> migrate 0010->0016 (NEW image) -> install keys -> recreate -> validate -> reopen"
"${ROLLOUT[@]}" drain --authorize "$AUTH"
curl -sS -o /dev/null -w '%{http_code}' -k --resolve rehearsal.localhost:8443:127.0.0.1 https://rehearsal.localhost:8443/login | grep -q '^503$' && ok "maintenance mode: edge serves 503" || die "maintenance 503 not served"
"${ROLLOUT[@]}" migrate --authorize "$AUTH"
[ "$(psql_owner "SELECT version_num FROM alembic_version")" = "0016_signed_database_context" ] || die "not at 0016"
[ "$(psql_owner "SELECT count(*) FROM pg_policies")" = "51" ] || die "policy count != 51"
ok "schema 0016; 51 signed policies"
"${ROLLOUT[@]}" install-context-keys --authorize "$AUTH"
"${ROLLOUT[@]}" recreate-runtime --authorize "$AUTH"
"${ROLLOUT[@]}" validate --authorize "$AUTH"
"${ROLLOUT[@]}" reopen --authorize "$AUTH"
curl -fsS http://127.0.0.1:8000/health/ready | grep -q '"signed_context":"ok"' || die "signed_context not ok"
ok "NEW runtime ready with signed_context: ok; traffic reopened"

log "8/9 post-upgrade proofs: invitation + four-eyes (signed), worker run, scheduler occurrence, rules"
APPR=$(uuidgen | tr A-F a-f); RUN2=$(uuidgen | tr A-F a-f); TOKEN="$(openssl rand -hex 24)"
TOKEN_HASH="$(printf '%s' "$TOKEN" | shasum -a 256 | cut -d' ' -f1)"
$DC exec -T postgres psql -U nlw -d nlw -q <<EOF
INSERT INTO workflow_runs (id, tenant_id, workflow_id, workflow_version_id, status, initiated_by_user_id) VALUES ('$RUN2','$WS','$WF','$VER','WAITING_APPROVAL','$UA');
INSERT INTO approvals (id, tenant_id, run_id, step_id, connector_id, connector_name, tool, status, requested_by_user_id) VALUES ('$APPR','$WS','$RUN2','a',gen_random_uuid(),'hook','webhook.send','pending','$UA');
INSERT INTO workspace_invitations (id, tenant_id, email, role, invited_by, token_hash, status, expires_at) VALUES (gen_random_uuid(),'$WS','b@rehearsal.test','admin','$UA','$TOKEN_HASH','pending',now() + interval '1 day');
EOF
printf '%s\n' "$TOKEN" | $DC exec -T api python -m nlw.ops.rollout.smoke --workspace "$WS" --user-a "$UA" --user-b "$UB" --approval "$APPR" --invitation-token-stdin
ok "unsigned forgery denied; signed context scoped; invitation accepted; self-approval blocked; four-eyes approval ok"
# Worker executes a brand-new connector-free run under worker_execution context.
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
ok "prometheus rule groups loaded (nlw-backup, nlw-signed-context); alertmanager healthy"

log "9/9 SEPARATE disposable downgrade 0016 -> 0015: legacy policies return (documented rollback warning)"
$DC stop api worker scheduler >/dev/null
$DC --profile migration run --rm -T migrate sh -c 'alembic downgrade 0015_membership_approval_sod' >/dev/null
LEGACY="$(psql_owner "SELECT count(*) FROM pg_policies WHERE qual LIKE '%app.user_id%' OR qual LIKE '%app.tenant_id%' OR with_check LIKE '%app.user_id%' OR with_check LIKE '%app.tenant_id%'")"
[ "$LEGACY" -gt 0 ] || die "downgrade did not restore legacy policies"
ok "downgrade re-installs $LEGACY legacy unsigned-GUC policies — exactly why downgrade below 0016 is security-sensitive"
$DC --profile migration run --rm -T migrate >/dev/null
[ "$(psql_owner "SELECT version_num FROM alembic_version")" = "0016_signed_database_context" ] || die "re-upgrade failed"
ok "re-upgraded to 0016 (up -> down -> up)"

printf '\n\033[1;32mREHEARSAL PASSED\033[0m — local, disposable, MinIO fixture (NOT DR evidence); keys and volumes are removed on exit.\n'
