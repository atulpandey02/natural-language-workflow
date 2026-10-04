#!/usr/bin/env bash
# Staging-validation (CI only): prove the backup-freshness monitoring chain end
# to end on the THROWAWAY runner stack (ADR-022 amendment 1):
#
#   real `backup` service -> real metrics writer -> backup_textfile volume
#   -> hardened node-exporter -> Prometheus target `nlw-backup`
#   -> nlw_backup_last_success_timestamp_seconds -> NlwBackupStale loaded, not firing
#
# The restic repository is LOCAL and EPHEMERAL (inside the stack's throwaway
# `backup_run` volume): this proves the metrics/alert chain, NOT S3 transport or
# off-host durability (staging verifies those with its real repository). The
# repository value is allowlisted to `local:` + one in-container path; nothing
# leaves the runner, no port is opened, and generated values are masked and
# never printed.
set -euo pipefail

read -r -a DC <<< "${COMPOSE:?COMPOSE must be set}"
EXPECTED_IMAGE="${EXPECTED_NODE_EXPORTER_IMAGE:-prom/node-exporter:v1.12.1}"
REPO="local:/run/nlw/ci-restic-repository"
FRESH_S="${EVIDENCE_FRESH_SECONDS:-900}"
BACKUP_CONTAINER="nlw-ci-backup-evidence-$$"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"

fail() { echo "EVIDENCE FAIL: $*" >&2; exit 1; }
ok() { echo "  [ok] $*"; echo "- $*" >> "$SUMMARY"; }

cleanup() {
  docker rm -f "$BACKUP_CONTAINER" >/dev/null 2>&1 || true
  unset RESTIC_REPOSITORY RESTIC_PASSWORD BACKUP_AWS_ACCESS_KEY_ID \
    BACKUP_AWS_SECRET_ACCESS_KEY NLW_BACKUP_DATABASE_URL
}
trap cleanup EXIT

# --- repository allowlist: local + in-container only ------------------------------
case "$REPO" in
  local:/run/nlw/ci-restic-repository) ;;
  *) fail "repository is not the allowlisted local path" ;;
esac
for forbidden in "s3:" "http://" "https://" "32.197.83.193" "nlwplatform.com" "amazonaws.com"; do
  case "$REPO" in *"$forbidden"*) fail "repository references a forbidden backend" ;; esac
done

# --- throwaway credentials (masked before use, never printed) ----------------------
rand() { openssl rand -hex "$1"; }
RESTIC_PASSWORD="ci-restic-$(rand 24)"
BACKUP_AWS_ACCESS_KEY_ID="ci-unused-$(rand 8)"      # presence-validated only; local repo
BACKUP_AWS_SECRET_ACCESS_KEY="ci-unused-$(rand 24)" # never used for network access
if [ -n "${GITHUB_ACTIONS:-}" ]; then
  for v in "$RESTIC_PASSWORD" "$BACKUP_AWS_ACCESS_KEY_ID" "$BACKUP_AWS_SECRET_ACCESS_KEY" \
    "${POSTGRES_PASSWORD:?}"; do echo "::add-mask::$v"; done
fi
export RESTIC_REPOSITORY="$REPO" RESTIC_PASSWORD BACKUP_AWS_ACCESS_KEY_ID \
  BACKUP_AWS_SECRET_ACCESS_KEY BACKUP_AWS_REGION=us-east-1
export NLW_BACKUP_DATABASE_URL="postgresql://nlw:${POSTGRES_PASSWORD:?}@postgres:5432/nlw"
export NLW_BACKUP_ENVIRONMENT=staging-validation NLW_BACKUP_SOURCE_INSTANCE_ID=ci-runner \
  NLW_BACKUP_SOURCE_RELEASE="${GITHUB_SHA:-local}"

echo "## Backup metric ingestion evidence" >> "$SUMMARY"
echo "Repository: local, ephemeral (throwaway \`backup_run\` volume) - proves the metrics/alert chain, not S3 transport." >> "$SUMMARY"

cid() { "${DC[@]}" ps -q "$1" | head -1; }
NE="$(cid node-exporter)"; PROM="$(cid prometheus)"
if [ -z "$NE" ] || [ -z "$PROM" ]; then fail "node-exporter and prometheus must be running"; fi

# --- (1) the REAL backup service writes the evidence --------------------------------
"${DC[@]}" --profile backup build backup >/dev/null
started=$(date +%s)
if ! "${DC[@]}" --profile backup run --name "$BACKUP_CONTAINER" backup >/dev/null 2>&1; then
  fail "the real backup service did not succeed (exit $(docker inspect -f '{{.State.ExitCode}}' "$BACKUP_CONTAINER" 2>/dev/null || echo '?'))"
fi
[ "$(docker inspect -f '{{.State.ExitCode}}' "$BACKUP_CONTAINER")" = "0" ] || fail "backup exit code"
writer=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/textfile"}}{{.Type}} {{.Name}} {{.RW}}{{end}}{{end}}' "$BACKUP_CONTAINER")
case "$writer" in volume\ *_backup_textfile\ true) ;; *) fail "backup is not the read-write writer of backup_textfile" ;; esac
TEXTFILE_VOLUME=$(echo "$writer" | awk '{print $2}')
ok "real backup service succeeded and wrote ${TEXTFILE_VOLUME} read-write (local ephemeral repository)"
docker rm -f "$BACKUP_CONTAINER" >/dev/null

FILE=$(docker exec "$NE" cat /textfile/nlw_backup.prom) || fail "node-exporter cannot read the textfile"
for m in nlw_backup_success nlw_backup_duration_seconds nlw_backup_repository_verify_success \
  nlw_backup_retention_success nlw_backup_last_success_timestamp_seconds; do
  echo "$FILE" | grep -qE "^${m} " || fail "metrics file lacks ${m}"
done
echo "$FILE" | grep -qE '^nlw_backup_success 1$' || fail "backup did not report success"
echo "$FILE" | grep -qE '^nlw_backup_repository_verify_success 1$' || fail "repository not verified"
FILE_TS=$(echo "$FILE" | awk '/^nlw_backup_last_success_timestamp_seconds /{print $2}')
python3 -c "import sys; t=float('$FILE_TS'); sys.exit(0 if t >= $started - 5 else 1)" \
  || fail "last-success timestamp did not advance for this run"
ok "metrics file: success 1, repository verified 1, fresh last-success timestamp"

# --- (2) the RUNNING exporter is hardened exactly as reviewed ------------------------
docker inspect "$NE" | python3 -c '
import json, sys
c = json.load(sys.stdin)[0]; hc = c["HostConfig"]; cfg = c["Config"]
want_image, volume = sys.argv[1], sys.argv[2]
problems = []
if cfg["Image"] != want_image: problems.append("image %s" % cfg["Image"])
if cfg.get("User") != "65534:65534": problems.append("user")
if hc.get("ReadonlyRootfs") is not True: problems.append("rootfs not read-only")
if [x.upper() for x in (hc.get("CapDrop") or [])] != ["ALL"] or hc.get("CapAdd"): problems.append("capabilities")
if "no-new-privileges:true" not in (hc.get("SecurityOpt") or []): problems.append("no-new-privileges")
if hc.get("Privileged"): problems.append("privileged")
if any(v for v in (hc.get("PortBindings") or {}).values()): problems.append("published port")
if any(v for v in (c["NetworkSettings"].get("Ports") or {}).values()): problems.append("host port mapped")
mounts = c["Mounts"]
if [(m["Type"], m.get("Name"), m["Destination"], m["RW"]) for m in mounts] != [("volume", volume, "/textfile", False)]:
    problems.append("mounts %s" % [(m["Type"], m["Destination"], m["RW"]) for m in mounts])
nets = list(c["NetworkSettings"]["Networks"])
if len(nets) != 1 or not nets[0].endswith("_internal"): problems.append("networks %s" % nets)
args = c.get("Args") or []
collectors = sorted(a for a in args if a.startswith("--collector.") and "." not in a[len("--collector."):])
if "--collector.disable-defaults" not in args or collectors != ["--collector.disable-defaults", "--collector.textfile"]:
    problems.append("collectors %s" % collectors)
if "--collector.textfile.directory=/textfile" not in args: problems.append("textfile directory")
if problems:
    print("hardening violations:", "; ".join(problems)); sys.exit(1)
' "$EXPECTED_IMAGE" "$TEXTFILE_VOLUME" || fail "node-exporter runtime hardening"
ok "node-exporter ${EXPECTED_IMAGE}: uid 65534, read-only rootfs, cap_drop ALL, no-new-privileges, no published port, only ${TEXTFILE_VOLUME}:/textfile read-only, internal network only, textfile collector only"

# --- (3) exporter serves it (inside the throwaway network) ---------------------------
METRICS=$(docker exec "$NE" wget -qO- http://127.0.0.1:9100/metrics) || fail "exporter HTTP"
echo "$METRICS" | grep -qE '^node_textfile_scrape_error 0$' || fail "textfile scrape error"
for m in nlw_backup_success nlw_backup_duration_seconds nlw_backup_repository_verify_success \
  nlw_backup_retention_success nlw_backup_last_success_timestamp_seconds; do
  echo "$METRICS" | grep -qE "^${m} " || fail "exporter does not serve ${m}"
done
if echo "$METRICS" | grep -qE '^node_(cpu|filesystem|memory|network)_'; then fail "host collectors exposed"; fi
ok "exporter: HTTP OK, node_textfile_scrape_error 0, all 5 nlw_backup_* series, no host collectors"

# --- (4) Prometheus: target, series, rule, alert (bounded retries) ---------------------
api() { docker exec "$PROM" wget -qO- "http://127.0.0.1:9090/api/v1/$1"; }
QUERY='nlw_backup_last_success_timestamp_seconds%7Bjob%3D%22nlw-backup%22%2Crole%3D%22backup%22%7D'
check_prom() {
  python3 - "$FILE_TS" "$FRESH_S" "$(api targets)" "$(api "query?query=${QUERY}")" "$(api rules)" "$(api alerts)" <<'PY'
import json, sys, time
file_ts, fresh_s = float(sys.argv[1]), float(sys.argv[2])
targets, query, rules, alerts = (json.loads(a) for a in sys.argv[3:7])
backup = [t for t in targets["data"]["activeTargets"] if t["labels"].get("job") == "nlw-backup"]
assert len(backup) == 1, "nlw-backup target count %d" % len(backup)
t = backup[0]
assert t["labels"]["instance"] == "node-exporter:9100", t["labels"]["instance"]
assert t["health"] == "up" and t["lastError"] == "", (t["health"], t["lastError"])
series = query["data"]["result"]
assert len(series) == 1, "series count %d" % len(series)
assert series[0]["metric"].get("job") == "nlw-backup" and series[0]["metric"].get("role") == "backup"
value = float(series[0]["value"][1])
assert abs(value - file_ts) <= 1, "prometheus %s != file %s" % (value, file_ts)
assert time.time() - value <= fresh_s, "timestamp not fresh"
stale = [r for g in rules["data"]["groups"] for r in g["rules"] if r.get("name") == "NlwBackupStale"]
assert len(stale) == 1, "NlwBackupStale loaded %d times" % len(stale)
q = stale[0]["query"]
assert "26 * 3600" in q and "absent(nlw_backup_last_success_timestamp_seconds)" in q, q
assert stale[0].get("duration") == 900, stale[0].get("duration")
firing = [a for a in alerts["data"]["alerts"]
          if a["labels"].get("alertname") == "NlwBackupStale" and a["state"] == "firing"]
assert not firing, "NlwBackupStale is firing"
state = stale[0].get("state")
print("target=up series=1 ts_match=%ss rule_state=%s" % (abs(value - file_ts), state))
PY
}
for i in $(seq 1 18); do
  if out=$(check_prom 2>&1); then break; fi
  [ "$i" -eq 18 ] && { echo "$out" | tail -3 >&2; fail "Prometheus evidence not satisfied within 180s"; }
  sleep 10
done
ok "Prometheus: job nlw-backup -> node-exporter:9100 up, lastError empty; ${out}"
ok "NlwBackupStale loaded (26h stale OR absent(...), for 15m) and not firing for fresh evidence"
echo "backup metric ingestion evidence: PASS"
