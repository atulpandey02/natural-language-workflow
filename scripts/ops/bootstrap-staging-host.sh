#!/usr/bin/env bash
# Mac-side Stage-1 provisioning for the real-VPS staging host.
#
# Source of truth: docs/ops/vps-provisioning.md (§1.3–§1.9). This automates the
# REMAINING safe Stage-1 work (SSH hardening §1.2 is already done). It runs from
# your Mac and drives the EC2 host over SSH.
#
# Interactive sudo model (nlwops has NO passwordless sudo, by design):
#   1. verify SSH connectivity + read-only target facts (no sudo),
#   2. write a deterministic, idempotent privileged helper to a REMOTE temp file,
#   3. run it once via an interactive TTY:  ssh -t ... 'sudo bash <helper>'
#      — you type the nlwops sudo password ONCE, into your own terminal,
#   4. the helper performs all root-level Stage-1 work,
#   5. the helper is removed afterwards.
# The sudo password is never stored, echoed, piped, put in argv/env/files, or
# logged — it goes straight from your terminal to remote sudo over the SSH TTY.
#
# Firewall safety: `ufw allow 22/tcp` is added BEFORE `ufw --force enable`, and a
# persistent ControlMaster connection (opened before the helper runs, and which
# survives UFW enable because established connections are allowed) is kept as a
# rollback channel. After the helper, a BRAND-NEW connection is tested; if it
# fails, the script offers to `ufw disable` over the still-open master.
#
# Does NOT: modify AWS Security Groups, touch SSH hardening, clone/deploy NLW,
# create .env.prod or any secret, select the off-host backup client, or reboot.
set -euo pipefail

# --- Target: deploy/staging/target.env via the shared lib (override via env) --
# The bootstrap-era address that used to be hard-coded here is retained only in
# docs/staging historical evidence; the instance id is what identifies the host.
# shellcheck source=lib/staging-target.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/staging-target.sh"

CM="${TMPDIR:-/tmp}/nlw-cm-$$.sock"        # ControlMaster socket (short path)
REMOTE_HELPER=""                            # set once created

BASE_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -i "$SSH_KEY")
MUX_OPTS=(-o "ControlPath=$CM" -i "$SSH_KEY")

log()  { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[bootstrap]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[bootstrap] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# Run a NON-privileged command over the persistent master connection.
rssh() { ssh "${MUX_OPTS[@]}" "$TARGET" "$@"; }

cleanup() {
  # Idempotent, best-effort teardown of THIS script's transient artifacts only:
  # the remote temp helper and the local ControlMaster socket. It NEVER rolls
  # back successful provisioning (UFW/Docker/etc. stay as configured); firewall
  # rollback happens only in the explicit fresh-connection-failure branch below.
  local rc=$?
  [ -n "$REMOTE_HELPER" ] && ssh "${MUX_OPTS[@]}" "$TARGET" "rm -f -- '$REMOTE_HELPER'" 2>/dev/null || true
  ssh -O exit -o "ControlPath=$CM" "$TARGET" 2>/dev/null || true
  rm -f "$CM" 2>/dev/null || true
  trap - EXIT INT TERM        # avoid re-entrancy if a signal arrives during cleanup
  return "$rc"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# --- 0. Connectivity + read-only target verification (no sudo) -------------
log "Checking SSH connectivity to ${TARGET} …"
ssh "${BASE_OPTS[@]}" "$TARGET" 'true' \
  || die "cannot SSH to ${TARGET} with key ${SSH_KEY}. Check the host/SG/key."

log "Opening a persistent control connection (rollback channel) …"
ssh -o "ControlMaster=yes" -o "ControlPath=$CM" -o "ControlPersist=300" \
    -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
    -i "$SSH_KEY" -Nf "$TARGET" \
  || die "failed to open the ControlMaster connection."

log "Verifying target facts (Ubuntu 24.04 / x86_64 / ≥2 vCPU / adequate RAM+disk) …"
facts="$(rssh 'set -e
  . /etc/os-release; echo "OS=$VERSION_ID:$ID"
  echo "ARCH=$(uname -m)"
  echo "VCPU=$(nproc)"
  echo "MEM_KB=$(awk "/MemTotal/{print \$2}" /proc/meminfo)"
  echo "DISK_AVAIL_KB=$(df -Pk / | awk "NR==2{print \$4}")"
')"
echo "$facts" | sed 's/^/    /'
os="$(sed -n 's/^OS=//p' <<<"$facts")"
arch="$(sed -n 's/^ARCH=//p' <<<"$facts")"
vcpu="$(sed -n 's/^VCPU=//p' <<<"$facts")"
mem_kb="$(sed -n 's/^MEM_KB=//p' <<<"$facts")"
disk_kb="$(sed -n 's/^DISK_AVAIL_KB=//p' <<<"$facts")"
case "$os" in 24.04:ubuntu) ;; *) die "expected Ubuntu 24.04, got '$os'." ;; esac
[ "$arch" = "x86_64" ] || die "expected x86_64, got '$arch'."
[ "${vcpu:-0}" -ge 2 ] || die "expected ≥2 vCPU, got '${vcpu}'."
[ "${mem_kb:-0}" -ge 3500000 ] || die "insufficient RAM (${mem_kb} kB; want ≥3.5 GiB)."
[ "${disk_kb:-0}" -ge 10000000 ] || die "insufficient free disk on / (${disk_kb} kB; want ≥10 GiB)."
log "Target verification passed."

# --- Privileged helper (deterministic + idempotent; runs as root) ----------
read -r -d '' HELPER_CONTENT <<'HELPER' || true
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
OPERATOR="nlwops"
say() { printf '  [helper] %s\n' "$*"; }
stamp() { date +%Y%m%dT%H%M%SZ; }

[ "$(id -u)" -eq 0 ] || { echo "helper must run as root"; exit 1; }

# 1) Baseline utilities (runbook §0.2). gpg is the backup ENCRYPTION tool; the
#    off-host CLIENT (rclone/awscli) is deferred until the provider is chosen.
say "apt update + baseline utils (ca-certificates curl gnupg ufw)"
apt-get update -y
apt-get install -y ca-certificates curl gnupg ufw

# 2) UFW (runbook §1.3): allow 22 BEFORE enabling; 80/443; IPV6=yes; NO app ports.
if ! grep -q '^IPV6=yes' /etc/default/ufw; then
  cp -a /etc/default/ufw "/etc/default/ufw.nlwbak.$(stamp)"
  sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
  say "set IPV6=yes in /etc/default/ufw"
fi
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp          # BEFORE enable — never lock out SSH
ufw allow 80/tcp
ufw allow 443/tcp
if ! ufw status | grep -q "Status: active"; then
  ufw --force enable
  say "ufw enabled"
else
  say "ufw already active (rules ensured)"
fi

# 3) Docker Engine from the official repo (runbook §1.4), idempotent.
install -m 0755 -d /etc/apt/keyrings
if [ ! -s /etc/apt/keyrings/docker.gpg ]; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  say "installed Docker apt key"
fi
codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
arch="$(dpkg --print-architecture)"
desired_list="deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${codename} stable"
if [ ! -f /etc/apt/sources.list.d/docker.list ] || [ "$(cat /etc/apt/sources.list.d/docker.list)" != "$desired_list" ]; then
  printf '%s\n' "$desired_list" > /etc/apt/sources.list.d/docker.list
  say "wrote /etc/apt/sources.list.d/docker.list"
fi
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

# 4) docker group for the operator (takes effect on next login).
if ! id -nG "$OPERATOR" | tr ' ' '\n' | grep -qx docker; then
  usermod -aG docker "$OPERATOR"
  say "added $OPERATOR to docker group (re-login required to take effect)"
fi

# 5) Docker log rotation / disk controls (runbook §1.8). We manage ONLY these
#    three keys. Absent -> create; already-equal -> no-op; differs but only OUR
#    keys -> back up + update; contains UNRELATED keys (or invalid JSON) -> back
#    up and STOP for operator review (never silently replace foreign config).
DAEMON=/etc/docker/daemon.json
DESIRED_JSON='{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "5" },
  "live-restore": true
}'
mkdir -p /etc/docker
write_desired() { printf '%s\n' "$DESIRED_JSON" > "$DAEMON"; python3 -c 'import json;json.load(open("/etc/docker/daemon.json"))'; }
if [ ! -f "$DAEMON" ]; then
  write_desired
  systemctl restart docker
  say "created /etc/docker/daemon.json (log rotation + live-restore)"
else
  cls="$(python3 - "$DAEMON" <<'PY'
import json, sys
desired = {"log-driver": "json-file",
           "log-opts": {"max-size": "10m", "max-file": "5"},
           "live-restore": True}
managed = set(desired)
try:
    cur = json.load(open(sys.argv[1]))
except Exception:
    print("INVALID"); sys.exit(0)
if not isinstance(cur, dict):
    print("INVALID")
elif cur == desired:
    print("SAME")
elif set(cur) <= managed:
    print("MANAGED_DIFF")
else:
    print("UNRELATED:" + ",".join(sorted(set(cur) - managed)))
PY
)"
  case "$cls" in
    SAME)
      say "/etc/docker/daemon.json already current" ;;
    MANAGED_DIFF)
      cp -a "$DAEMON" "${DAEMON}.nlwbak.$(stamp)"
      write_desired
      systemctl restart docker
      say "updated managed /etc/docker/daemon.json (previous backed up)" ;;
    INVALID)
      cp -a "$DAEMON" "${DAEMON}.nlwbak.$(stamp)"
      echo "STOP: existing /etc/docker/daemon.json is not valid JSON. Backed up to ${DAEMON}.nlwbak.* — review manually. Not modifying." >&2
      exit 3 ;;
    UNRELATED:*)
      cp -a "$DAEMON" "${DAEMON}.nlwbak.$(stamp)"
      echo "STOP: /etc/docker/daemon.json has UNRELATED keys: ${cls#UNRELATED:}. Backed up to ${DAEMON}.nlwbak.* — merge the approved log-rotation/live-restore settings by hand, then re-run. Not replacing foreign config." >&2
      exit 3 ;;
    *)
      echo "STOP: could not classify /etc/docker/daemon.json ('$cls')." >&2
      exit 3 ;;
  esac
fi

# 6) Unattended security updates ON, automatic reboot OFF (runbook §1.5).
apt-get install -y unattended-upgrades
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat > /etc/apt/apt.conf.d/51nlw-no-auto-reboot <<'EOF'
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
EOF
systemctl enable --now unattended-upgrades
say "unattended-upgrades enabled; automatic reboot disabled"

# 7) Time synchronization (runbook §1.6).
timedatectl set-ntp true || true
say "requested NTP time sync"

# 8) Application directory layout (runbook §1.9). No repo clone, no secrets.
install -d -m 750 -o "$OPERATOR" -g "$OPERATOR" /opt/nlw
install -d -m 750 -o "$OPERATOR" -g "$OPERATOR" /opt/nlw/app
install -d -m 700 -o "$OPERATOR" -g "$OPERATOR" /opt/nlw/backups
install -d -m 750 -o "$OPERATOR" -g "$OPERATOR" /opt/nlw/logs
say "/opt/nlw layout ensured (app 750, backups 700, logs 750; owner $OPERATOR)"

# Report (do NOT reboot) if a kernel/lib update wants one.
if [ -f /var/run/reboot-required ]; then
  say "NOTE: a reboot is PENDING — NOT rebooting (operator handles it in the reboot drill)."
fi
say "privileged Stage-1 helper complete."
HELPER

# --- Ship + run the helper via ONE interactive sudo TTY ---------------------
log "Uploading the privileged helper to a remote temp file …"
REMOTE_HELPER="$(rssh 'mktemp /tmp/nlw-bootstrap-helper.XXXXXX.sh')" \
  || die "failed to create the remote temp helper."
printf '%s\n' "$HELPER_CONTENT" | rssh "cat > '$REMOTE_HELPER' && chmod 700 '$REMOTE_HELPER'" \
  || die "failed to upload the remote helper."

log "Running Stage-1 as root. You will be prompted for the nlwops sudo password ONCE."
log "(The password goes straight to remote sudo; it is never captured by this script.)"
ssh -t -o "ControlPath=$CM" -i "$SSH_KEY" "$TARGET" "sudo bash '$REMOTE_HELPER'" \
  || die "the privileged helper failed. Review the output above; the host is unchanged past the last successful step. Re-run is safe (idempotent)."

# --- Firewall verification: a BRAND-NEW connection must succeed -------------
log "Verifying SSH still works over a brand-new connection (post-UFW) …"
if ssh -o "ControlMaster=no" -o "ControlPath=none" -o BatchMode=yes \
       -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -i "$SSH_KEY" \
       "$TARGET" 'echo FRESH_CONN_OK' | grep -q FRESH_CONN_OK; then
  log "New SSH connection OK — firewall is safe."
else
  warn "A NEW SSH connection FAILED after enabling UFW."
  warn "The persistent control channel is still open; attempting rollback (ufw disable)."
  warn "You may be prompted for the nlwops sudo password again."
  if ssh -t -o "ControlPath=$CM" -i "$SSH_KEY" "$TARGET" 'sudo ufw disable'; then
    die "UFW disabled to restore access. Investigate the 22/tcp rule before retrying. Host is otherwise provisioned."
  fi
  die "Rollback could not be completed automatically. Do NOT close existing sessions. Recover via the EC2 Serial Console (Instance → Connect → EC2 Serial Console) and run 'sudo ufw disable'. Do not modify the Security Group unless intended."
fi

log "Bootstrap complete. Run scripts/ops/verify-staging-host.sh next."
log "NOTE: docker group membership for nlwops takes effect on your NEXT login."
