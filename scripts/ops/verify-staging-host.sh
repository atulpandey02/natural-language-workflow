#!/usr/bin/env bash
# Mac-side READ-ONLY verification of the staging host against the approved
# runbook (docs/ops/vps-provisioning.md, Stage-1 acceptance checklist).
#
# It changes NOTHING on the host. Most checks are unprivileged; the effective
# sshd config and UFW status need root, so ONE interactive `sudo` read (no temp
# file, read-only commands) is used for those — you enter the nlwops sudo
# password once. The password is never stored, echoed, piped, or logged.
#
# Exits non-zero if any check FLAGs — including any of the ports
# 3000/8000/5432/6379/9090 listening on a non-loopback (public) address.
set -euo pipefail

# Host identity comes from deploy/staging/target.env (one reviewed source; the
# EC2 instance id is authoritative — see scripts/ops/lib/staging-target.sh).
# shellcheck source=lib/staging-target.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/staging-target.sh"
BASE_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -i "$SSH_KEY")

FLAGS=0
ok()   { printf '  \033[1;32m[ OK ]\033[0m %s\n' "$*"; }
flag() { printf '  \033[1;31m[FLAG]\033[0m %s\n' "$*"; FLAGS=$((FLAGS+1)); }
info() { printf '  \033[1;34m[info]\033[0m %s\n' "$*"; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

command -v ssh >/dev/null || { echo "ssh not found"; exit 2; }
ssh "${BASE_OPTS[@]}" "$TARGET" 'true' || { echo "cannot SSH to $TARGET"; exit 2; }
# The connected host must BE the expected instance (IMDSv2), whatever address
# reached it. Fail closed before reading anything else.
_ident="$(ssh "${BASE_OPTS[@]}" "$TARGET" "$(staging_remote_identity_cmd)" 2>/dev/null | tr -d '\r')"
staging_assert_instance "$_ident" || exit 2

# --- Unprivileged snapshot (single round-trip; no sudo) --------------------
U="$(ssh "${BASE_OPTS[@]}" "$TARGET" 'set -e
  . /etc/os-release; echo "OS=$PRETTY_NAME"
  echo "ARCH=$(uname -m)"
  echo "VCPU=$(nproc)"
  echo "MEM=$(free -h | awk "/Mem:/{print \$2}")"
  echo "DISK=$(df -h / | awk "NR==2{print \$4\" free of \"\$2}")"
  echo "IPV4=$(ip -4 -o addr show scope global | awk "{print \$4}" | paste -sd, -)"
  echo "IPV6=$(ip -6 -o addr show scope global | awk "{print \$4}" | paste -sd, -)"
  echo "DOCKER=$(docker --version 2>/dev/null || echo missing)"
  echo "COMPOSE=$(docker compose version --short 2>/dev/null || echo missing)"
  echo "DOCKER_ENABLED=$(systemctl is-enabled docker 2>/dev/null || echo unknown)"
  echo "DOCKER_ACTIVE=$(systemctl is-active docker 2>/dev/null || echo unknown)"
  echo "UU_PERIODIC=$(apt-config dump 2>/dev/null | sed -n "s/.*APT::Periodic::Unattended-Upgrade \"\(.*\)\";/\1/p" | head -1)"
  echo "UU_REBOOT=$(apt-config dump 2>/dev/null | sed -n "s/.*Unattended-Upgrade::Automatic-Reboot \"\(.*\)\";/\1/p" | head -1)"
  echo "UU_REBOOT_WU=$(apt-config dump 2>/dev/null | sed -n "s/.*Unattended-Upgrade::Automatic-Reboot-WithUsers \"\(.*\)\";/\1/p" | head -1)"
  echo "NTP_SYNC=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"
  echo "OPT_NLW=$(stat -c "%a %U:%G" /opt/nlw 2>/dev/null || echo missing)"
  echo "REBOOT_PENDING=$([ -f /var/run/reboot-required ] && echo yes || echo no)"
  echo "---LISTEN---"
  ss -H -tln 2>/dev/null || ss -tln
')"

val() { sed -n "s/^$1=//p" <<<"$U" | head -1; }
listen="$(awk '/^---LISTEN---$/{f=1;next} f' <<<"$U")"

# --- Privileged read-only snapshot (ONE interactive sudo; no temp file) ----
section "Fetching root-only reads (UFW + effective sshd) — sudo password once"
P="$(ssh -t -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -i "$SSH_KEY" "$TARGET" \
  'sudo sh -c "echo ===UFW===; ufw status verbose; echo ===SSHD===; sshd -T | grep -Ei \"^(passwordauthentication|permitrootlogin|pubkeyauthentication|kbdinteractiveauthentication) \""' \
  2>/dev/null | tr -d "\r")" || { echo "failed to read UFW/sshd (sudo)"; P=""; }
ufw_block="$(awk '/^===UFW===$/{f=1;next} /^===SSHD===$/{f=0} f' <<<"$P")"
sshd_block="$(awk '/^===SSHD===$/{f=1;next} f' <<<"$P")"

# --- Report ----------------------------------------------------------------
section "Host"
info "OS:   $(val OS)";      case "$(val OS)" in *"24.04"*) ok "Ubuntu 24.04";; *) flag "OS is not Ubuntu 24.04";; esac
info "Arch: $(val ARCH)";    [ "$(val ARCH)" = "x86_64" ] && ok "x86_64" || flag "arch not x86_64"
info "vCPU: $(val VCPU)";    [ "$(val VCPU)" -ge 2 ] 2>/dev/null && ok "≥2 vCPU" || flag "fewer than 2 vCPU"
info "RAM:  $(val MEM)"
info "Disk: $(val DISK)"
info "IPv4: $(val IPV4)"
if [ -n "$(val IPV6)" ]; then info "IPv6 (global): $(val IPV6)"; else info "IPv6 (global): none (IPv4-only, as expected)"; fi
[ "$(val REBOOT_PENDING)" = "yes" ] && info "Reboot pending (deferred to the reboot drill)" || true

section "SSH effective settings"
if [ -n "$sshd_block" ]; then
  printf '%s\n' "$sshd_block" | sed 's/^/    /'
  grep -qi '^passwordauthentication no'      <<<"$sshd_block" && ok "PasswordAuthentication no" || flag "PasswordAuthentication is not 'no'"
  grep -qi '^permitrootlogin no'             <<<"$sshd_block" && ok "PermitRootLogin no"        || flag "PermitRootLogin is not 'no'"
  grep -qi '^pubkeyauthentication yes'       <<<"$sshd_block" && ok "PubkeyAuthentication yes"  || flag "PubkeyAuthentication is not 'yes'"
else
  flag "could not read effective sshd config"
fi

section "Firewall (UFW)"
if [ -n "$ufw_block" ]; then
  printf '%s\n' "$ufw_block" | sed 's/^/    /'
  grep -qi 'Status: active' <<<"$ufw_block" && ok "UFW active" || flag "UFW is not active"
  grep -qiE 'deny \(incoming\)' <<<"$ufw_block" && ok "default deny incoming" || flag "default incoming policy is not deny"
else
  flag "could not read UFW status"
fi

section "Listening ports (exposure check)"
printf '%s\n' "$listen" | awk 'NF' | sed 's/^/    /' | head -40
# Flag any of the sensitive ports listening on a NON-loopback local address.
exposed="$(awk '
  { la=$4 }
  {
    n=split(la, a, ":"); port=a[n]; addr=la; sub(":"port"$","",addr)
    if (port ~ /^(3000|8000|5432|6379|9090)$/) {
      if (addr !~ /^(127\.0\.0\.1|\[::1\]|::1)$/) print addr":"port
    }
  }' <<<"$listen" | sort -u)"
if [ -n "$exposed" ]; then
  while IFS= read -r e; do flag "sensitive port on non-loopback address: $e"; done <<<"$exposed"
else
  ok "no 3000/8000/5432/6379/9090 listener on a public/non-loopback address"
fi

section "Docker"
info "$(val DOCKER)";  case "$(val DOCKER)" in Docker*) ok "Docker Engine present";; *) flag "docker missing";; esac
info "Compose v$(val COMPOSE)"; case "$(val COMPOSE)" in missing) flag "docker compose plugin missing";; *) ok "Compose plugin present";; esac
[ "$(val DOCKER_ENABLED)" = "enabled" ] && ok "docker enabled on boot" || flag "docker not enabled on boot ($(val DOCKER_ENABLED))"
[ "$(val DOCKER_ACTIVE)" = "active" ]   && ok "docker active"          || flag "docker not active ($(val DOCKER_ACTIVE))"

section "Unattended upgrades / reboot policy"
[ "$(val UU_PERIODIC)" = "1" ] && ok "unattended-upgrade enabled (Periodic=1)" || flag "unattended-upgrade not enabled (Periodic='$(val UU_PERIODIC)')"
[ "$(val UU_REBOOT)" = "false" ] && ok "Automatic-Reboot false" || flag "Automatic-Reboot is not false ('$(val UU_REBOOT)')"
[ "$(val UU_REBOOT_WU)" = "false" ] && ok "Automatic-Reboot-WithUsers false" || info "Automatic-Reboot-WithUsers='$(val UU_REBOOT_WU)'"

section "Time sync"
[ "$(val NTP_SYNC)" = "yes" ] && ok "NTP synchronized" || flag "NTP not synchronized ('$(val NTP_SYNC)')"

section "Application directory"
info "/opt/nlw: $(val OPT_NLW)"
case "$(val OPT_NLW)" in "750 nlwops:nlwops") ok "/opt/nlw 750 owned by nlwops";; missing) flag "/opt/nlw missing";; *) flag "/opt/nlw perms/owner unexpected";; esac

section "Result"
if [ "$FLAGS" -eq 0 ]; then
  printf '\033[1;32mALL CHECKS PASSED\033[0m — Stage-1 host baseline looks correct.\n'
  exit 0
else
  printf '\033[1;31m%d CHECK(S) FLAGGED\033[0m — review the [FLAG] lines above.\n' "$FLAGS"
  exit 1
fi
