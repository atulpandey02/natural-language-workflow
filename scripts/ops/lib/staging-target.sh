#!/usr/bin/env bash
# Shared staging-target configuration for the Mac-side ops scripts (M12A-Prep §M).
#
# Sourced (not executed). Loads deploy/staging/target.env — the ONE reviewed
# source of the SSH address / operator user / instance id — and exposes:
#   SSH_HOST SSH_USER SSH_KEY TARGET REMOTE_APP EXPECTED_INSTANCE_ID
#   EXPECTED_REGION STAGING_HOST COMPOSE_PROJECT
# Environment overrides (SSH_HOST, SSH_USER, SSH_KEY) still win, so a changed
# public IP can be passed once without editing anything; the instance-id check
# (`staging_assert_instance`) is what actually authorizes the host.
set -u

_nlw_ops_lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NLW_REPO_ROOT="${NLW_REPO_ROOT:-$(cd "${_nlw_ops_lib_dir}/../../.." && pwd)}"
NLW_STAGING_TARGET_FILE="${NLW_STAGING_TARGET_FILE:-${NLW_REPO_ROOT}/deploy/staging/target.env}"

[ -r "$NLW_STAGING_TARGET_FILE" ] || { echo "staging target config missing: $NLW_STAGING_TARGET_FILE" >&2; return 2 2>/dev/null || exit 2; }
# shellcheck disable=SC1090
. "$NLW_STAGING_TARGET_FILE"

: "${NLW_STAGING_INSTANCE_ID:?target.env: NLW_STAGING_INSTANCE_ID required}"
: "${NLW_STAGING_SSH_HOST:?target.env: NLW_STAGING_SSH_HOST required}"
: "${NLW_STAGING_SSH_USER:?target.env: NLW_STAGING_SSH_USER required}"
: "${NLW_STAGING_REMOTE_APP:?target.env: NLW_STAGING_REMOTE_APP required}"

EXPECTED_INSTANCE_ID="$NLW_STAGING_INSTANCE_ID"
EXPECTED_REGION="${NLW_STAGING_REGION:-}"
STAGING_HOST="${NLW_STAGING_PUBLIC_HOSTNAME:-}"
COMPOSE_PROJECT="${NLW_STAGING_COMPOSE_PROJECT:-app}"
SSH_HOST="${SSH_HOST:-$NLW_STAGING_SSH_HOST}"
SSH_USER="${SSH_USER:-$NLW_STAGING_SSH_USER}"
SSH_KEY="${SSH_KEY:-${NLW_STAGING_SSH_KEY:-$HOME/.ssh/nlw-staging-key.pem}}"
TARGET="${SSH_USER}@${SSH_HOST}"
REMOTE_APP="$NLW_STAGING_REMOTE_APP"

# Read the instance id + region from IMDSv2 on the connected host (read-only).
# Usage: staging_imds_identity "<ssh-command-prefix as array via name>" -> prints "id region ip"
staging_remote_identity_cmd() {
  cat <<'EOS'
T=$(curl -sS -m 5 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
for p in instance-id placement/region public-ipv4; do curl -sS -m 5 -H "X-aws-ec2-metadata-token: $T" "http://169.254.169.254/latest/meta-data/$p"; printf ' '; done; echo
EOS
}

# Pure check: "id region ip" line vs the expected instance id (and region if set).
# Returns 0 on match; prints the reason on stderr otherwise.
staging_assert_instance() {
  local line="$1" id region
  id="${line%% *}"; region="$(printf '%s' "$line" | awk '{print $2}')"
  [ -n "$id" ] || { echo "STOP: could not read the instance id from IMDSv2" >&2; return 1; }
  [ "$id" = "$EXPECTED_INSTANCE_ID" ] || { echo "STOP: connected host is $id, expected $EXPECTED_INSTANCE_ID — wrong target" >&2; return 1; }
  if [ -n "$EXPECTED_REGION" ] && [ "$region" != "$EXPECTED_REGION" ]; then
    echo "STOP: host region $region != expected $EXPECTED_REGION" >&2; return 1
  fi
  return 0
}
