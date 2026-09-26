#!/usr/bin/env bash
# Record a HUMAN-confirmed controlled test alert delivery for the rollout's
# `reopen`/`go-check` (docs/ops/alerting.md). Run ON THE HOST as root:
#
#   sudo scripts/ops/record-alert-delivery.sh --receiver ops-slack --confirmed-by "<operator>"
#
# Writes /opt/nlw/rollout/alert-delivery.json as root:<rollout group> 0640 so the
# rollout user (nlwops) can read it, WITHOUT touching the ownership or mode of the
# rollout directory (it stays nlwops:nlwops 0700). The record is evidence written
# by a person after they SAW the alert arrive; nothing here sends or checks an
# alert, and the rollout never writes this file itself.
set -euo pipefail

DIR="/opt/nlw/rollout"; RECEIVER=""; BY=""; AT=""; OWNER="root"; GROUP="nlwops"
usage() { echo "usage: $0 --receiver NAME --confirmed-by OPERATOR [--delivered-at ISO8601-with-tz] [--dir DIR] [--owner USER] [--group GROUP]" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --receiver) RECEIVER="$2"; shift 2 ;;
    --confirmed-by) BY="$2"; shift 2 ;;
    --delivered-at) AT="$2"; shift 2 ;;
    --dir) DIR="$2"; shift 2 ;;
    --owner) OWNER="$2"; shift 2 ;;
    --group) GROUP="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$RECEIVER" ] && [ -n "$BY" ] || usage
case "$RECEIVER" in null|"") echo "refusing: the null receiver never delivers anything" >&2; exit 2 ;; esac
printf '%s' "$RECEIVER$BY" | grep -Eq '^[A-Za-z0-9 ._@+-]+$' || { echo "refusing: receiver/operator must be plain text" >&2; exit 2; }
[ -d "$DIR" ] || { echo "refusing: $DIR does not exist (the rollout creates it; never create it here)" >&2; exit 2; }
if [ -z "$AT" ]; then AT="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"; fi
printf '%s' "$AT" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$' \
  || { echo "refusing: --delivered-at must be ISO-8601 WITH a timezone" >&2; exit 2; }

dir_identity() { ls -ldn "$1" | awk '{print $1, $3, $4}'; }   # mode, uid, gid — never mtime/link count
before="$(dir_identity "$DIR")"
TMP="$(mktemp "$DIR/.alert-delivery.XXXXXX")"
trap 'rm -f "$TMP"' EXIT
printf '{"receiver": "%s", "delivered_at": "%s", "confirmed_by": "%s"}\n' "$RECEIVER" "$AT" "$BY" > "$TMP"
# `install` sets owner/group/mode on the FILE only; mv is atomic; the parent is never chmod/chown'ed.
install -m 0640 -o "$OWNER" -g "$GROUP" "$TMP" "$DIR/alert-delivery.json.new"
mv -f "$DIR/alert-delivery.json.new" "$DIR/alert-delivery.json"
after="$(dir_identity "$DIR")"
[ "$before" = "$after" ] || { echo "BUG: the rollout directory changed: $before -> $after" >&2; exit 1; }
echo "recorded: receiver=$RECEIVER delivered_at=$AT confirmed_by=$BY -> $DIR/alert-delivery.json ($(ls -l "$DIR/alert-delivery.json" | cut -d' ' -f1))"
