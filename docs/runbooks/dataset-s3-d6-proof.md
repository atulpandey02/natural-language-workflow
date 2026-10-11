# Dataset S3 D6 proof (NOT RUN — procedure for review)

Status: **a procedure, not a record.** Nothing in this document has been run.
No AWS account has been contacted, and nothing here has been validated by AWS.
It implements ADR-033 D6: the isolated, staging-only proof that must pass
before any dataset object reaches S3.

- **Templates:** every policy comes from
  [dataset-s3-provisioning.md](dataset-s3-provisioning.md), rendered from the
  reviewed commit. Nothing is typed by hand.
- **Review:** [the policy review](../security/o2-aws-policy-review.md) records
  what was checked locally and what only this proof can show.
- **Decisions:** [the owner-decision sheet](dataset-s3-d6-owner-decisions.md)
  must be filled in before step P01.
- **Contract tests:** `tests/unit/test_dataset_s3_d6_proof.py` parses this
  document. It checks that every command block is labelled, that the labels
  match the AWS operations inside, that no mutating command names production,
  that no command can print a credential, and that cleanup uses recorded ids
  only.

## How to read the commands

Every command block is preceded by a label:

`**<step id> · <class> · <where>**`, optionally with `· EXPECT-DENIED`.

| Class | Meaning |
|---|---|
| **READ-ONLY** | AWS calls that only inspect (`get-*`, `list-*`, `describe-*`, `head-*`, `simulate-*`, `wait`, `validate-logs`, `get-caller-identity`), or that issue a session without printing it |
| **MUTATING** | at least one AWS call that creates, changes or deletes something, including writing an object |
| **HOST** | changes on the proof instance only, no AWS call |
| **LOCAL** | the workstation only, no AWS call |
| `· EXPECT-DENIED` | every AWS call in the block must be refused; an allowed call is stop condition S4 |

`<where>` is `workstation` (the owner's machine, with the owner's existing
administrator access) or `proof instance` (the disposable EC2 instance from
P03, reached over SSH).

**Rules for the whole session:**

- **Shells.** Workstation steps run under macOS `/bin/bash` 3.2 or later;
  proof-instance steps under Amazon Linux 2023's bash 5. `lib.sh` uses
  nothing newer than bash 3.2 on the workstation path.
- **How each block runs.**
  - **P00-01** contains only `export` lines. Type or paste it into the
    session shell itself, so the variables persist. It makes no check and
    cannot exit the shell.
  - **P00-02** is pasted into `bash -s`. It verifies that the checkout is the
    reviewed commit and is clean before it does anything else, then extracts
    every step and helper file into `$PROOF_DIR` with a SHA-256 manifest.
  - **Every later step** is run as `bash "$PROOF_DIR/run-step" <step id>`,
    never pasted. `run-step` re-checks every extracted file against the
    manifest first, so a step cannot drift from the reviewed text.
  - Each step is its own `bash` process: `stop` ends that process, not the
    session. Values that later steps need travel only through the ledger,
    `created.env`.
- If a block fails in a way the step does not predict, stop (S9) and follow
  [§F Recovery](#f-recovery-from-a-partial-proof).
- Never add `--debug`, `set -x` or `--output json` to a command that issues
  credentials. Never `cat` a credential file. Never put an access key in a
  file: the human credentials live only in the macOS Keychain (P00-03).
- Never edit a policy during the session. A wrong template is fixed in a
  reviewed pull request, and the proof restarts.

## A. Resource inventory

### A.1 Staging proof resources (created by this procedure)

Names use only placeholders. `<ACCOUNT>` is the approved account (decision
E5) and `<SUFFIX>` is `-d6` followed by 12 random hex digits, generated for
each proof run in P00-01 (decision E6).
Every resource is tagged `nlw-env=staging` and `nlw-proof=<PROOF_ID>`, where
IAM and the service allow tags.

<!-- inventory -->
```json
[
  {"id": "role-bootstrap", "type": "AWS::IAM::Role", "name": "nlw-staging-dataset-bootstrap",
   "created_by": "admin", "step": "P03-01", "ledger": "REC_ROLE_BOOTSTRAP", "after_proof": "decision E3"},
  {"id": "profile-bootstrap", "type": "AWS::IAM::InstanceProfile", "name": "nlw-staging-dataset-bootstrap",
   "created_by": "admin", "step": "P03-01", "ledger": "REC_PROFILE_BOOTSTRAP", "after_proof": "decision E3"},
  {"id": "role-api", "type": "AWS::IAM::Role", "name": "nlw-staging-dataset-api",
   "created_by": "admin", "step": "P03-01", "ledger": "REC_ROLE_API", "after_proof": "decision E3"},
  {"id": "role-ingest", "type": "AWS::IAM::Role", "name": "nlw-staging-dataset-ingest",
   "created_by": "admin", "step": "P03-01", "ledger": "REC_ROLE_INGEST", "after_proof": "decision E3"},
  {"id": "role-operator", "type": "AWS::IAM::Role", "name": "nlw-staging-dataset-operator",
   "created_by": "admin", "step": "P03-01", "ledger": "REC_ROLE_OPERATOR", "after_proof": "decision E3"},
  {"id": "role-audit-admin", "type": "AWS::IAM::Role", "name": "nlw-staging-dataset-audit-admin",
   "created_by": "admin", "step": "P03-01", "ledger": "REC_ROLE_AUDIT_ADMIN", "after_proof": "retained with the audit records"},
  {"id": "role-audit-reader", "type": "AWS::IAM::Role", "name": "nlw-staging-dataset-audit-reader",
   "created_by": "admin", "step": "P03-01", "ledger": "REC_ROLE_AUDIT_READER", "after_proof": "retained with the audit records"},
  {"id": "key-dataset", "type": "AWS::KMS::Key", "name": "alias/nlw-staging-datasets",
   "created_by": "admin", "step": "P03-02", "ledger": "REC_KEY_ARN", "after_proof": "decision E3"},
  {"id": "key-audit", "type": "AWS::KMS::Key", "name": "alias/nlw-staging-dataset-audit",
   "created_by": "audit-admin", "step": "P03-04", "ledger": "REC_AUDIT_KEY_ARN", "after_proof": "retained with the audit records"},
  {"id": "bucket-dataset", "type": "AWS::S3::Bucket", "name": "nlw-staging-datasets-<ACCOUNT>-us-east-1<SUFFIX>",
   "created_by": "admin", "step": "P03-06", "ledger": "REC_BUCKET", "after_proof": "decision E3"},
  {"id": "bucket-audit", "type": "AWS::S3::Bucket", "name": "nlw-staging-dataset-audit-<ACCOUNT>-us-east-1<SUFFIX>",
   "created_by": "audit-admin", "step": "P03-07", "ledger": "REC_AUDIT_BUCKET", "after_proof": "retained with the audit records"},
  {"id": "trail", "type": "AWS::CloudTrail::Trail", "name": "nlw-staging-dataset-data-events",
   "created_by": "audit-admin", "step": "P03-08", "ledger": "REC_TRAIL_ARN", "after_proof": "decision E3"},
  {"id": "proof-sg", "type": "AWS::EC2::SecurityGroup", "name": "nlw-staging-dataset-proof-ssh",
   "created_by": "admin", "step": "P03-10", "ledger": "REC_SG_ID", "after_proof": "always deleted"},
  {"id": "proof-instance", "type": "AWS::EC2::Instance", "name": "nlw-staging-dataset-proof",
   "created_by": "admin", "step": "P03-10", "ledger": "REC_INSTANCE_ID", "after_proof": "always deleted"},
  {"id": "budget", "type": "AWS::Budgets::Budget", "name": "nlw-staging-dataset-proof-<PROOF_ID>",
   "created_by": "admin", "step": "P03-00", "ledger": "REC_BUDGET_NAME", "after_proof": "decision E4"},
  {"id": "proof-objects", "type": "AWS::S3::Object", "name": "versions/<PROOF_WS>/… and versions/<PROOF_WS2>/…",
   "created_by": "api", "step": "P04-P14", "ledger": "REC_OBJ_", "after_proof": "always purged"}
]
```

**Relationships:**

| From | To | How |
|---|---|---|
| proof instance | `nlw-staging-dataset-bootstrap` | instance profile; IMDSv2 required, hop limit 1 |
| bootstrap role | api and ingest roles | `sts:AssumeRole` only; explicit deny of every other role, of S3 and of KMS |
| api role | dataset bucket `versions/*`, dataset key | create once, head and attributes, `GenerateDataKey` through S3 |
| ingest role | dataset bucket `versions/*`, dataset key | `GetObject`, `Decrypt` through S3 |
| operator role | dataset bucket `versions/*`, dataset key | list, version-aware delete, `Decrypt`; MFA humans only |
| credential refresher | api and ingest roles | host service writing one file per container. **Not built** (O-6); P14 uses a documented stand-in |
| trail | dataset bucket objects → audit bucket, audit key | data events only, this bucket only |
| audit-admin role | trail, audit bucket, audit key | administers; never dataset data |
| audit-reader role | audit bucket logs, audit key | reads and validates logs |

**Not created here:**

- `<ADMIN_ROLE>` already exists. It is the owner's account administration
  role (decision E8), used through the workstation profile `nlw-proof-admin`.
- The human principals for the three MFA roles already exist (decision E9).
- The account-level management-event trail is assumed to exist (decision E7).

### A.2 Production resources (never created or touched by this proof)

Production mirrors A.1 with `production` in every name:
`nlw-production-datasets-<ACCOUNT>-us-east-1<SUFFIX>`,
`alias/nlw-production-datasets`, `nlw-production-dataset-{bootstrap,api,ingest,operator,audit-admin,audit-reader}`,
`nlw-production-dataset-audit-<ACCOUNT>-us-east-1<SUFFIX>`,
`alias/nlw-production-dataset-audit` and `nlw-production-dataset-data-events`.

This proof refers to production names **only** in READ-ONLY policy
simulations (P10). No MUTATING block names production; the contract test
enforces it.

## Prerequisites (all LOCAL; no AWS call)

- The owner-decision sheet is complete and signed off, and the D6 session is
  explicitly authorized in writing.
- A checkout of the reviewed commit, with a clean tree.
- AWS CLI v2 at version 2.22 or later on the workstation and the proof
  instance (needed for `--if-none-match`).
- `jq` and `python3` on the workstation.
- The backend image to be proven, by digest, from a release manifest that
  passed `python -m nlw.ops.release_provenance verify`. It must contain
  `nlw.storage.s3_credentials` (`eb42250` or later).

**Where credentials come from.** Nothing in `$PROOF_DIR` holds an access key.

- **Source identities.** Two humans, the operator and the audit
  administrator (E9), each use an IAM user (E11 = `iam-user-mfa`) with a
  dedicated access key created only for this proof run.
- **Storage.** Each key is stored only in that person's macOS login Keychain,
  under the service `nlw-d6-<PROOF_ID>-<operator|audit>` (P00-03).
- **Use.** The AWS CLI reads a key through `credential_process`, which runs
  `credential-process.sh`. The script prints the key to the CLI's pipe, never
  to a file or a terminal.
- **Roles.** Every role profile below chains from one of those two source
  profiles, with that person's MFA device.
- **Removal.** X09 deletes the two access keys in IAM. X08 removes the
  Keychain items, deletes only this proof's cached CLI sessions, and scans
  `$PROOF_DIR` for anything that looks like a credential.
- **Lifetime.** The keys exist only between P00-03 and X09. §F requires X09
  and X08 after any stop, whatever else is abandoned.

<!-- file: aws-config.workstation -->
```ini
# Workstation profiles. <...> values are filled by P00-02 from the session
# variables; none is committed and none is a secret. No profile holds a key.
[profile nlw-proof-human-operator]
credential_process = /bin/bash <PROOF_DIR>/credential-process.sh <PROOF_ID> operator
region = us-east-1

[profile nlw-proof-human-audit]
credential_process = /bin/bash <PROOF_DIR>/credential-process.sh <PROOF_ID> audit
region = us-east-1

[profile nlw-proof-admin]
# <ADMIN_ROLE> (decision E8), assumed by the operator with MFA.
role_arn = arn:aws:iam::<ACCOUNT>:role/<ADMIN_ROLE>
role_session_name = nlw-staging-proof-admin
source_profile = nlw-proof-human-operator
mfa_serial = <OPERATOR_MFA_ARN>
duration_seconds = 3600
region = us-east-1

[profile nlw-proof-audit-admin]
role_arn = arn:aws:iam::<ACCOUNT>:role/nlw-staging-dataset-audit-admin
role_session_name = nlw-staging-audit-admin
source_profile = nlw-proof-human-audit
mfa_serial = <AUDIT_MFA_ARN>
duration_seconds = 3600
region = us-east-1

[profile nlw-proof-audit-reader]
role_arn = arn:aws:iam::<ACCOUNT>:role/nlw-staging-dataset-audit-reader
role_session_name = nlw-staging-audit-reader
source_profile = nlw-proof-human-audit
mfa_serial = <AUDIT_MFA_ARN>
duration_seconds = 3600
region = us-east-1

[profile nlw-proof-operator]
role_arn = arn:aws:iam::<ACCOUNT>:role/nlw-staging-dataset-operator
role_session_name = nlw-staging-operator
source_profile = nlw-proof-human-operator
mfa_serial = <OPERATOR_MFA_ARN>
duration_seconds = 3600
region = us-east-1

[profile nlw-proof-operator-nomfa]
# Negative control: the same role without MFA. It must be refused.
role_arn = arn:aws:iam::<ACCOUNT>:role/nlw-staging-dataset-operator
role_session_name = nlw-staging-operator
source_profile = nlw-proof-human-operator
region = us-east-1
```

<!-- file: credential-process.sh -->
```sh
#!/bin/bash
# credential-process.sh PROOF_ID WHO [MODE]: one human source identity, held
# only in the macOS login Keychain. MODE print (the default) is for the AWS
# CLI's credential_process: the key goes to the CLI's pipe, never to a file or
# a terminal. add prompts (hidden) for a new key; key-id prints only the
# access key id; remove deletes both items and fails if any remains.
set -euo pipefail
umask 077
proof="${1:-}"; who="${2:-}"; mode="${3:-print}"
[[ "$proof" =~ ^d6-[0-9]{8}-[0-9a-f]{6}$ && "$who" =~ ^(operator|audit)$ ]] \
  || { echo "credential-process.sh: bad arguments" >&2; exit 2; }
svc="nlw-d6-$proof-$who"
kc=/usr/bin/security
case "$mode" in
  add)
    echo "Keychain prompts follow: enter the $who access key id, then its secret." >&2
    "$kc" add-generic-password -U -s "$svc" -a access-key-id -w
    "$kc" add-generic-password -U -s "$svc" -a secret-access-key -w ;;
  key-id)
    "$kc" find-generic-password -s "$svc" -a access-key-id -w ;;
  remove)
    "$kc" delete-generic-password -s "$svc" -a access-key-id > /dev/null 2>&1 || true
    "$kc" delete-generic-password -s "$svc" -a secret-access-key > /dev/null 2>&1 || true
    if "$kc" find-generic-password -s "$svc" > /dev/null 2>&1; then
      echo "STOP S7: Keychain items remain for $svc" >&2; exit 1
    fi ;;
  print)
    { "$kc" find-generic-password -s "$svc" -a access-key-id -w
      "$kc" find-generic-password -s "$svc" -a secret-access-key -w; } \
      | /usr/bin/python3 -c 'import json, sys
k, s = sys.stdin.read().split("\n")[:2]
print(json.dumps({"Version": 1, "AccessKeyId": k, "SecretAccessKey": s}))' ;;
  *) echo "credential-process.sh: bad mode" >&2; exit 2 ;;
esac
```

<!-- file: run-step -->
```sh
#!/bin/bash
# run-step STEP: run one extracted step after checking every extracted file
# against the manifest P00-02 wrote from the reviewed commit.
set -euo pipefail
: "${PROOF_DIR:?}"
step="${1:-}"
[[ "$step" =~ ^(P[0-9][0-9]-[0-9][0-9]|X[0-9][0-9])$ ]] || { echo "STOP S9: bad step id" >&2; exit 1; }
python3 - "$PROOF_DIR" <<'PY' || { echo "STOP S9: an extracted file differs from the reviewed commit" >&2; exit 1; }
import hashlib, json, os, sys
d = sys.argv[1]
manifest = json.load(open(os.path.join(d, "manifest.json")))
for rel, digest in manifest.items():
    if hashlib.sha256(open(os.path.join(d, rel), "rb").read()).hexdigest() != digest:
        sys.exit(1)
PY
[[ -f "$PROOF_DIR/steps/$step.sh" ]] || { echo "STOP S9: no such step" >&2; exit 1; }
exec bash "$PROOF_DIR/steps/$step.sh"
```

<!-- file: normalize-policy.py -->
```python
"""Print a policy document in a canonical form, so a deployed policy can be
compared with the rendered template. Keys are sorted; lists are sorted; a
one-element list and its single value compare equal (IAM, KMS and S3 return
either). Input is the document, or a JSON string holding it (KMS)."""

import json
import sys
import urllib.parse


def canon(x):
    if isinstance(x, dict):
        return {k: canon(v) for k, v in sorted(x.items())}
    if isinstance(x, list):
        items = sorted((canon(v) for v in x), key=lambda v: json.dumps(v, sort_keys=True))
        return items[0] if len(items) == 1 else items
    return x


raw = sys.stdin.read().strip()
doc = json.loads(raw)
while isinstance(doc, str):
    doc = json.loads(urllib.parse.unquote(doc))
print(json.dumps(canon(doc), sort_keys=True, indent=1))
```

<!-- file: aws-config.instance -->
```ini
# Proof-instance profiles. The bootstrap identity is the instance profile.
[profile proof-bootstrap]
region = us-east-1

[profile proof-api]
role_arn = arn:aws:iam::<ACCOUNT>:role/nlw-staging-dataset-api
role_session_name = nlw-staging-api
credential_source = Ec2InstanceMetadata
duration_seconds = 900
region = us-east-1

[profile proof-ingest]
role_arn = arn:aws:iam::<ACCOUNT>:role/nlw-staging-dataset-ingest
role_session_name = nlw-staging-ingest
credential_source = Ec2InstanceMetadata
duration_seconds = 900
region = us-east-1

[profile proof-api-wrong-session]
# Negative control: the API role with a session name its trust refuses.
role_arn = arn:aws:iam::<ACCOUNT>:role/nlw-staging-dataset-api
role_session_name = nlw-staging-ingest
credential_source = Ec2InstanceMetadata
region = us-east-1
```

The shell library below is sourced at the start of every block. It holds the
only definitions of names, the ledger, the template renderer and the helpers
that keep command output off the terminal.

<!-- file: lib.sh -->
```sh
# shellcheck shell=bash
# No `set -E` and no ERR trap: an ERR trap inherited into command
# substitutions fires inside guarded checks such as
# `[[ "$(...)" == x ]] || stop ...` (seen on bash 3.2).
set -euo pipefail
umask 077
: "${PROOF_DIR:?}" "${PROOF_ID:?}" "${APPROVED_ACCOUNT:?}" "${RUNBOOK_DIR:?}" "${BUCKET_SUFFIX:?}"
ACCOUNT="$APPROVED_ACCOUNT"
SUFFIX="$BUCKET_SUFFIX"
[[ "$ACCOUNT" =~ ^[0-9]{12}$ ]] || { echo "STOP S1: APPROVED_ACCOUNT is not an account id" >&2; exit 1; }
# A proof-run-specific, high-entropy suffix (P00): 12 random hex digits.
[[ "$SUFFIX" =~ ^-d6[0-9a-f]{12}$ ]] || { echo "STOP S1: BUCKET_SUFFIX is not this proof's suffix" >&2; exit 1; }
BUCKET="nlw-staging-datasets-${ACCOUNT}-us-east-1${SUFFIX}"
AUDIT_BUCKET="nlw-staging-dataset-audit-${ACCOUNT}-us-east-1${SUFFIX}"
TRAIL=nlw-staging-dataset-data-events
TRAIL_ARN="arn:aws:cloudtrail:us-east-1:${ACCOUNT}:trail/${TRAIL}"
ROLE_PREFIX="arn:aws:iam::${ACCOUNT}:role"
KEY_ALIAS=alias/nlw-staging-datasets
AUDIT_KEY_ALIAS=alias/nlw-staging-dataset-audit
(( ${#BUCKET} <= 63 && ${#AUDIT_BUCKET} <= 63 )) || { echo "STOP S1: a bucket name exceeds 63 characters" >&2; exit 1; }
if [[ -n "${ADMIN_ROLE:-}" ]]; then
  [[ "$ADMIN_ROLE" =~ ^[A-Za-z0-9+=,.@_/-]+$ && "$ADMIN_ROLE" != arn:* && "$ADMIN_ROLE" != */ ]] \
    || { echo "STOP S1: ADMIN_ROLE must be the role name with any path, not an ARN (E8)" >&2; exit 1; }
fi
OTHER_BUCKET="nlw-production-datasets-${ACCOUNT}-us-east-1${SUFFIX}"
CONTAINER_UID=10001
CONTAINER_GID=999
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
export AWS_CONFIG_FILE="$PROOF_DIR/aws-config"
export AWS_SHARED_CREDENTIALS_FILE=/dev/null
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE
touch "$PROOF_DIR/created.env" "$PROOF_DIR/expected-events.tsv" "$PROOF_DIR/journal.log"

STOPPED=""
ON_EXIT=""
stop() {
  STOPPED=1
  printf '%s STOP %s %s\n' "$(date -u +%FT%TZ)" "$1" "$2" >> "$PROOF_DIR/journal.log"
  echo "STOP $1: $2" >&2
  exit 1
}
# on_exit CMD: run CMD when this step's process ends, however it ends (a
# finished step, a stop, or a failure). Used to stop background processes.
on_exit() { ON_EXIT="${ON_EXIT}${1}"$'\n'; }
# The EXIT handler runs the cleanups and, if the step failed without a stop,
# records S10 with the failing command (BASH_COMMAND still names it here,
# including inside functions, on bash 3.2 and 5). There is no ERR trap. Only
# the command's first words are logged, never its output.
_on_exit() {
  local rc=$? failed="${BASH_COMMAND:0:80}"
  set +e
  [[ -z "$ON_EXIT" ]] || eval "$ON_EXIT"
  if [[ $rc -ne 0 && -z "$STOPPED" ]]; then
    printf '%s STOP S10 command failed: %s\n' "$(date -u +%FT%TZ)" "$failed" >> "$PROOF_DIR/journal.log"
    echo "STOP S10: command failed: $failed" >&2
  fi
}
trap _on_exit EXIT

# The ledger belongs to exactly one proof run.
if [[ ! -s "$PROOF_DIR/created.env" ]]; then
  printf 'REC_PROOF_ID=%q\n' "$PROOF_ID" > "$PROOF_DIR/created.env"
fi
# shellcheck disable=SC1091
source "$PROOF_DIR/created.env"
[[ "${REC_PROOF_ID:-}" == "$PROOF_ID" ]] || stop S8 "the ledger belongs to another proof run"

# verify_reviewed_commit [DIR]: rendering and execution use only the reviewed,
# unmodified checkout.
verify_reviewed_commit() {
  local dir="${1:-$RUNBOOK_DIR}"
  [[ "${REVIEWED_COMMIT:-}" =~ ^[0-9a-f]{40}$ ]] || stop S9 "REVIEWED_COMMIT is not a full commit id"
  [[ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" == "$REVIEWED_COMMIT" ]] \
    || stop S9 "the checkout is not the reviewed commit"
  [[ -z "$(git -C "$dir" status --porcelain 2>/dev/null)" ]] || stop S9 "the checkout has local changes"
}

note() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$PROOF_DIR/journal.log"; }

# validate_humans JSON [EXCLUDED_JSON]: a non-empty list of IAM users of the
# approved account (E11), no wildcard, no root, no other account, no
# duplicates, and nothing shared with EXCLUDED_JSON (E9).
validate_humans() {
  python3 - "$ACCOUNT" "$1" "${2:-[]}" <<'PY' || stop S9 "a human principal list is invalid (decisions E9 and E11)"
import json, re, sys
account, raw, excluded = sys.argv[1], sys.argv[2], sys.argv[3]
def strict(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)
try:
    people, others = json.loads(raw, object_pairs_hook=strict), json.loads(excluded)
except ValueError:
    sys.exit(1)
user = re.compile(r"^arn:aws:iam::%s:user/(?:[A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]+$" % account)
ok = (isinstance(people, list) and people and all(isinstance(p, str) and user.match(p) for p in people)
      and len(set(people)) == len(people) and isinstance(others, list) and not set(people) & set(others))
sys.exit(0 if ok else 1)
PY
}

# record NAME VALUE: append-only ledger, written immediately after a create
# succeeds. Cleanup acts only on names in this ledger.
record() {
  [[ "$1" =~ ^REC_[A-Z0-9_]+$ ]] || stop S8 "bad ledger name $1"
  [[ -n "$2" ]] || stop S10 "a create returned no identifier for $1"
  [[ "$2" != *'*'* ]] || stop S8 "wildcard ledger value for $1"
  printf '%s=%q\n' "$1" "$2" >> "$PROOF_DIR/created.env"
  printf -v "$1" '%s' "$2"
  note "recorded $1"
}

# expect_error CODE cmd...: the command must fail with that error code
# (AccessDenied also matches KMS and CloudTrail's AccessDeniedException; a
# HEAD request has no body, so its code is the HTTP status). Output is kept
# in a private file and never printed. An unexpected success is S4.
expect_error() {
  local code="$1"; shift
  if "$@" > "$PROOF_DIR/last.out" 2> "$PROOF_DIR/last.err"; then
    : > "$PROOF_DIR/last.out"
    stop "${ON_ALLOWED:-S4}" "allowed, expected $code: $1 ${2:-} ${3:-}"
  fi
  : > "$PROOF_DIR/last.out"
  grep -qE "\(${code}(Exception)?\)" "$PROOF_DIR/last.err" \
    || stop S9 "expected $code, got: $(grep -oE '\([A-Za-z0-9]+\)' "$PROOF_DIR/last.err" | head -1)"
  note "refused as expected ($code): $1 ${2:-} ${3:-}"
}
expect_denied() { expect_error AccessDenied "$@"; }
# absent CODE cmd...: the lookup must report not-found. Finding it is S2.
absent() { ON_ALLOWED=S2 expect_error "$@"; }

# expect_event ROLE EVENT KEY ERROR: a data event P13 must find in the trail.
expect_event() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4:--}" >> "$PROOF_DIR/expected-events.tsv"; }

# expect_simulated DECISION output: every decision in a simulator result.
expect_simulated() {
  local want="$1" got; got="$(tr '\t' '\n' <<< "$2" | sort -u | tr '\n' ' ')"
  [[ "$got" == "$want " ]] || stop S4 "simulator returned '$got', expected '$want'"
  note "simulated: $want"
}

# render TEMPLATE: print a template from the reviewed runbook with every
# placeholder filled from this session; refuses to print a partial policy.
render() {
  verify_reviewed_commit
  python3 - "$1" "$RUNBOOK_DIR/dataset-s3-provisioning.md" <<'PY'
import json, os, re, sys
name, path = sys.argv[1], sys.argv[2]
m = re.search(r"<!-- template: %s -->\n`{3}json\n(.*?)`{3}" % re.escape(name), open(path).read(), re.S)
if m is None:
    sys.exit(f"no template {name}")
body = m.group(1)
env = os.environ
values = {
    "<ACCOUNT>": env["ACCOUNT"], "<ENV>": "staging", "<OTHER_ENV>": "production",
    "<BUCKET>": env["BUCKET"], "<AUDIT_BUCKET>": env["AUDIT_BUCKET"],
    "<TRAIL_ARN>": env["TRAIL_ARN"], "<ADMIN_ROLE>": env["ADMIN_ROLE"],
    "<AUDIT_ADMIN_ROLE>": "nlw-staging-dataset-audit-admin",
    "<AUDIT_READER_ROLE>": "nlw-staging-dataset-audit-reader",
}
for key, var in (("<KEY_ARN>", "REC_KEY_ARN"), ("<AUDIT_KEY_ARN>", "REC_AUDIT_KEY_ARN")):
    if env.get(var):
        values[key] = env[var]
if env.get("HUMANS"):
    people = json.loads(env["HUMANS"])
    user = re.compile(r"^arn:aws:iam::%s:user/(?:[A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]+$" % env["ACCOUNT"])
    if not (isinstance(people, list) and people and all(isinstance(p, str) and user.match(p) for p in people)):
        sys.exit("invalid human principals")
    body = body.replace('"<HUMAN_PRINCIPAL_ARNS>"', json.dumps(people))
if env.get("AUDIT_RETENTION_DAYS"):
    body = body.replace('"<AUDIT_EXPIRY_DAYS>"', str(int(env["AUDIT_RETENTION_DAYS"]) + 1))
for k, v in values.items():
    body = body.replace(k, v)
if re.search(r"<[A-Z_]+>", body):
    sys.exit(f"unfilled placeholder in {name}")
def strict(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        sys.exit(f"duplicate key in {name}")
    return dict(pairs)
doc = json.loads(body, object_pairs_hook=strict)
for s in (doc if isinstance(doc, list) else doc.get("Statement", [])):
    if isinstance(s, dict) and "Effect" in s and s["Effect"] not in ("Allow", "Deny"):
        sys.exit(f"non-canonical Effect in {name}")
if isinstance(doc, list) and name.endswith("-statements"):
    doc = {"Version": "2012-10-17", "Statement": doc}
json.dump(doc, sys.stdout)
PY
}
export ACCOUNT BUCKET AUDIT_BUCKET TRAIL_ARN REC_KEY_ARN REC_AUDIT_KEY_ARN

# write_credentials SERVICE PROFILE: the refresher stand-in (P14). The session
# goes straight from the CLI into a private file by atomic rename; only the
# expiry is printed.
write_credentials() {
  local dir="/run/nlw/aws/$1"
  sudo install -d -m 0700 -o "$CONTAINER_UID" -g "$CONTAINER_GID" "$dir"
  aws configure export-credentials --profile "$2" --format process \
    | sudo python3 -c '
import json, os, sys, tempfile
d, uid, gid = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
c = json.load(sys.stdin)
fd, tmp = tempfile.mkstemp(dir=d)
with os.fdopen(fd, "w") as f:
    f.write("[default]\n")
    f.write("aws_access_key_id = " + c["AccessKeyId"] + "\n")
    f.write("aws_secret_access_key = " + c["SecretAccessKey"] + "\n")
    f.write("aws_session_token = " + c["SessionToken"] + "\n")
    f.write("x_nlw_expiration = " + c["Expiration"] + "\n")
    f.flush()
    os.fsync(f.fileno())
os.chmod(tmp, 0o400)
os.chown(tmp, uid, gid)
os.replace(tmp, os.path.join(d, "credentials"))
print("credential file rotated; expiry", c["Expiration"])
' "$dir" "$CONTAINER_UID" "$CONTAINER_GID"
}

# probe SERVICE CREDENTIAL_DIR [docker args...] -- [probe args...]: run the
# reviewed startup path inside the proven image (P14, P15).
probe() {
  local service="$1" dir="$2"; shift 2
  local docker_args=()
  while [[ $# -gt 0 && "$1" != "--" ]]; do docker_args+=("$1"); shift; done
  [[ "${1:-}" == "--" ]] && shift
  sudo docker run --rm "${docker_args[@]}" \
    -v "$dir:/run/nlw/aws/creds:ro" \
    -e AWS_SHARED_CREDENTIALS_FILE=/run/nlw/aws/creds/credentials \
    -v "$PROOF_DIR/probe.py:/probe.py:ro" \
    --entrypoint python "$IMAGE" /probe.py "$service" "$BUCKET" "$@"
}
```

The probe runs the application's real startup path, `build_clients`, with the
bucket name as the only setting. It prints the verified role ARN or the
refusal message, never a credential.

<!-- file: probe.py -->
```python
"""D6 credential probe: the application's own startup check, nothing more."""

import sys
import time

from prometheus_client import REGISTRY

from nlw.core.config import Settings
from nlw.storage.s3_credentials import CredentialError, build_clients

GAUGE = "nlw_dataset_s3_credentials_expiry_timestamp_seconds"


def main() -> int:
    service, bucket = sys.argv[1], sys.argv[2]
    settings = Settings.model_construct(
        dataset_s3_bucket=bucket,
        dataset_s3_region="us-east-1",
        dataset_s3_endpoint_url=None,
        dataset_s3_path_style=False,
    )
    try:
        client, role_arn = build_clients(settings, service)
    except CredentialError as exc:
        print(f"REFUSED: {exc}")
        return 3
    print(f"ACCEPTED: {role_arn}")
    if len(sys.argv) > 4 and sys.argv[3] == "--loop":
        key, minutes = sys.argv[4], int(sys.argv[5])
        for _ in range(minutes):
            try:
                client.head_object(Bucket=bucket, Key=key)
            except Exception as exc:  # report the refusal, never a credential
                print(f"REFUSED: {type(exc).__name__}: {exc}")
                return 4
            print(f"HEAD OK; credential expiry {REGISTRY.get_sample_value(GAUGE):.0f}")
            time.sleep(60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

<!-- file: user-data.sh -->
```sh
#!/bin/bash
# Proof instance first boot: Docker only. No credential, no repository token.
set -euo pipefail
dnf install -y docker jq
systemctl enable --now docker
```

## C. Ordered proof procedure

### P00. Session files

**P00-01 · LOCAL · workstation** — session variables (type into the session
shell itself; exports only)

```bash
export REVIEWED_COMMIT="<the full commit id the owner approved for this run>"
export PROOF_ID="d6-$(date -u +%Y%m%d)-$(openssl rand -hex 3)"
export BUCKET_SUFFIX="-d6$(openssl rand -hex 6)"
export PROOF_DIR="$HOME/nlw-d6/$PROOF_ID" RUNBOOK_DIR="$PWD/docs/runbooks"
export APPROVED_ACCOUNT="<from decision E5>" ADMIN_ROLE="<role name with any path, decision E8>"
export AUDIT_RETENTION_DAYS="<from decision E1>"
export E11_IDENTITY="<iam-user-mfa or identity-center, decision E11>"
export OPERATOR_MFA_ARN="<the operator's MFA device ARN>" AUDIT_MFA_ARN="<the audit administrator's MFA device ARN>"
export BUDGET_LIMIT_USD="<decision E4>" BUDGET_EMAIL="<decision E4 recipient>"
export IMAGE="ghcr.io/atulpandey02/natural-language-workflow@sha256:<verified backend digest>"
export OPERATOR_CIDR="<the workstation's public IPv4>/32"
export OBJECT_LOCK_MODE="<GOVERNANCE or COMPLIANCE, decision E2>" E3_DECISION="<delete or retain, decision E3>"
export OPERATOR_HUMANS_JSON='["<decision E9>"]' AUDIT_ADMIN_HUMANS_JSON='["<decision E9>"]'
export AUDIT_READER_HUMANS_JSON='["<decision E9>"]'
export E12_MUST_NOT_PASS_JSON='["<decision E12: principals that must not pass the bootstrap role>"]'
```

**P00-02 · LOCAL · workstation** — verify the checkout, then extract the
reviewed steps and files (paste into `bash -s`)

```bash
set -euo pipefail
[[ "$(git rev-parse HEAD)" == "$REVIEWED_COMMIT" ]] || { echo "STOP S9: not the reviewed commit" >&2; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo "STOP S9: the checkout has local changes" >&2; exit 1; }
[[ "$E11_IDENTITY" == iam-user-mfa ]] \
  || { echo "STOP S9: this procedure supports only E11 = iam-user-mfa; Identity Center needs a reviewed trust design" >&2; exit 1; }
[[ "$(uname -s)" == Darwin && -x /usr/bin/security ]] \
  || { echo "STOP S9: the credential source is the macOS Keychain; another workstation needs a reviewed design" >&2; exit 1; }
[[ "$PROOF_DIR" != *[[:space:]]* ]] || { echo "STOP S9: PROOF_DIR must not contain spaces" >&2; exit 1; }
mkdir -m 0700 -p "$PROOF_DIR" "$PROOF_DIR/evidence" "$PROOF_DIR/steps"
python3 - "$RUNBOOK_DIR/dataset-s3-d6-proof.md" "$PROOF_DIR" <<'PY'
import hashlib, json, os, re, sys
text, out = open(sys.argv[1]).read(), sys.argv[2]
files = {}
for name, body in re.findall(r"<!-- file: ([a-z0-9.-]+) -->\n`{3}[a-z]+\n(.*?)`{3}", text, re.S):
    files[name] = body
label = re.compile(r"\*\*(P\d\d-\d\d|X\d\d) · ")
pos = 0
for block in re.finditer(r"`{3}bash\n(.*?)`{3}", text, re.S):
    ids = label.findall(text, pos, block.start())
    if ids:
        files[f"steps/{ids[-1]}.sh"] = block.group(1)
    pos = block.end()
manifest = {}
for rel, body in files.items():
    with open(os.path.join(out, rel), "w") as f:
        f.write(body)
    manifest[rel] = hashlib.sha256(body.encode()).hexdigest()
with open(os.path.join(out, "manifest.json"), "w") as f:
    json.dump(manifest, f, indent=1, sort_keys=True)
PY
chmod 0700 "$PROOF_DIR/credential-process.sh" "$PROOF_DIR/run-step"
sed -e "s#<ACCOUNT>#$APPROVED_ACCOUNT#g" -e "s#<PROOF_DIR>#$PROOF_DIR#g" -e "s#<PROOF_ID>#$PROOF_ID#g" \
  -e "s#<ADMIN_ROLE>#$ADMIN_ROLE#g" -e "s#<OPERATOR_MFA_ARN>#$OPERATOR_MFA_ARN#g" \
  -e "s#<AUDIT_MFA_ARN>#$AUDIT_MFA_ARN#g" "$PROOF_DIR/aws-config.workstation" > "$PROOF_DIR/aws-config"
if grep -qE '<[A-Z_]+>|aws_access_key_id|aws_secret_access_key|aws_session_token' "$PROOF_DIR/aws-config"; then
  echo "STOP S7: aws-config is incomplete or holds a key" >&2; exit 1
fi
git rev-parse HEAD > "$PROOF_DIR/proof-commit"
touch "$PROOF_DIR/started"
echo "extracted $(ls "$PROOF_DIR/steps" | wc -l | xargs) steps; continue with: bash \"\$PROOF_DIR/run-step\" P00-03"
```

**P00-03 · READ-ONLY · workstation** — human credentials into the Keychain
(each person enters their own key at the hidden Keychain prompt)

Each person first creates a **new** access key for their IAM user (E11)
only for this run. It is deleted in X09. Nobody writes it into a file, a
shell variable, a chat or a ticket; it is typed or pasted only into the
Keychain prompt below.

```bash
source "$PROOF_DIR/lib.sh"
for who in operator audit; do
  bash "$PROOF_DIR/credential-process.sh" "$PROOF_ID" "$who" add
  arn="$(aws sts get-caller-identity --profile "nlw-proof-human-$who" --query Arn --output text)"
  [[ "$arn" =~ ^arn:aws:iam::${ACCOUNT}:user/ ]] || stop S1 "the $who source identity is not an IAM user of the approved account (E11)"
  list="$OPERATOR_HUMANS_JSON"; [[ "$who" == operator ]] || list="$AUDIT_ADMIN_HUMANS_JSON"
  jq -e --arg a "$arn" 'index($a) != null' <<< "$list" > /dev/null \
    || stop S1 "the $who source identity is not in its decision E9 list"
  record "REC_HUMAN_$(tr a-z A-Z <<< "$who")_USER" "${arn##*/}"
  record "REC_HUMAN_$(tr a-z A-Z <<< "$who")_KEY_ID" "$(bash "$PROOF_DIR/credential-process.sh" "$PROOF_ID" "$who" key-id)"
done
validate_humans "$OPERATOR_HUMANS_JSON" "$AUDIT_ADMIN_HUMANS_JSON"
validate_humans "$AUDIT_ADMIN_HUMANS_JSON" "$OPERATOR_HUMANS_JSON"
validate_humans "$AUDIT_READER_HUMANS_JSON"
note "P00-03 two human source identities verified; keys held only in the Keychain"
```

### P01. Caller identity, account, region and tools (stop S1)

**P01-01 · READ-ONLY · workstation**

```bash
source "$PROOF_DIR/lib.sh"
aws --version | grep -Eq 'aws-cli/2\.(2[2-9]|[3-9][0-9])\.' || stop S9 "AWS CLI v2.22+ required"
got_account="$(aws sts get-caller-identity --profile nlw-proof-admin --query Account --output text)"
[[ "$got_account" == "$ACCOUNT" ]] || stop S1 "admin profile is in a different account"
aws sts get-caller-identity --profile nlw-proof-admin --query Arn --output text \
  | grep -q ":assumed-role/${ADMIN_ROLE##*/}/" || stop S1 "admin profile is not <ADMIN_ROLE>"
[[ "$(aws configure get region --profile nlw-proof-admin)" == us-east-1 ]] || stop S1 "region is not us-east-1"
aws ec2 describe-availability-zones --profile nlw-proof-admin \
  --query 'AvailabilityZones[0].RegionName' --output text | grep -qx us-east-1 || stop S1 "region mismatch"
note "P01 identity: account and region match the approved target"
```

### P02. Baseline inventory: nothing may exist yet (stop S2)

**P02-01 · READ-ONLY · workstation**

```bash
source "$PROOF_DIR/lib.sh"
for b in "$BUCKET" "$AUDIT_BUCKET"; do
  absent 404 aws s3api head-bucket --bucket "$b" --profile nlw-proof-admin
done
for r in bootstrap api ingest operator audit-admin audit-reader; do
  absent NoSuchEntity aws iam get-role --role-name "nlw-staging-dataset-$r" --profile nlw-proof-admin
done
absent NoSuchEntity aws iam get-instance-profile \
  --instance-profile-name nlw-staging-dataset-bootstrap --profile nlw-proof-admin
for a in "$KEY_ALIAS" "$AUDIT_KEY_ALIAS"; do
  absent NotFound aws kms describe-key --key-id "$a" --profile nlw-proof-admin
done
absent TrailNotFound aws cloudtrail get-trail --name "$TRAIL" --profile nlw-proof-admin
[[ -z "$(aws ec2 describe-instances --profile nlw-proof-admin \
  --filters Name=tag:Name,Values=nlw-staging-dataset-proof \
            Name=instance-state-name,Values=pending,running,stopping,stopped \
  --query 'Reservations[].Instances[].InstanceId' --output text)" ]] || stop S2 "proof instance exists"
aws cloudtrail describe-trails --profile nlw-proof-admin --include-shadow-trails \
  --query 'trailList[].[Name,IsMultiRegionTrail,IsOrganizationTrail]' --output text \
  > "$PROOF_DIR/evidence/p02-existing-trails.txt"
aws ec2 describe-vpcs --profile nlw-proof-admin --filters Name=isDefault,Values=true \
  --query 'Vpcs[0].VpcId' --output text | grep -q '^vpc-' || stop S9 "no default VPC (decision E10)"
note "P02 baseline: no dataset proof resource exists"
```

A head-bucket `403` means the name exists in another account. `absent`
reports it as S9 with the code `403`; the owner treats it as S2. Compare
`p02-existing-trails.txt` with decision E7. If no multi-region management
trail exists, stop (S9) until the owner decides.

### P03. Provision the staging-only proof resources

Each create is followed immediately by `record`. A create that fails leaves
the ledger as it was; see §F.

**P03-00 · MUTATING · workstation** — cost alert (decision E4)

An AWS Budgets alert notifies; it does not cap spending. The proof creates it
before any other resource and verifies it, so the alert exists while the
proof's costs accrue.

```bash
source "$PROOF_DIR/lib.sh"
BUDGET="nlw-staging-dataset-proof-$PROOF_ID"
jq -n --arg n "$BUDGET" --arg a "$BUDGET_LIMIT_USD" \
  '{BudgetName: $n, BudgetType: "COST", TimeUnit: "MONTHLY", BudgetLimit: {Amount: $a, Unit: "USD"}}' \
  > "$PROOF_DIR/budget.json"
jq -n --arg e "$BUDGET_EMAIL" '[{Notification: {NotificationType: "ACTUAL", ComparisonOperator: "GREATER_THAN",
  Threshold: 80, ThresholdType: "PERCENTAGE"}, Subscribers: [{SubscriptionType: "EMAIL", Address: $e}]}]' \
  > "$PROOF_DIR/budget-notify.json"
aws budgets create-budget --profile nlw-proof-admin --account-id "$ACCOUNT" \
  --budget "file://$PROOF_DIR/budget.json" --notifications-with-subscribers "file://$PROOF_DIR/budget-notify.json"
record REC_BUDGET_NAME "$BUDGET"
aws budgets describe-budget --profile nlw-proof-admin --account-id "$ACCOUNT" --budget-name "$BUDGET" \
  --query 'Budget.BudgetLimit.Amount' --output text | grep -Eq "^${BUDGET_LIMIT_USD}(\.0+)?$" \
  || stop S9 "the budget limit differs from decision E4"
aws budgets describe-notifications-for-budget --profile nlw-proof-admin --account-id "$ACCOUNT" \
  --budget-name "$BUDGET" --query 'length(Notifications)' --output text | grep -qx 1 \
  || stop S9 "the budget alert is missing"
```

`budget-notify.json` holds the recipient's address; it stays in `$PROOF_DIR`
and never enters evidence.

**P03-01 · MUTATING · workstation** — roles, trust only (no permissions yet)

```bash
source "$PROOF_DIR/lib.sh"
validate_humans "$OPERATOR_HUMANS_JSON" "$AUDIT_ADMIN_HUMANS_JSON"
validate_humans "$AUDIT_ADMIN_HUMANS_JSON" "$OPERATOR_HUMANS_JSON"
validate_humans "$AUDIT_READER_HUMANS_JSON"
TAGS=(Key=nlw-env,Value=staging "Key=nlw-proof,Value=$PROOF_ID")
mkrole() { # mkrole NAME TRUST_TEMPLATE LEDGER [HUMANS_JSON]
  HUMANS="${4:-}" render "$2" > "$PROOF_DIR/trust-$1.json"
  record "$3" "$(aws iam create-role --profile nlw-proof-admin --role-name "nlw-staging-dataset-$1" \
    --assume-role-policy-document "file://$PROOF_DIR/trust-$1.json" --max-session-duration 3600 \
    --tags "${TAGS[@]}" --query Role.Arn --output text)"
  aws iam wait role-exists --profile nlw-proof-admin --role-name "nlw-staging-dataset-$1"
}
mkrole bootstrap trust-bootstrap REC_ROLE_BOOTSTRAP
mkrole api trust-api REC_ROLE_API
mkrole ingest trust-ingest REC_ROLE_INGEST
mkrole operator trust-human-mfa REC_ROLE_OPERATOR "$OPERATOR_HUMANS_JSON"
mkrole audit-admin trust-human-mfa REC_ROLE_AUDIT_ADMIN "$AUDIT_ADMIN_HUMANS_JSON"
mkrole audit-reader trust-human-mfa REC_ROLE_AUDIT_READER "$AUDIT_READER_HUMANS_JSON"
record REC_PROFILE_BOOTSTRAP "$(aws iam create-instance-profile --profile nlw-proof-admin \
  --instance-profile-name nlw-staging-dataset-bootstrap --tags "${TAGS[@]}" \
  --query InstanceProfile.Arn --output text)"
aws iam add-role-to-instance-profile --profile nlw-proof-admin \
  --instance-profile-name nlw-staging-dataset-bootstrap --role-name nlw-staging-dataset-bootstrap
```

`*_HUMANS_JSON` are JSON lists of IAM user ARNs from decision E9, exported in
the session shell, never committed. `validate_humans` refuses a wildcard,
the account root, another account, a role, a malformed ARN, a duplicate, and
any principal shared by the operator and audit-admin lists; `render` refuses
the same and writes the list itself, so nothing else can be injected.

**P03-02 · MUTATING · workstation** — dataset key

```bash
source "$PROOF_DIR/lib.sh"
render dataset-kms-key-statements > "$PROOF_DIR/key-policy.json"
record REC_KEY_ARN "$(aws kms create-key --profile nlw-proof-admin \
  --description "nlw staging dataset objects ($PROOF_ID)" --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT --policy "file://$PROOF_DIR/key-policy.json" \
  --tags TagKey=nlw-env,TagValue=staging "TagKey=nlw-proof,TagValue=$PROOF_ID" \
  --query KeyMetadata.Arn --output text)"
aws kms create-alias --profile nlw-proof-admin --alias-name "$KEY_ALIAS" --target-key-id "$REC_KEY_ARN"
aws kms enable-key-rotation --profile nlw-proof-admin --key-id "$REC_KEY_ARN"
```

**P03-03 · MUTATING · workstation** — audit-admin permissions, phase 1

```bash
source "$PROOF_DIR/lib.sh"
export REC_KEY_ARN
REC_AUDIT_KEY_ARN="arn:aws:kms:us-east-1:${ACCOUNT}:key/pending" render role-audit-admin \
  | jq '.Statement |= map(select(.Sid != "AdministerAuditKey"))' > "$PROOF_DIR/policy-audit-admin.json"
aws iam put-role-policy --profile nlw-proof-admin --role-name nlw-staging-dataset-audit-admin \
  --policy-name nlw-dataset-audit-admin --policy-document "file://$PROOF_DIR/policy-audit-admin.json"
```

Phase 1 drops the only statement that names the audit key, which does not
exist yet. The audit key policy itself (P03-04) already lets this role manage
the key.

**P03-04 · MUTATING · workstation** — audit key (as audit administrator, MFA)

```bash
source "$PROOF_DIR/lib.sh"
render audit-kms-key-statements > "$PROOF_DIR/audit-key-policy.json"
record REC_AUDIT_KEY_ARN "$(aws kms create-key --profile nlw-proof-audit-admin \
  --description "nlw staging dataset audit logs ($PROOF_ID)" --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT --policy "file://$PROOF_DIR/audit-key-policy.json" \
  --tags TagKey=nlw-env,TagValue=staging "TagKey=nlw-proof,TagValue=$PROOF_ID" \
  --query KeyMetadata.Arn --output text)"
aws kms create-alias --profile nlw-proof-audit-admin --alias-name "$AUDIT_KEY_ALIAS" \
  --target-key-id "$REC_AUDIT_KEY_ARN"
aws kms enable-key-rotation --profile nlw-proof-audit-admin --key-id "$REC_AUDIT_KEY_ARN"
```

**P03-05 · MUTATING · workstation** — audit-admin phase 2 and audit-reader permissions

```bash
source "$PROOF_DIR/lib.sh"
export REC_KEY_ARN REC_AUDIT_KEY_ARN
render role-audit-admin > "$PROOF_DIR/policy-audit-admin.json"
render role-audit-reader > "$PROOF_DIR/policy-audit-reader.json"
aws iam put-role-policy --profile nlw-proof-admin --role-name nlw-staging-dataset-audit-admin \
  --policy-name nlw-dataset-audit-admin --policy-document "file://$PROOF_DIR/policy-audit-admin.json"
aws iam put-role-policy --profile nlw-proof-admin --role-name nlw-staging-dataset-audit-reader \
  --policy-name nlw-dataset-audit-reader --policy-document "file://$PROOF_DIR/policy-audit-reader.json"
```

**P03-06 · MUTATING · workstation** — dataset bucket

```bash
source "$PROOF_DIR/lib.sh"
export REC_KEY_ARN
# In us-east-1, CreateBucket returns success for a bucket this account already
# owns. Absence is checked in this same block, and the new bucket must be
# pristine before anything is configured.
absent 404 aws s3api head-bucket --profile nlw-proof-admin --bucket "$BUCKET"
note "absence confirmed: $BUCKET"
aws s3api create-bucket --profile nlw-proof-admin --bucket "$BUCKET" --object-ownership BucketOwnerEnforced
absent NoSuchTagSet aws s3api get-bucket-tagging --profile nlw-proof-admin --bucket "$BUCKET"
absent NoSuchBucketPolicy aws s3api get-bucket-policy --profile nlw-proof-admin --bucket "$BUCKET"
[[ "$(aws s3api list-object-versions --profile nlw-proof-admin --bucket "$BUCKET" --max-items 1 \
  --query 'sum([length(Versions || `[]`), length(DeleteMarkers || `[]`)])' --output text)" == 0 ]] \
  || stop S2 "the dataset bucket is not new: it holds objects"
record REC_BUCKET "$BUCKET"
aws s3api put-public-access-block --profile nlw-proof-admin --bucket "$BUCKET" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-tagging --profile nlw-proof-admin --bucket "$BUCKET" \
  --tagging "TagSet=[{Key=nlw-env,Value=staging},{Key=nlw-proof,Value=$PROOF_ID}]"
aws s3api put-bucket-versioning --profile nlw-proof-admin --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled
jq -n --arg k "$REC_KEY_ARN" '{Rules: [{ApplyServerSideEncryptionByDefault:
  {SSEAlgorithm: "aws:kms", KMSMasterKeyID: $k}, BucketKeyEnabled: true}]}' > "$PROOF_DIR/enc.json"
aws s3api put-bucket-encryption --profile nlw-proof-admin --bucket "$BUCKET" \
  --server-side-encryption-configuration "file://$PROOF_DIR/enc.json"
render dataset-bucket-lifecycle > "$PROOF_DIR/lifecycle.json"
aws s3api put-bucket-lifecycle-configuration --profile nlw-proof-admin --bucket "$BUCKET" \
  --lifecycle-configuration "file://$PROOF_DIR/lifecycle.json"
render dataset-bucket-policy > "$PROOF_DIR/bucket-policy.json"
aws s3api put-bucket-policy --profile nlw-proof-admin --bucket "$BUCKET" \
  --policy "file://$PROOF_DIR/bucket-policy.json"
```

**P03-07 · MUTATING · workstation** — audit bucket (as audit administrator)

```bash
source "$PROOF_DIR/lib.sh"
export REC_KEY_ARN REC_AUDIT_KEY_ARN
absent 404 aws s3api head-bucket --profile nlw-proof-audit-admin --bucket "$AUDIT_BUCKET"
note "absence confirmed: $AUDIT_BUCKET"
aws s3api create-bucket --profile nlw-proof-audit-admin --bucket "$AUDIT_BUCKET" \
  --object-ownership BucketOwnerEnforced --object-lock-enabled-for-bucket
absent NoSuchTagSet aws s3api get-bucket-tagging --profile nlw-proof-audit-admin --bucket "$AUDIT_BUCKET"
absent NoSuchBucketPolicy aws s3api get-bucket-policy --profile nlw-proof-audit-admin --bucket "$AUDIT_BUCKET"
[[ "$(aws s3api list-object-versions --profile nlw-proof-audit-admin --bucket "$AUDIT_BUCKET" --max-items 1 \
  --query 'sum([length(Versions || `[]`), length(DeleteMarkers || `[]`)])' --output text)" == 0 ]] \
  || stop S2 "the audit bucket is not new: it holds objects"
record REC_AUDIT_BUCKET "$AUDIT_BUCKET"
aws s3api put-public-access-block --profile nlw-proof-audit-admin --bucket "$AUDIT_BUCKET" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-tagging --profile nlw-proof-audit-admin --bucket "$AUDIT_BUCKET" \
  --tagging "TagSet=[{Key=nlw-env,Value=staging},{Key=nlw-proof,Value=$PROOF_ID}]"
jq -n --arg k "$REC_AUDIT_KEY_ARN" '{Rules: [{ApplyServerSideEncryptionByDefault:
  {SSEAlgorithm: "aws:kms", KMSMasterKeyID: $k}, BucketKeyEnabled: false}]}' > "$PROOF_DIR/audit-enc.json"
aws s3api put-bucket-encryption --profile nlw-proof-audit-admin --bucket "$AUDIT_BUCKET" \
  --server-side-encryption-configuration "file://$PROOF_DIR/audit-enc.json"
jq -n --argjson d "$AUDIT_RETENTION_DAYS" --arg m "$OBJECT_LOCK_MODE" \
  '{ObjectLockEnabled: "Enabled", Rule: {DefaultRetention: {Mode: $m, Days: $d}}}' > "$PROOF_DIR/lock.json"
aws s3api put-object-lock-configuration --profile nlw-proof-audit-admin --bucket "$AUDIT_BUCKET" \
  --object-lock-configuration "file://$PROOF_DIR/lock.json"
render audit-bucket-lifecycle > "$PROOF_DIR/audit-lifecycle.json"
aws s3api put-bucket-lifecycle-configuration --profile nlw-proof-audit-admin --bucket "$AUDIT_BUCKET" \
  --lifecycle-configuration "file://$PROOF_DIR/audit-lifecycle.json"
render audit-bucket-policy > "$PROOF_DIR/audit-bucket-policy.json"
aws s3api put-bucket-policy --profile nlw-proof-audit-admin --bucket "$AUDIT_BUCKET" \
  --policy "file://$PROOF_DIR/audit-bucket-policy.json"
```

`OBJECT_LOCK_MODE` is `GOVERNANCE` or `COMPLIANCE` (decision E2). COMPLIANCE
cannot be shortened or removed by anyone, including the account root, and the
bucket cannot be deleted until every object's retention ends.

`create-bucket`'s own `--object-ownership` and `--object-lock-enabled-for-bucket`
flags take effect in the same request. What us-east-1 does with them when it
returns success for a bucket the account already owns is not documented; it
stays an open question for D6 (the pristine checks still stop the run).

**Remaining name race (documented, not closable).** Between `HeadBucket`
and `CreateBucket`, a principal in the same account could create the same
name; `CreateBucket` would then succeed on it. The 12-hex-digit proof suffix
makes an accidental collision negligible, and the pristine checks catch any
bucket that already has tags, a policy or objects. A deliberately raced,
empty, unconfigured bucket from an insider with `s3:CreateBucket` would pass
them; that insider could equally alter the proof's bucket afterwards, which
the management-event trail (E7) records.

**P03-08 · MUTATING · workstation** — trail (as audit administrator)

```bash
source "$PROOF_DIR/lib.sh"
record REC_TRAIL_ARN "$(aws cloudtrail create-trail --profile nlw-proof-audit-admin --name "$TRAIL" \
  --s3-bucket-name "$AUDIT_BUCKET" --s3-key-prefix dataset-data-events \
  --kms-key-id "$REC_AUDIT_KEY_ARN" --enable-log-file-validation \
  --no-include-global-service-events --no-is-multi-region-trail \
  --tags-list Key=nlw-env,Value=staging "Key=nlw-proof,Value=$PROOF_ID" \
  --query TrailARN --output text)"
[[ "$REC_TRAIL_ARN" == "$TRAIL_ARN" ]] || stop S9 "trail ARN differs from the template"
render trail-advanced-event-selectors > "$PROOF_DIR/selectors.json"
aws cloudtrail put-event-selectors --profile nlw-proof-audit-admin --trail-name "$TRAIL_ARN" \
  --advanced-event-selectors "file://$PROOF_DIR/selectors.json"
aws cloudtrail start-logging --profile nlw-proof-audit-admin --name "$TRAIL_ARN"
```

**P03-09 · MUTATING · workstation** — dataset role permissions (last, so no
runtime role can act before encryption, policy and audit are in place)

```bash
source "$PROOF_DIR/lib.sh"
export REC_KEY_ARN REC_AUDIT_KEY_ARN
for r in bootstrap api ingest operator; do
  render "role-$r" > "$PROOF_DIR/policy-$r.json"
  aws iam put-role-policy --profile nlw-proof-admin --role-name "nlw-staging-dataset-$r" \
    --policy-name "nlw-dataset-$r" --policy-document "file://$PROOF_DIR/policy-$r.json"
done
```

**P03-10 · MUTATING · workstation** — disposable proof instance

```bash
source "$PROOF_DIR/lib.sh"
VPC="$(aws ec2 describe-vpcs --profile nlw-proof-admin --filters Name=isDefault,Values=true \
  --query 'Vpcs[0].VpcId' --output text)"
AMI="$(aws ssm get-parameters --profile nlw-proof-admin \
  --names /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64 \
  --query 'Parameters[0].Value' --output text)"
record REC_SG_ID "$(aws ec2 create-security-group --profile nlw-proof-admin \
  --group-name nlw-staging-dataset-proof-ssh --description "nlw D6 proof SSH ($PROOF_ID)" --vpc-id "$VPC" \
  --tag-specifications "ResourceType=security-group,Tags=[{Key=nlw-env,Value=staging},{Key=nlw-proof,Value=$PROOF_ID}]" \
  --query GroupId --output text)"
aws ec2 authorize-security-group-ingress --profile nlw-proof-admin --group-id "$REC_SG_ID" \
  --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$OPERATOR_CIDR}]"
record REC_INSTANCE_ID "$(aws ec2 run-instances --profile nlw-proof-admin --image-id "$AMI" \
  --instance-type t3.small --count 1 --security-group-ids "$REC_SG_ID" \
  --iam-instance-profile Name=nlw-staging-dataset-bootstrap \
  --metadata-options HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled \
  --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=16,VolumeType=gp3,Encrypted=true,DeleteOnTermination=true}' \
  --user-data "file://$PROOF_DIR/user-data.sh" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=nlw-staging-dataset-proof},{Key=nlw-env,Value=staging},{Key=nlw-proof,Value=$PROOF_ID}]" \
  --query 'Instances[0].InstanceId' --output text)"
aws ec2 wait instance-status-ok --profile nlw-proof-admin --instance-ids "$REC_INSTANCE_ID"
```

**P03-11 · READ-ONLY · workstation** — deployed policies and settings equal the rendered templates

Compared after `normalize-policy.py`: every role's trust policy and inline
policy, both key policies, both bucket policies, both lifecycle rules, the
trail's event selectors, both buckets' encryption, the dataset bucket's
versioning, the audit bucket's Object Lock, key rotation, and the instance
metadata options. Any difference stops the run (S9); the template is never
edited to match.

```bash
source "$PROOF_DIR/lib.sh"
aws s3api get-bucket-encryption --profile nlw-proof-admin --bucket "$BUCKET" \
  --query 'ServerSideEncryptionConfiguration.Rules[0].[ApplyServerSideEncryptionByDefault.KMSMasterKeyID,BucketKeyEnabled]' \
  --output text | grep -qx "$REC_KEY_ARN	True" || stop S9 "dataset bucket encryption differs"
aws s3api get-bucket-versioning --profile nlw-proof-admin --bucket "$BUCKET" --query Status --output text \
  | grep -qx Enabled || stop S9 "dataset bucket versioning off"
same() { # same LABEL DEPLOYED_JSON RENDERED_FILE: equal after normalization, or S9
  diff -q <(python3 "$PROOF_DIR/normalize-policy.py" <<< "$2") \
    <(python3 "$PROOF_DIR/normalize-policy.py" < "$3") > /dev/null || stop S9 "$1 differs from the rendered template"
}
for r in bootstrap api ingest operator audit-admin audit-reader; do
  same "trust policy of $r" "$(aws iam get-role --profile nlw-proof-admin --role-name "nlw-staging-dataset-$r" \
    --query Role.AssumeRolePolicyDocument --output json)" "$PROOF_DIR/trust-$r.json"
  same "inline policy of $r" "$(aws iam get-role-policy --profile nlw-proof-admin --role-name "nlw-staging-dataset-$r" \
    --policy-name "nlw-dataset-$r" --query PolicyDocument --output json)" "$PROOF_DIR/policy-$r.json"
done
same "dataset key policy" "$(aws kms get-key-policy --profile nlw-proof-admin --key-id "$REC_KEY_ARN" \
  --policy-name default --query Policy --output json)" "$PROOF_DIR/key-policy.json"
same "audit key policy" "$(aws kms get-key-policy --profile nlw-proof-audit-admin --key-id "$REC_AUDIT_KEY_ARN" \
  --policy-name default --query Policy --output json)" "$PROOF_DIR/audit-key-policy.json"
same "dataset bucket policy" "$(aws s3api get-bucket-policy --profile nlw-proof-admin --bucket "$BUCKET" \
  --query Policy --output json)" "$PROOF_DIR/bucket-policy.json"
same "audit bucket policy" "$(aws s3api get-bucket-policy --profile nlw-proof-audit-admin --bucket "$AUDIT_BUCKET" \
  --query Policy --output json)" "$PROOF_DIR/audit-bucket-policy.json"
same "dataset lifecycle" "$(aws s3api get-bucket-lifecycle-configuration --profile nlw-proof-admin \
  --bucket "$BUCKET" --output json)" "$PROOF_DIR/lifecycle.json"
same "audit lifecycle" "$(aws s3api get-bucket-lifecycle-configuration --profile nlw-proof-audit-admin \
  --bucket "$AUDIT_BUCKET" --output json)" "$PROOF_DIR/audit-lifecycle.json"
aws s3api get-object-lock-configuration --profile nlw-proof-audit-admin --bucket "$AUDIT_BUCKET" \
  --query 'ObjectLockConfiguration.Rule.DefaultRetention.[Mode,Days]' --output text \
  | grep -qx "${OBJECT_LOCK_MODE}	${AUDIT_RETENTION_DAYS}" || stop S9 "audit Object Lock differs"
aws cloudtrail get-trail-status --profile nlw-proof-audit-admin --name "$TRAIL_ARN" \
  --query IsLogging --output text | grep -qx True || stop S6 "trail is not logging"
same "event selectors" "$(aws cloudtrail get-event-selectors --profile nlw-proof-audit-admin \
  --trail-name "$TRAIL_ARN" --query AdvancedEventSelectors --output json)" "$PROOF_DIR/selectors.json"
for k in "$REC_KEY_ARN"; do
  aws kms get-key-rotation-status --profile nlw-proof-admin --key-id "$k" \
    --query KeyRotationEnabled --output text | grep -qx True || stop S9 "key rotation off"
done
aws ec2 describe-instances --profile nlw-proof-admin --instance-ids "$REC_INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].MetadataOptions.[HttpTokens,HttpPutResponseHopLimit]' \
  --output text | grep -qx "required	1" || stop S5 "instance metadata options differ"
for r in bootstrap api ingest operator audit-admin audit-reader; do
  [[ "$(aws iam simulate-principal-policy --profile nlw-proof-admin \
    --policy-source-arn "$ROLE_PREFIX/nlw-staging-dataset-$r" \
    --action-names iam:PassRole ec2:AssociateIamInstanceProfile \
    --resource-arns "$ROLE_PREFIX/nlw-staging-dataset-bootstrap" \
    --query 'EvaluationResults[].EvalDecision' --output text | tr '\t' '\n' | sort -u)" == explicitDeny ]] \
    || stop S4 "nlw-staging-dataset-$r is not explicitly denied passing the bootstrap role"
done
for principal in $(jq -r '.[]' <<< "${E12_MUST_NOT_PASS_JSON:-[]}"); do
  [[ "$(aws iam simulate-principal-policy --profile nlw-proof-admin --policy-source-arn "$principal" \
    --action-names iam:PassRole --resource-arns "$ROLE_PREFIX/nlw-staging-dataset-bootstrap" \
    --query 'EvaluationResults[0].EvalDecision' --output text)" != allowed ]] \
    || stop S4 "a principal decision E12 excludes can pass the bootstrap role"
done
note "P03 provisioned state matches the templates"
```

**P03-12 · MUTATING · workstation** — open the proof session

```bash
source "$PROOF_DIR/lib.sh"
ssh-keygen -q -t ed25519 -N '' -f "$PROOF_DIR/proof-key"
HOST="$(aws ec2 describe-instances --profile nlw-proof-admin --instance-ids "$REC_INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicDnsName' --output text)"
aws ec2-instance-connect send-ssh-public-key --profile nlw-proof-admin --instance-id "$REC_INSTANCE_ID" \
  --instance-os-user ec2-user --ssh-public-key "file://$PROOF_DIR/proof-key.pub" --query Success --output text
B="$PROOF_DIR/instance-bundle"
mkdir -m 0700 -p "$B"
cp -R "$PROOF_DIR/steps" "$PROOF_DIR/lib.sh" "$PROOF_DIR/probe.py" "$PROOF_DIR/run-step" \
  "$PROOF_DIR/manifest.json" "$PROOF_DIR/credential-process.sh" "$PROOF_DIR/normalize-policy.py" \
  "$PROOF_DIR/user-data.sh" "$PROOF_DIR/aws-config.workstation" "$PROOF_DIR/aws-config.instance" \
  "$PROOF_DIR/created.env" "$B/"
printf 'export PROOF_ID=%q APPROVED_ACCOUNT=%q BUCKET_SUFFIX=%q IMAGE=%q\n' \
  "$PROOF_ID" "$APPROVED_ACCOUNT" "$BUCKET_SUFFIX" "$IMAGE" > "$B/instance-env.sh"
printf 'export PROOF_DIR="$HOME/proof" RUNBOOK_DIR=/nonexistent\n' >> "$B/instance-env.sh"
scp -r -i "$PROOF_DIR/proof-key" -o StrictHostKeyChecking=accept-new "$B" "ec2-user@$HOST:proof"
```

The pushed key is valid for 60 seconds; repeat the last two commands, then
`ssh -i "$PROOF_DIR/proof-key" "ec2-user@$HOST"` to open the session. In that
session, run `source ~/proof/instance-env.sh` once; every `proof instance`
step then runs as `bash ~/proof/run-step <step id>`. The bundle holds no
credential: the instance uses its instance profile.

**P03-13 · HOST · proof instance** — session setup and the IMDS block

```bash
source "$PROOF_DIR/lib.sh"
chmod 0700 "$PROOF_DIR"
sed -e "s/<ACCOUNT>/$APPROVED_ACCOUNT/g" "$PROOF_DIR/aws-config.instance" > "$PROOF_DIR/aws-config"
sudo iptables -I DOCKER-USER -d 169.254.169.254/32 -j DROP
sudo iptables -C DOCKER-USER -d 169.254.169.254/32 -j DROP || stop S5 "IMDS drop rule missing"
sudo docker pull -q "$IMAGE" >/dev/null || stop S9 "anonymous image pull failed; no registry token is brought to the host"
```

**P03-14 · READ-ONLY · proof instance** — identities and IMDS from containers (stop S5)

```bash
source "$PROOF_DIR/lib.sh"
aws sts get-caller-identity --profile proof-bootstrap --query Arn --output text \
  | grep -q ':assumed-role/nlw-staging-dataset-bootstrap/' || stop S1 "instance identity is not bootstrap"
aws sts get-caller-identity --profile proof-api --query Arn --output text \
  | grep -q ':assumed-role/nlw-staging-dataset-api/nlw-staging-api$' || stop S9 "api identity"
aws sts get-caller-identity --profile proof-ingest --query Arn --output text \
  | grep -q ':assumed-role/nlw-staging-dataset-ingest/nlw-staging-ingest$' || stop S9 "ingest identity"
if sudo docker run --rm --entrypoint python "$IMAGE" -c '
import urllib.request
r = urllib.request.Request("http://169.254.169.254/latest/api/token", method="PUT",
    headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
urllib.request.urlopen(r, timeout=3)'; then stop S5 "IMDS reachable from an application container"; fi
note "P03-14 IMDS unreachable from a bridge-network container"
```

### P04. API conditional object creation

Objects are random bytes, never customer data. Keys follow the ADR-033
layout, `versions/<workspace>/<dataset>/<version>/source.csv`.

**P04-01 · MUTATING · proof instance**

```bash
source "$PROOF_DIR/lib.sh"
PROOF_WS="$(uuidgen)"; PROOF_WS2="$(uuidgen)"
record REC_PROOF_WS "$PROOF_WS"; record REC_PROOF_WS2 "$PROOF_WS2"
K1="versions/$PROOF_WS/$(uuidgen)/$(uuidgen)/source.csv"
head -c 1048576 /dev/urandom > "$PROOF_DIR/obj1.bin"
SHA1="$(openssl dgst -sha256 -binary "$PROOF_DIR/obj1.bin" | base64)"
V1="$(aws s3api put-object --profile proof-api --bucket "$BUCKET" --key "$K1" \
  --body "$PROOF_DIR/obj1.bin" --if-none-match '*' \
  --server-side-encryption aws:kms --ssekms-key-id "$REC_KEY_ARN" --bucket-key-enabled \
  --checksum-algorithm SHA256 --checksum-sha256 "$SHA1" --query VersionId --output text)"
record REC_OBJ_K1 "$K1"; record REC_OBJ_K1_VERSION "$V1"
expect_event nlw-staging-dataset-api PutObject "$K1" -
```

### P05. Duplicate and unconditional writes are refused

**P05-01 · MUTATING · proof instance · EXPECT-DENIED**

```bash
source "$PROOF_DIR/lib.sh"
expect_error PreconditionFailed aws s3api put-object --profile proof-api --bucket "$BUCKET" \
  --key "$REC_OBJ_K1" --body "$PROOF_DIR/obj1.bin" --if-none-match '*' \
  --server-side-encryption aws:kms --ssekms-key-id "$REC_KEY_ARN" --bucket-key-enabled
expect_denied aws s3api put-object --profile proof-api --bucket "$BUCKET" \
  --key "$REC_OBJ_K1" --body "$PROOF_DIR/obj1.bin" \
  --server-side-encryption aws:kms --ssekms-key-id "$REC_KEY_ARN" --bucket-key-enabled
expect_event nlw-staging-dataset-api PutObject "$REC_OBJ_K1" AccessDenied
expect_denied aws s3api put-object --profile proof-api --bucket "$BUCKET" \
  --key "outside/$REC_PROOF_WS/x" --body "$PROOF_DIR/obj1.bin" --if-none-match '*' \
  --server-side-encryption aws:kms --ssekms-key-id "$REC_KEY_ARN" --bucket-key-enabled
expect_denied aws s3api copy-object --profile proof-api --bucket "$BUCKET" \
  --copy-source "$BUCKET/$REC_OBJ_K1" --key "versions/$REC_PROOF_WS/copy/$(uuidgen)/source.csv" \
  --if-none-match '*' --server-side-encryption aws:kms --ssekms-key-id "$REC_KEY_ARN"
```

**P05-02 · MUTATING · proof instance** — simultaneous writes: exactly one wins

```bash
source "$PROOF_DIR/lib.sh"
K2="versions/$REC_PROOF_WS/$(uuidgen)/$(uuidgen)/source.csv"
record REC_OBJ_K2 "$K2"
for i in 1 2 3 4; do
  ( aws s3api put-object --profile proof-api --bucket "$BUCKET" --key "$K2" \
      --body "$PROOF_DIR/obj1.bin" --if-none-match '*' \
      --server-side-encryption aws:kms --ssekms-key-id "$REC_KEY_ARN" --bucket-key-enabled \
      --query VersionId --output text > "$PROOF_DIR/race-$i.out" 2> "$PROOF_DIR/race-$i.err" \
    && echo ok > "$PROOF_DIR/race-$i.status" || echo fail > "$PROOF_DIR/race-$i.status" ) &
done
wait
[[ "$(cat "$PROOF_DIR"/race-*.status | grep -c ok)" == 1 ]] || stop S4 "more or fewer than one write won"
grep -hoE '\((PreconditionFailed|ConditionalRequestConflict)\)' "$PROOF_DIR"/race-*.err | wc -l \
  | grep -qx ' *3' || stop S9 "losers did not fail with 412/409"
record REC_OBJ_K2_VERSION "$(cat "$(grep -l ok "$PROOF_DIR"/race-*.status | sed 's/status$/out/')")"
```

### P06. Required encryption headers and stored KMS encryption

**P06-01 · MUTATING · proof instance · EXPECT-DENIED** — E-ALG-MISSING,
E-KEY-MISSING, E-ALG-WRONG, E-KEY-WRONG, each as `PutObject` and
`CreateMultipartUpload`

```bash
source "$PROOF_DIR/lib.sh"
K="versions/$REC_PROOF_WS/$(uuidgen)/$(uuidgen)/source.csv"
WRONG_KEY="arn:aws:kms:us-east-1:${ACCOUNT}:key/00000000-0000-0000-0000-000000000000"
KEY_ID="${REC_KEY_ARN##*/}"
cases=(
  ""                                                          # E-ALG-MISSING
  "--server-side-encryption aws:kms"                          # E-KEY-MISSING
  "--server-side-encryption AES256"                           # E-ALG-WRONG
  "--server-side-encryption aws:kms:dsse --ssekms-key-id $REC_KEY_ARN"   # E-ALG-WRONG
  "--server-side-encryption aws:kms --ssekms-key-id $WRONG_KEY"          # E-KEY-WRONG (other key)
  "--server-side-encryption aws:kms --ssekms-key-id $KEY_ALIAS"          # E-KEY-WRONG (alias)
  "--server-side-encryption aws:kms --ssekms-key-id $KEY_ID"             # E-KEY-WRONG (bare id)
)
for c in "${cases[@]}"; do
  # shellcheck disable=SC2086
  expect_denied aws s3api put-object --profile proof-api --bucket "$BUCKET" --key "$K" \
    --body "$PROOF_DIR/obj1.bin" --if-none-match '*' $c
  # shellcheck disable=SC2086
  expect_denied aws s3api create-multipart-upload --profile proof-api --bucket "$BUCKET" --key "$K" $c
done
```

**P06-02 · READ-ONLY · proof instance** — E-OK and E-STORED

```bash
source "$PROOF_DIR/lib.sh"
for k in "$REC_OBJ_K1" "$REC_OBJ_K2"; do
  aws s3api head-object --profile proof-api --bucket "$BUCKET" --key "$k" \
    --query '[ServerSideEncryption,SSEKMSKeyId,BucketKeyEnabled]' --output text \
    | grep -qx "aws:kms	$REC_KEY_ARN	True" || stop S9 "stored encryption differs for $k"
  expect_event nlw-staging-dataset-api HeadObject "$k" -
done
note "P06 E-OK and E-STORED: every object is SSE-KMS with the staging key and a Bucket Key"
```

### P07. Multipart uploads under the encryption policy (E-MPU; stop S3)

This is the open question from the provisioning review: do the
encryption-header denies refuse `UploadPart` or `CompleteMultipartUpload`,
which carry no encryption headers? If the correctly headed flow is refused,
stop with S3. No exception is added to the policy.

**P07-01 · MUTATING · proof instance** — the correctly headed flow succeeds

```bash
source "$PROOF_DIR/lib.sh"
K3="versions/$REC_PROOF_WS/$(uuidgen)/$(uuidgen)/source.csv"
head -c $((5 * 1048576)) /dev/urandom > "$PROOF_DIR/part1.bin"
head -c 1048576 /dev/urandom > "$PROOF_DIR/part2.bin"
U="$(aws s3api create-multipart-upload --profile proof-api --bucket "$BUCKET" --key "$K3" \
  --server-side-encryption aws:kms --ssekms-key-id "$REC_KEY_ARN" --bucket-key-enabled \
  --checksum-algorithm SHA256 --query UploadId --output text)" || stop S3 "headed CreateMultipartUpload refused"
record REC_MPU_K3 "$K3"; record REC_MPU_K3_UPLOAD "$U"
for n in 1 2; do
  aws s3api upload-part --profile proof-api --bucket "$BUCKET" --key "$K3" --upload-id "$U" \
    --part-number "$n" --body "$PROOF_DIR/part$n.bin" --checksum-algorithm SHA256 \
    --query '{ETag: ETag, ChecksumSHA256: ChecksumSHA256}' --output json > "$PROOF_DIR/part$n.json" \
    || stop S3 "UploadPart refused under the encryption policy"
done
jq -s '{Parts: [to_entries[] | .value + {PartNumber: (.key + 1)}]}' \
  "$PROOF_DIR/part1.json" "$PROOF_DIR/part2.json" > "$PROOF_DIR/parts.json"
expect_denied aws s3api complete-multipart-upload --profile proof-api --bucket "$BUCKET" --key "$K3" \
  --upload-id "$U" --multipart-upload "file://$PROOF_DIR/parts.json"
V3="$(aws s3api complete-multipart-upload --profile proof-api --bucket "$BUCKET" --key "$K3" \
  --upload-id "$U" --multipart-upload "file://$PROOF_DIR/parts.json" --if-none-match '*' \
  --query VersionId --output text)" || stop S3 "CompleteMultipartUpload refused under the encryption policy"
record REC_OBJ_K3 "$K3"; record REC_OBJ_K3_VERSION "$V3"
for e in CreateMultipartUpload UploadPart CompleteMultipartUpload; do expect_event nlw-staging-dataset-api "$e" "$K3" -; done
expect_event nlw-staging-dataset-api CompleteMultipartUpload "$K3" AccessDenied
aws s3api head-object --profile proof-api --bucket "$BUCKET" --key "$K3" \
  --query '[ServerSideEncryption,SSEKMSKeyId,BucketKeyEnabled]' --output text \
  | grep -qx "aws:kms	$REC_KEY_ARN	True" || stop S9 "multipart object encryption differs"
aws s3api get-object-attributes --profile proof-api --bucket "$BUCKET" --key "$K3" \
  --object-attributes Checksum ObjectParts --query 'Checksum.ChecksumType' --output text \
  | grep -qx COMPOSITE || stop S9 "multipart checksum is not composite"
```

**P07-02 · MUTATING · proof instance** — a second completion and an abort

```bash
source "$PROOF_DIR/lib.sh"
U2="$(aws s3api create-multipart-upload --profile proof-api --bucket "$BUCKET" --key "$REC_OBJ_K3" \
  --server-side-encryption aws:kms --ssekms-key-id "$REC_KEY_ARN" --bucket-key-enabled \
  --checksum-algorithm SHA256 --query UploadId --output text)"
record REC_MPU_K3_UPLOAD2 "$U2"
aws s3api upload-part --profile proof-api --bucket "$BUCKET" --key "$REC_OBJ_K3" --upload-id "$U2" \
  --part-number 1 --body "$PROOF_DIR/part2.bin" --checksum-algorithm SHA256 \
  --query '{ETag: ETag, ChecksumSHA256: ChecksumSHA256}' --output json > "$PROOF_DIR/u2p1.json"
jq '{Parts: [. + {PartNumber: 1}]}' "$PROOF_DIR/u2p1.json" > "$PROOF_DIR/u2parts.json"
expect_error PreconditionFailed aws s3api complete-multipart-upload --profile proof-api --bucket "$BUCKET" \
  --key "$REC_OBJ_K3" --upload-id "$U2" --multipart-upload "file://$PROOF_DIR/u2parts.json" --if-none-match '*'
aws s3api abort-multipart-upload --profile proof-api --bucket "$BUCKET" --key "$REC_OBJ_K3" --upload-id "$U2"
expect_event nlw-staging-dataset-api AbortMultipartUpload "$REC_OBJ_K3" -
note "P07 E-MPU: the headed multipart flow works; duplicate completion 412; abort works"
```

The lifecycle rule `abort-incomplete-multipart` is shown by P03-11's policy
comparison. Observing an abandoned upload's removal takes a day; it is
optional and recorded only if the owner keeps the resources (E3).

### P08. API metadata operations and the accepted `GetObject` residual risk

**P08-01 · READ-ONLY · proof instance**

```bash
source "$PROOF_DIR/lib.sh"
aws s3api get-object-attributes --profile proof-api --bucket "$BUCKET" --key "$REC_OBJ_K1" \
  --object-attributes ETag Checksum ObjectSize --query ObjectSize --output text | grep -qx 1048576 \
  || stop S9 "GetObjectAttributes"
expect_event nlw-staging-dataset-api GetObjectAttributes "$REC_OBJ_K1" -
# Residual risk R1 (ADR-033 note 1): the API role CAN read object bytes because
# HeadObject needs s3:GetObject. Record that it is allowed AND audited.
aws s3api get-object --profile proof-api --bucket "$BUCKET" --key "$REC_OBJ_K1" "$PROOF_DIR/r1.bin" \
  --query ContentLength --output text >/dev/null
rm -f "$PROOF_DIR/r1.bin"
expect_event nlw-staging-dataset-api GetObject "$REC_OBJ_K1" -
note "P08 residual R1 recorded: API GetObject allowed and expected in the trail"
```

**P08-02 · READ-ONLY · proof instance · EXPECT-DENIED**

```bash
source "$PROOF_DIR/lib.sh"
expect_denied aws s3api list-objects-v2 --profile proof-api --bucket "$BUCKET" --prefix versions/ --max-items 1
expect_denied aws s3api list-object-versions --profile proof-api --bucket "$BUCKET" --prefix versions/ --max-items 1
expect_denied aws sts get-caller-identity --profile proof-api-wrong-session
```

### P09. Ingest reads only the staging `versions/` prefix

**P09-01 · MUTATING · proof instance** — an object in a second workspace

```bash
source "$PROOF_DIR/lib.sh"
K4="versions/$REC_PROOF_WS2/$(uuidgen)/$(uuidgen)/source.csv"
record REC_OBJ_K4 "$K4"
record REC_OBJ_K4_VERSION "$(aws s3api put-object --profile proof-api --bucket "$BUCKET" --key "$K4" \
  --body "$PROOF_DIR/obj1.bin" --if-none-match '*' \
  --server-side-encryption aws:kms --ssekms-key-id "$REC_KEY_ARN" --bucket-key-enabled \
  --query VersionId --output text)"
```

**P09-02 · READ-ONLY · proof instance** — ingest reads, and residual risk R2

```bash
source "$PROOF_DIR/lib.sh"
aws s3api get-object --profile proof-ingest --bucket "$BUCKET" --key "$REC_OBJ_K1" "$PROOF_DIR/in.bin" \
  --query ContentLength --output text >/dev/null
cmp -s "$PROOF_DIR/in.bin" "$PROOF_DIR/obj1.bin" || stop S9 "ingest read differs from the written bytes"
rm -f "$PROOF_DIR/in.bin"
expect_event nlw-staging-dataset-ingest GetObject "$REC_OBJ_K1" -
# Residual risk R2 (ADR-033 note 2): IAM scope is the whole prefix. The ingest
# role can read an object of ANOTHER workspace; the application, not IAM,
# restricts it to the claimed version. Record that this is allowed and audited.
aws s3api get-object --profile proof-ingest --bucket "$BUCKET" --key "$REC_OBJ_K4" "$PROOF_DIR/in.bin" \
  --query ContentLength --output text >/dev/null
rm -f "$PROOF_DIR/in.bin"
expect_event nlw-staging-dataset-ingest GetObject "$REC_OBJ_K4" -
note "P09 residual R2 recorded: ingest read across workspaces allowed and expected in the trail"
```

**P09-03 · READ-ONLY · workstation** — the prefix boundary, by simulation

Without `s3:ListBucket`, S3 answers `AccessDenied` for a missing key as well
as for a forbidden one, so a live read outside `versions/` proves nothing.
The simulator shows the boundary instead. KMS simulations carry the key's
`nlw-env` tag as context, as a real request would.

```bash
source "$PROOF_DIR/lib.sh"
sim() { aws iam simulate-principal-policy --profile nlw-proof-admin --policy-source-arn "$1" \
  --action-names "${@:3}" --resource-arns "$2" --query 'EvaluationResults[].EvalDecision' --output text; }
TAG="ContextKeyName=aws:ResourceTag/nlw-env,ContextKeyValues=staging,ContextKeyType=string"
expect_simulated implicitDeny "$(sim "$ROLE_PREFIX/nlw-staging-dataset-ingest" "arn:aws:s3:::$BUCKET/outside/x" s3:GetObject)"
expect_simulated allowed "$(sim "$ROLE_PREFIX/nlw-staging-dataset-ingest" "arn:aws:s3:::$BUCKET/versions/x" s3:GetObject)"
expect_simulated implicitDeny "$(aws iam simulate-principal-policy --profile nlw-proof-admin \
  --policy-source-arn "$ROLE_PREFIX/nlw-staging-dataset-ingest" --action-names kms:GenerateDataKey kms:Encrypt \
  --resource-arns "$REC_KEY_ARN" --context-entries "$TAG" --query 'EvaluationResults[].EvalDecision' --output text)"
expect_simulated allowed "$(aws iam simulate-principal-policy --profile nlw-proof-admin \
  --policy-source-arn "$ROLE_PREFIX/nlw-staging-dataset-ingest" --action-names kms:Decrypt \
  --resource-arns "$REC_KEY_ARN" --context-entries "$TAG" --query 'EvaluationResults[].EvalDecision' --output text)"
```

The key policy, not only IAM, decides KMS access. Its live counterpart is
P09-02: ingest decrypts what the API wrote.

**P09-04 · MUTATING · proof instance · EXPECT-DENIED**

```bash
source "$PROOF_DIR/lib.sh"
expect_denied aws s3api put-object --profile proof-ingest --bucket "$BUCKET" \
  --key "versions/$REC_PROOF_WS/$(uuidgen)/$(uuidgen)/source.csv" --body "$PROOF_DIR/obj1.bin" \
  --if-none-match '*' --server-side-encryption aws:kms --ssekms-key-id "$REC_KEY_ARN"
expect_event nlw-staging-dataset-ingest PutObject - AccessDenied
expect_denied aws s3api list-objects-v2 --profile proof-ingest --bucket "$BUCKET" --prefix versions/ --max-items 1
```

### P10. Cross-environment access is denied

Production resources do not exist, so the production side is shown by policy
simulation only. Each simulation has a positive control; if a control does
not come back `allowed`, the simulator is not evaluating what we think (S9).

**P10-01 · READ-ONLY · workstation** — staging roles against production names

```bash
source "$PROOF_DIR/lib.sh"
sim() { aws iam simulate-principal-policy --profile nlw-proof-admin --policy-source-arn "$1" \
  --action-names "${@:3}" --resource-arns "$2" --query 'EvaluationResults[].EvalDecision' --output text; }
PROD_KEY="arn:aws:kms:us-east-1:${ACCOUNT}:key/00000000-0000-0000-0000-000000000000"
for r in api ingest operator; do
  expect_simulated explicitDeny "$(sim "$ROLE_PREFIX/nlw-staging-dataset-$r" \
    "arn:aws:s3:::$OTHER_BUCKET/versions/x" s3:GetObject s3:PutObject s3:DeleteObjectVersion)"
  expect_simulated explicitDeny "$(aws iam simulate-principal-policy --profile nlw-proof-admin \
    --policy-source-arn "$ROLE_PREFIX/nlw-staging-dataset-$r" --action-names kms:Decrypt \
    --resource-arns "$PROD_KEY" \
    --context-entries "ContextKeyName=aws:ResourceTag/nlw-env,ContextKeyValues=production,ContextKeyType=string" \
    --query 'EvaluationResults[].EvalDecision' --output text)"
done
expect_simulated allowed "$(sim "$ROLE_PREFIX/nlw-staging-dataset-ingest" "arn:aws:s3:::$BUCKET/versions/x" s3:GetObject)"
expect_simulated explicitDeny "$(sim "$ROLE_PREFIX/nlw-staging-dataset-bootstrap" "arn:aws:s3:::$BUCKET/versions/x" s3:GetObject)"
```

**P10-02 · READ-ONLY · workstation** — production roles against the staging bucket

```bash
source "$PROOF_DIR/lib.sh"
jq -n '{Version: "2012-10-17", Statement: [{Effect: "Allow", Action: "s3:*", Resource: "*"}]}' \
  > "$PROOF_DIR/allow-all.json"
simres() { aws iam simulate-custom-policy --profile nlw-proof-admin \
  --policy-input-list "file://$PROOF_DIR/allow-all.json" \
  --resource-policy "file://$PROOF_DIR/bucket-policy.json" --resource-owner "arn:aws:iam::${ACCOUNT}:root" \
  --caller-arn "arn:aws:iam::${ACCOUNT}:user/nlw-d6-simulated-caller" \
  --action-names s3:GetObject --resource-arns "arn:aws:s3:::$BUCKET/versions/x" \
  --context-entries "ContextKeyName=aws:PrincipalArn,ContextKeyValues=$1,ContextKeyType=string" \
    "ContextKeyName=aws:PrincipalAccount,ContextKeyValues=$ACCOUNT,ContextKeyType=string" \
    "ContextKeyName=aws:SecureTransport,ContextKeyValues=true,ContextKeyType=boolean" \
  --query 'EvaluationResults[].EvalDecision' --output text; }
expect_simulated explicitDeny "$(simres "$ROLE_PREFIX/nlw-production-dataset-api")"
expect_simulated explicitDeny "$(simres "$ROLE_PREFIX/nlw-production-dataset-ingest")"
expect_simulated allowed "$(simres "$ROLE_PREFIX/nlw-staging-dataset-ingest")"
```

If the simulator refuses a caller ARN that does not exist, record the reverse
direction as **not provable until production exists** and carry it to the
production provisioning review. Do not create any production-named principal.

**P10-03 · READ-ONLY · proof instance · EXPECT-DENIED** — live, against the
real staging resources: the bootstrap role reaches no data

```bash
source "$PROOF_DIR/lib.sh"
expect_error 403 aws s3api head-object --profile proof-bootstrap --bucket "$BUCKET" --key "$REC_OBJ_K1"
expect_denied aws kms describe-key --profile proof-bootstrap --key-id "$REC_KEY_ARN"
expect_event nlw-staging-dataset-bootstrap HeadObject "$REC_OBJ_K1" AccessDenied
```

### P11. Runtime roles cannot delete objects or tamper with audit resources

Live attempts are made only where an unexpected success is harmless or
reversible: an identical policy or selector, a delete marker, or a
`StopLogging` that the audit administrator restarts at once (§F, R-LOG).
Irreversible actions are shown by simulation.

**P11-01 · MUTATING · proof instance · EXPECT-DENIED** — no runtime deletion

```bash
source "$PROOF_DIR/lib.sh"
for p in proof-api proof-ingest proof-bootstrap; do
  expect_denied aws s3api delete-object --profile "$p" --bucket "$BUCKET" --key "$REC_OBJ_K2"
  expect_denied aws s3api delete-object --profile "$p" --bucket "$BUCKET" --key "$REC_OBJ_K2" \
    --version-id "$REC_OBJ_K2_VERSION"
done
expect_event nlw-staging-dataset-api DeleteObject "$REC_OBJ_K2" AccessDenied
expect_event nlw-staging-dataset-ingest DeleteObject "$REC_OBJ_K2" AccessDenied
```

**P11-02 · MUTATING · proof instance · EXPECT-DENIED** — audit tamper by runtime roles

The policy and selector files are the deployed ones, copied from the
workstation; an unexpected success changes nothing.

```bash
source "$PROOF_DIR/lib.sh"
for p in proof-api proof-ingest proof-bootstrap; do
  expect_denied aws cloudtrail stop-logging --profile "$p" --name "$TRAIL_ARN"
  expect_denied aws cloudtrail put-event-selectors --profile "$p" --trail-name "$TRAIL_ARN" \
    --advanced-event-selectors "file://$PROOF_DIR/selectors.json"
  expect_denied aws s3api put-bucket-policy --profile "$p" --bucket "$AUDIT_BUCKET" \
    --policy "file://$PROOF_DIR/audit-bucket-policy.json"
  expect_denied aws s3api put-bucket-lifecycle-configuration --profile "$p" --bucket "$AUDIT_BUCKET" \
    --lifecycle-configuration "file://$PROOF_DIR/audit-lifecycle.json"
  expect_denied aws s3api list-objects-v2 --profile "$p" --bucket "$AUDIT_BUCKET" --max-items 1
  expect_denied aws kms describe-key --profile "$p" --key-id "$REC_AUDIT_KEY_ARN"
done
```

Copy `selectors.json`, `audit-bucket-policy.json` and `audit-lifecycle.json`
from the workstation's `$PROOF_DIR` with the same `scp` as P03-12 before this
block. If `stop-logging` is ever allowed: S4, and R-LOG at once.

**P11-03 · READ-ONLY · workstation** — irreversible tamper, by simulation

```bash
source "$PROOF_DIR/lib.sh"
sim() { aws iam simulate-principal-policy --profile nlw-proof-admin --policy-source-arn "$1" \
  --action-names "${@:3}" --resource-arns "$2" --query 'EvaluationResults[].EvalDecision' --output text; }
for r in bootstrap api ingest operator; do
  ROLE="$ROLE_PREFIX/nlw-staging-dataset-$r"
  expect_simulated explicitDeny "$(sim "$ROLE" "$TRAIL_ARN" cloudtrail:DeleteTrail cloudtrail:StopLogging cloudtrail:UpdateTrail)"
  expect_simulated explicitDeny "$(sim "$ROLE" "arn:aws:s3:::$AUDIT_BUCKET" s3:DeleteBucket s3:PutBucketPolicy s3:PutBucketObjectLockConfiguration)"
  expect_simulated explicitDeny "$(sim "$ROLE" "arn:aws:s3:::$AUDIT_BUCKET/dataset-data-events/x" s3:DeleteObjectVersion s3:BypassGovernanceRetention s3:PutObjectRetention)"
  expect_simulated explicitDeny "$(sim "$ROLE" "$REC_AUDIT_KEY_ARN" kms:ScheduleKeyDeletion kms:PutKeyPolicy kms:Decrypt)"
done
for r in api ingest; do
  expect_simulated implicitDeny "$(sim "$ROLE_PREFIX/nlw-staging-dataset-$r" "arn:aws:s3:::$BUCKET/versions/x" s3:DeleteObject s3:DeleteObjectVersion)"
done
```

### P12. Operator MFA assumption and version-aware deletion

**P12-01 · READ-ONLY · workstation · EXPECT-DENIED** — no MFA, no operator

```bash
source "$PROOF_DIR/lib.sh"
expect_denied aws sts get-caller-identity --profile nlw-proof-operator-nomfa
```

**P12-02 · READ-ONLY · proof instance · EXPECT-DENIED** — the instance role
cannot become the operator

```bash
source "$PROOF_DIR/lib.sh"
expect_denied aws sts assume-role --profile proof-bootstrap \
  --role-arn "$ROLE_PREFIX/nlw-staging-dataset-operator" --role-session-name nlw-staging-operator \
  --query AssumedRoleUser.Arn --output text
expect_denied aws sts assume-role --profile proof-api \
  --role-arn "$ROLE_PREFIX/nlw-staging-dataset-operator" --role-session-name nlw-staging-operator \
  --query AssumedRoleUser.Arn --output text
```

**P12-03 · MUTATING · workstation** — MFA operator purges P04–P09 objects by version

```bash
source "$PROOF_DIR/lib.sh"
aws sts get-caller-identity --profile nlw-proof-operator --query Arn --output text \
  | grep -q ':assumed-role/nlw-staging-dataset-operator/nlw-staging-operator$' || stop S9 "operator identity"
expect_denied aws s3api delete-object --profile nlw-proof-operator --bucket "$BUCKET" --key "$REC_OBJ_K1"
expect_denied aws s3api put-object --profile nlw-proof-operator --bucket "$BUCKET" --key "$REC_OBJ_K1" \
  --body /dev/null --if-none-match '*' --server-side-encryption aws:kms --ssekms-key-id "$REC_KEY_ARN"
for n in K1 K2 K3 K4; do
  key_var="REC_OBJ_$n"; ver_var="REC_OBJ_${n}_VERSION"
  aws s3api delete-object --profile nlw-proof-operator --bucket "$BUCKET" \
    --key "${!key_var}" --version-id "${!ver_var}" --query VersionId --output text
  expect_event nlw-staging-dataset-operator DeleteObject "${!key_var}" -
done
for ws in "$REC_PROOF_WS" "$REC_PROOF_WS2"; do
  aws s3api list-object-versions --profile nlw-proof-operator --bucket "$BUCKET" --prefix "versions/$ws/" \
    --query 'sum([length(Versions || `[]`), length(DeleteMarkers || `[]`)])' --output text | grep -qx 0 \
    || stop S9 "versions or delete markers remain under versions/$ws/"
done
note "P12 operator: MFA required, plain delete refused, version-aware purge complete, nothing remains"
```

`REC_OBJ_*_VERSION` values were recorded on the proof instance; copy the
instance's `created.env` back (`scp ... ec2-user@$HOST:proof/created.env`)
and append its new lines to the workstation ledger before this block.

### P13. CloudTrail records allowed and denied operations (stop S6)

Data events reach the audit bucket within about 15 minutes. Wait at least 20
minutes after P12, then read the logs as the audit reader.

**P13-01 · READ-ONLY · workstation**

```bash
source "$PROOF_DIR/lib.sh"
DAY="$(date -u +%Y/%m/%d)"
PREFIX="dataset-data-events/AWSLogs/$ACCOUNT/CloudTrail/us-east-1/$DAY/"
mkdir -p "$PROOF_DIR/trail"
aws s3api list-objects-v2 --profile nlw-proof-audit-reader --bucket "$AUDIT_BUCKET" --prefix "$PREFIX" \
  --query 'Contents[].Key' --output text | tr '\t' '\n' > "$PROOF_DIR/trail/keys.txt"
while read -r k; do
  [[ -n "$k" ]] && aws s3api get-object --profile nlw-proof-audit-reader --bucket "$AUDIT_BUCKET" \
    --key "$k" "$PROOF_DIR/trail/$(basename "$k")" --query ContentLength --output text >/dev/null
done < "$PROOF_DIR/trail/keys.txt"
for f in "$PROOF_DIR"/trail/*.json.gz; do gunzip -c "$f"; done \
  | jq -c --arg b "$BUCKET" '.Records[] | {
      eventTime, eventName, errorCode: (.errorCode // "-"), eventID, requestID,
      role: .userIdentity.sessionContext.sessionIssuer.userName,
      session: (.userIdentity.arn | split("/") | last),
      key: ([.resources[]? | select(.type == "AWS::S3::Object") | .ARN][0] // "-"
            | ltrimstr("arn:aws:s3:::" + $b + "/")),
      in_scope: ([.resources[]? | select(.type == "AWS::S3::Object") | .ARN
                  | startswith("arn:aws:s3:::" + $b + "/")] | all)}' \
  > "$PROOF_DIR/evidence/p13-events.jsonl"
python3 - "$PROOF_DIR/expected-events.tsv" "$PROOF_DIR/evidence/p13-events.jsonl" <<'PY' \
  || stop S6 "an expected data event is missing, or an event is out of scope"
import json, sys
events = [json.loads(line) for line in open(sys.argv[2])]
missing = []
for line in open(sys.argv[1]):
    role, name, key, err = line.rstrip("\n").split("\t")
    if not any(e["role"] == role and e["eventName"] == name
               and (key == "-" or e["key"] == key)
               and (err == "-" and e["errorCode"] == "-" or err != "-" and e["errorCode"].startswith(err))
               for e in events):
        missing.append((role, name, err))
out_of_scope = [e["eventID"] for e in events if not e["in_scope"]]
print(f"events={len(events)} expected={sum(1 for _ in open(sys.argv[1]))} missing={len(missing)} out_of_scope={len(out_of_scope)}")
for m in missing:
    print("MISSING", *m)
sys.exit(1 if missing or out_of_scope else 0)
PY
jq -c 'select(.eventName == "ListObjectVersions" or .eventName == "ListObjects")' \
  "$PROOF_DIR/evidence/p13-events.jsonl" | wc -l | xargs printf 'bucket-level list events observed: %s\n' \
  > "$PROOF_DIR/evidence/p13-list-events.txt"
aws cloudtrail validate-logs --profile nlw-proof-audit-reader --trail-arn "$TRAIL_ARN" \
  --start-time "$(date -u -r "$PROOF_DIR/started" +%FT%TZ)" > "$PROOF_DIR/evidence/p13-validate-logs.txt" \
  || stop S6 "log file validation failed"
```

`p13-list-events.txt` records whether the operator's P12 listing reached this
trail. It is an observation, not a pass condition: if it is zero, decision
E13 applies.

Merge the proof instance's `expected-events.tsv` into the workstation copy
before this block. If the session crossed midnight UTC, list each day. The projection keeps no access key id, no account id and
no source IP; `userIdentity.accessKeyId` is never extracted.

### P14. Credential files rotate, expire and never fall back to IMDS

The refresher is not built (O-6). `write_credentials` in `lib.sh` is its
stand-in: the same file format, atomic rename, `0400`, owned by the container
user, never printed. It shows that the **application** handles rotation and
expiry. It **cannot** show anything about the future refresher itself:

- systemd scheduling, its 15-minute timer and start-up ordering;
- retry and backoff after a failed `AssumeRole`;
- root ownership of the refresher and the exact mode and owner it applies;
- that the credential directories are on tmpfs;
- behaviour across a host reboot;
- the refresh-failure alert.

Those are O-6 proof items. API and ingest containers also both run as uid
10001 today, so credential isolation between them rests on the separate
mounts alone; O-6 must give them separate runtime users.

**P14-01 · MUTATING · proof instance** — a fresh object for the probe

```bash
source "$PROOF_DIR/lib.sh"
K5="versions/$REC_PROOF_WS/$(uuidgen)/$(uuidgen)/source.csv"
record REC_OBJ_K5 "$K5"
record REC_OBJ_K5_VERSION "$(aws s3api put-object --profile proof-api --bucket "$BUCKET" --key "$K5" \
  --body "$PROOF_DIR/obj1.bin" --if-none-match '*' \
  --server-side-encryption aws:kms --ssekms-key-id "$REC_KEY_ARN" --bucket-key-enabled \
  --query VersionId --output text)"
```

**P14-02 · READ-ONLY · proof instance** — rotation keeps a running process working

```bash
source "$PROOF_DIR/lib.sh"
write_credentials api proof-api
( for _ in $(seq 1 7); do sleep 300; write_credentials api proof-api; done ) > "$PROOF_DIR/rotate.log" 2>&1 &
ROTATOR=$!
# However this step ends, the rotator is stopped and reaped before the
# process exits, so it can never rewrite the file under P14-03.
on_exit "kill $ROTATOR 2> /dev/null; wait $ROTATOR 2> /dev/null"
probe api /run/nlw/aws/api --network bridge -e AWS_EC2_METADATA_DISABLED=true -- --loop "$REC_OBJ_K5" 35 \
  | tee "$PROOF_DIR/evidence/p14-rotation.txt"
wait "$ROTATOR"
[[ "$(grep -c '^HEAD OK' "$PROOF_DIR/evidence/p14-rotation.txt")" -ge 35 ]] \
  || stop S9 "a rotating credential file did not keep the process working for 35 minutes"
```

Sessions last 15 minutes, so 35 minutes of successful calls span at least two
rotations. The expiry printed each minute must advance.

**P14-03 · READ-ONLY · proof instance** — expiry without rotation fails closed

```bash
source "$PROOF_DIR/lib.sh"
write_credentials api proof-api
if probe api /run/nlw/aws/api --network bridge -e AWS_EC2_METADATA_DISABLED=true -- --loop "$REC_OBJ_K5" 20 \
  > "$PROOF_DIR/evidence/p14-expiry.txt"; then stop S4 "credentials did not expire"; fi
grep -q '^REFUSED: .*expired or about to expire' "$PROOF_DIR/evidence/p14-expiry.txt" \
  || stop S9 "expiry refusal message differs"
```

**P14-04 · READ-ONLY · proof instance** — a missing file is refused even when IMDS is reachable

The container runs on the host network, where IMDS **is** reachable with hop
limit 1, and without `AWS_EC2_METADATA_DISABLED`. The credential file is
absent, so startup refuses before the SDK is consulted. This shows only that
a missing file is refused; it does **not** show what happens when a running
process's credentials expire with IMDS reachable. P14-05 tests that.

```bash
source "$PROOF_DIR/lib.sh"
sudo install -d -m 0700 -o "$CONTAINER_UID" -g "$CONTAINER_GID" /run/nlw/aws/empty
out="$(probe api /run/nlw/aws/empty --network host | grep -E '^(ACCEPTED|REFUSED)' || true)"
[[ "$out" == "REFUSED: the AWS credential file is missing or unreadable" ]] \
  || stop S4 "credential chain fell back or behaved unexpectedly: $out"
note "P14-04 a missing credential file is refused with IMDS reachable"
```

**P14-05 · READ-ONLY · proof instance** — mid-run expiry with IMDS reachable

P14-03 again, on the host network without `AWS_EC2_METADATA_DISABLED`. A
fallback to the instance role would keep `HEAD OK` lines coming, as the
bootstrap identity, or fail with a different error; only the expiry refusal
passes. Until this runs, the "no IMDS fallback" guarantee for mid-run expiry
rests on the unit test of the pinned provider chain alone.

```bash
source "$PROOF_DIR/lib.sh"
write_credentials api proof-api
if probe api /run/nlw/aws/api --network host -- --loop "$REC_OBJ_K5" 20 \
  > "$PROOF_DIR/evidence/p14-expiry-imds-reachable.txt"; then stop S4 "credentials did not expire"; fi
grep -q '^REFUSED: .*expired or about to expire' "$PROOF_DIR/evidence/p14-expiry-imds-reachable.txt" \
  || stop S4 "expiry with IMDS reachable did not fail closed"
note "P14-05 mid-run expiry fails closed with IMDS reachable"
```

### P15. Containers reject missing, expired, exposed, static or wrong-role credentials

**P15-01 · READ-ONLY · proof instance**

```bash
source "$PROOF_DIR/lib.sh"
write_credentials api proof-api
write_credentials ingest proof-ingest
ok="$(probe api /run/nlw/aws/api --network bridge -e AWS_EC2_METADATA_DISABLED=true | grep -E '^(ACCEPTED|REFUSED)')"
[[ "$ok" == "ACCEPTED: arn:aws:iam::$ACCOUNT:role/nlw-staging-dataset-api" ]] || stop S9 "api not accepted"
refused() { # refused EXPECTED_SUBSTRING probe-args... (structured log lines are ignored)
  local want="$1"; shift; local got; got="$(probe "$@" | grep -E '^(ACCEPTED|REFUSED)' || true)"
  [[ "$got" == "REFUSED: "*"$want"* ]] || stop S4 "expected refusal '$want', got '$got'"
  note "refused: $want"
}
refused "not the expected role nlw-staging-dataset-api" api /run/nlw/aws/ingest --network bridge
refused "missing or unreadable" api /run/nlw/aws/empty --network bridge
sudo install -d -m 0700 -o "$CONTAINER_UID" -g "$CONTAINER_GID" /run/nlw/aws/expired /run/nlw/aws/exposed
printf '[default]\naws_access_key_id = proof-dummy-id\naws_secret_access_key = proof-dummy\naws_session_token = proof-dummy\nx_nlw_expiration = 2000-01-01T00:00:00Z\n' \
  | sudo install -m 0400 -o "$CONTAINER_UID" -g "$CONTAINER_GID" /dev/stdin /run/nlw/aws/expired/credentials
refused "expired or about to expire" api /run/nlw/aws/expired --network bridge
sudo install -m 0444 -o "$CONTAINER_UID" -g "$CONTAINER_GID" /run/nlw/aws/expired/credentials /run/nlw/aws/exposed/credentials
refused "private regular file" api /run/nlw/aws/exposed --network bridge
refused "static AWS credentials" api /run/nlw/aws/api --network bridge -e AWS_ACCESS_KEY_ID=proof-dummy-id
```

### P16. Sanitized evidence

**P16-01 · LOCAL · workstation** (repeat on the proof instance for its files,
then copy them back)

```bash
source "$PROOF_DIR/lib.sh"
for f in "$PROOF_DIR"/evidence/* "$PROOF_DIR/journal.log"; do
  sed -i.bak -e "s/$ACCOUNT/<ACCOUNT>/g" -e "s#${REC_KEY_ARN##*/}#<KEY_ID>#g" \
    -e "s#${REC_AUDIT_KEY_ARN##*/}#<AUDIT_KEY_ID>#g" -e "s/${REC_INSTANCE_ID:-i-none}/<INSTANCE_ID>/g" "$f"
  rm -f "$f.bak"
done
if grep -RIlE '[0-9]{12}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{12,}|aws_secret_access_key|aws_session_token|SecretAccessKey|SessionToken|x-amz-security-token' \
  "$PROOF_DIR/evidence" "$PROOF_DIR/journal.log"; then
  stop S7 "a sensitive value is in the evidence; do not share it"
fi
shopt -s nullglob
if grep -lE 'aws_access_key_id|aws_secret_access_key|aws_session_token|SecretAccessKey|SessionToken|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}' \
  "$PROOF_DIR/aws-config" "$PROOF_DIR"/*.json "$PROOF_DIR"/*.tsv "$PROOF_DIR"/*.out "$PROOF_DIR"/*.err; then
  stop S7 "a credential-like value is in a proof data file"
fi
note "P16 evidence scan clean"
```

The evidence holds step ids, decisions, event names, error codes, event and
request ids, object keys made of random UUIDs, and the sanitized journal. It
never holds object contents, credentials, account ids, key ids or IP
addresses. It is committed under `docs/evidence/o2-d6/` only in a later,
separately reviewed pull request.

### P17. Teardown or preserve (decision E3)

Run the [§F cleanup](#f-cleanup) steps that decision E3 selects. Proof objects,
the proof instance and its security group are always removed. Audit records
are always retained under Object Lock.

### P18. Final inventory and cost-bearing resources

**P18-01 · READ-ONLY · workstation**

```bash
source "$PROOF_DIR/lib.sh"
aws resourcegroupstaggingapi get-resources --profile nlw-proof-admin \
  --tag-filters "Key=nlw-proof,Values=$PROOF_ID" --query 'ResourceTagMappingList[].ResourceARN' \
  --output text | tr '\t' '\n' | sed "s/$ACCOUNT/<ACCOUNT>/g" > "$PROOF_DIR/evidence/p18-tagged.txt"
for r in bootstrap api ingest operator audit-admin audit-reader; do
  aws iam get-role --profile nlw-proof-admin --role-name "nlw-staging-dataset-$r" \
    --query Role.RoleName --output text 2>/dev/null || echo "absent nlw-staging-dataset-$r"
done > "$PROOF_DIR/evidence/p18-roles.txt"
aws ec2 describe-instances --profile nlw-proof-admin --instance-ids "$REC_INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].State.Name' --output text | grep -qx terminated \
  || stop S9 "the proof instance is not terminated"
note "P18 final inventory written"
```

**Cost-bearing resources after the proof** (estimates to confirm against
current AWS pricing; nothing here was priced live):

| Resource | Billing | Kept when |
|---|---|---|
| dataset KMS key | per key-month, plus requests | E3 = retain |
| audit KMS key | per key-month, plus requests | always (it protects retained logs) |
| CloudTrail data events | per 100,000 events | while the trail logs |
| dataset and audit buckets | storage and requests | dataset: E3 = retain; audit: always |
| proof instance, volume, public IPv4 | per hour | never; terminated in P17 |

## D. Stop conditions

Every stop writes `STOP <id>` to the journal and exits. After a stop, nothing
further runs, including cleanup, until the owner has read the journal. Then
follow [§F Recovery](#f-recovery-from-a-partial-proof).

| Id | Stop immediately when | Checked in |
|---|---|---|
| **S1** | the AWS account or region differs from the approved target | `lib.sh`, P01, P03-14 |
| **S2** | an expected bucket, role, key, trail or instance already exists, or a just-created bucket is not new | P02, P03-06, P03-07 |
| **S3** | multipart uploads conflict with the encryption policy | P07 |
| **S4** | any runtime role, the bootstrap role or the operator gets broader permissions than designed: an EXPECT-DENIED call succeeds, a simulation is not a deny, or a credential is accepted that should be refused. A write that succeeded may have left an object: run R-OBJ | `expect_error`, `expect_simulated`, P03-11, P05, P11, P14, P15 |
| **S5** | IMDS is reachable from an application container on the bridge network, or the instance metadata options differ | P03-11, P03-13, P03-14 |
| **S6** | CloudTrail fails to record an expected data event, records an event outside the dataset bucket, is not logging, or log validation fails | P03-11, P13 |
| **S7** | a secret or credential would be printed or kept in evidence | P16, and the rules in "How to read the commands" |
| **S8** | cleanup would affect a resource that this proof did not create | `record`, X01–X02 |
| **S9** | a check returned an unexpected value, error code or state, or a precondition failed | everywhere |
| **S10** | a command failed: a create, a configuration change or a read (the `EXIT` handler in `lib.sh` for any failure without a stop, and `record` given no identifier) | `lib.sh` |

## F. Cleanup

Cleanup acts **only** on values in `$PROOF_DIR/created.env`. It never lists a
bucket to find what to delete, never uses a wildcard, `--recursive`, `--force`
or `s3 rm`, and verifies the proof tag before every delete.

**X01 · LOCAL · workstation** — the ledger names only proof resources

```bash
source "$PROOF_DIR/lib.sh"
while IFS='=' read -r name value; do
  [[ "$name" =~ ^REC_[A-Z0-9_]+$ ]] || stop S8 "malformed ledger line"
  [[ "$value" != *'*'* ]] || stop S8 "wildcard in ledger: $name"
  case "$name" in
    REC_ROLE_*) [[ "$value" =~ ^arn:aws:iam::${ACCOUNT}:role/nlw-staging-dataset-[a-z-]+$ ]] ;;
    REC_PROOF_ID) [[ "$value" == "$PROOF_ID" ]] ;;
    REC_ORPHAN_BUCKET) [[ "$value" == "$BUCKET" ]] ;;
    REC_ORPHAN_AUDIT_BUCKET) [[ "$value" == "$AUDIT_BUCKET" ]] ;;
    REC_HUMAN_*_KEY_ID) [[ "$value" =~ ^AKIA[0-9A-Z]{16}$ ]] ;;
    REC_BUCKET) [[ "$value" == "$BUCKET" && "$value" == *"$SUFFIX" ]] ;;
    REC_AUDIT_BUCKET) [[ "$value" == "$AUDIT_BUCKET" && "$value" == *"$SUFFIX" ]] ;;
    REC_TRAIL_ARN) [[ "$value" == "$TRAIL_ARN" ]] ;;
    REC_PROFILE_BOOTSTRAP) [[ "$value" == "arn:aws:iam::${ACCOUNT}:instance-profile/nlw-staging-dataset-bootstrap" ]] ;;
    REC_BUDGET_NAME) [[ "$value" == "nlw-staging-dataset-proof-$PROOF_ID" ]] ;;
    REC_OBJ_K[0-9]|REC_MPU_K[0-9]|REC_RECOVERED_[0-9]*_KEY|REC_RECOVERED_MPU_[0-9]*_KEY)
      [[ "$value" == "versions/$REC_PROOF_WS/"* || "$value" == "versions/$REC_PROOF_WS2/"* ]] ;;
    *) true ;;
  esac || stop S8 "$name does not name this proof run's staging resource"
done < "$PROOF_DIR/created.env"
note "X01 ledger checked"
```

**X02 · READ-ONLY · workstation** — every resource to delete carries this proof's tag

```bash
source "$PROOF_DIR/lib.sh"
tagged() { [[ "$1" == "$PROOF_ID" ]] || stop S8 "$2 is not tagged nlw-proof=$PROOF_ID"; }
tagged "$(aws ec2 describe-tags --profile nlw-proof-admin --filters "Name=resource-id,Values=${REC_INSTANCE_ID}" \
  Name=key,Values=nlw-proof --query 'Tags[0].Value' --output text)" instance
tagged "$(aws ec2 describe-tags --profile nlw-proof-admin --filters "Name=resource-id,Values=${REC_SG_ID}" \
  Name=key,Values=nlw-proof --query 'Tags[0].Value' --output text)" security-group
tagged "$(aws s3api get-bucket-tagging --profile nlw-proof-admin --bucket "${REC_BUCKET}" \
  --query "TagSet[?Key=='nlw-proof'].Value | [0]" --output text)" dataset-bucket
tagged "$(aws kms list-resource-tags --profile nlw-proof-admin --key-id "${REC_KEY_ARN}" \
  --query "Tags[?TagKey=='nlw-proof'].TagValue | [0]" --output text)" dataset-key
for v in REC_ROLE_BOOTSTRAP REC_ROLE_API REC_ROLE_INGEST REC_ROLE_OPERATOR; do
  tagged "$(aws iam list-role-tags --profile nlw-proof-admin --role-name "${!v##*/}" \
    --query "Tags[?Key=='nlw-proof'].Value | [0]" --output text)" "$v"
done
tagged "$(aws iam list-instance-profile-tags --profile nlw-proof-admin \
  --instance-profile-name "${REC_PROFILE_BOOTSTRAP##*/}" \
  --query "Tags[?Key=='nlw-proof'].Value | [0]" --output text)" instance-profile
tagged "$(aws cloudtrail list-tags --profile nlw-proof-audit-admin --resource-id-list "${REC_TRAIL_ARN}" \
  --query "ResourceTagList[0].TagsList[?Key=='nlw-proof'].Value | [0]" --output text)" trail
[[ "$(aws iam get-instance-profile --profile nlw-proof-admin \
  --instance-profile-name "${REC_PROFILE_BOOTSTRAP##*/}" --query 'InstanceProfile.Arn' --output text)" \
  == "${REC_PROFILE_BOOTSTRAP}" ]] || stop S8 "the instance profile is not the recorded one"
[[ "$(aws cloudtrail get-trail --profile nlw-proof-audit-admin --name "${REC_TRAIL_ARN}" \
  --query 'Trail.TrailARN' --output text)" == "${REC_TRAIL_ARN}" ]] || stop S8 "the trail is not the recorded one"
```

**X03 · MUTATING · workstation** — always: the proof instance and its security group

```bash
source "$PROOF_DIR/lib.sh"
aws ec2 terminate-instances --profile nlw-proof-admin --instance-ids "${REC_INSTANCE_ID}" \
  --query 'TerminatingInstances[0].CurrentState.Name' --output text
aws ec2 wait instance-terminated --profile nlw-proof-admin --instance-ids "${REC_INSTANCE_ID}"
aws ec2 delete-security-group --profile nlw-proof-admin --group-id "${REC_SG_ID}"
note "X03 proof instance and security group removed"
```

**X04 · MUTATING · workstation** — always: every recorded object version and
any abandoned recorded upload (idempotent; a missing version is not an error)

```bash
source "$PROOF_DIR/lib.sh"
for n in K1 K2 K3 K4 K5; do
  key_var="REC_OBJ_$n"; ver_var="REC_OBJ_${n}_VERSION"
  [[ -n "${!key_var:-}" && -n "${!ver_var:-}" ]] || continue
  aws s3api delete-object --profile nlw-proof-operator --bucket "${REC_BUCKET}" \
    --key "${!key_var}" --version-id "${!ver_var}" --query VersionId --output text
done
for v in $(compgen -v | grep -E '^REC_RECOVERED_[0-9]+_KEY$' || true); do
  ver="${v%_KEY}_VERSION"
  aws s3api delete-object --profile nlw-proof-operator --bucket "${REC_BUCKET}" \
    --key "${!v}" --version-id "${!ver}" --query VersionId --output text
done
for v in $(compgen -v | grep -E '^REC_RECOVERED_MPU_[0-9]+_KEY$' || true); do
  up="${v%_KEY}_UPLOAD"
  aws s3api abort-multipart-upload --profile nlw-proof-operator --bucket "${REC_BUCKET}" \
    --key "${!v}" --upload-id "${!up}" 2> /dev/null || note "upload ${!up} already closed"
done
for u in REC_MPU_K3_UPLOAD REC_MPU_K3_UPLOAD2; do
  [[ -n "${!u:-}" ]] || continue
  aws s3api abort-multipart-upload --profile nlw-proof-operator --bucket "${REC_BUCKET}" \
    --key "${REC_MPU_K3}" --upload-id "${!u}" 2>/dev/null || note "upload $u already closed"
done
```

**X05 · READ-ONLY · workstation** — the bucket holds nothing the proof did not create

```bash
source "$PROOF_DIR/lib.sh"
aws s3api list-object-versions --profile nlw-proof-operator --bucket "${REC_BUCKET}" --prefix versions/ \
  --query 'sum([length(Versions || `[]`), length(DeleteMarkers || `[]`)])' --output text | grep -qx 0 \
  || stop S8 "the dataset bucket holds versions this proof did not record; nothing more is deleted"
aws s3api list-multipart-uploads --profile nlw-proof-operator --bucket "${REC_BUCKET}" --prefix versions/ \
  --query 'length(Uploads[] || `[]`)' --output text | grep -qx 0 || stop S8 "unrecorded multipart upload"
```

**X06 · MUTATING · workstation** — only when E3 = delete: dataset bucket, runtime roles, dataset key

```bash
source "$PROOF_DIR/lib.sh"
[[ "${E3_DECISION:?}" == delete ]] || { note "E3 = retain: X06 skipped"; exit 0; }
aws s3api delete-bucket --profile nlw-proof-admin --bucket "${REC_BUCKET}"
aws iam remove-role-from-instance-profile --profile nlw-proof-admin \
  --instance-profile-name "${REC_PROFILE_BOOTSTRAP##*/}" --role-name "${REC_ROLE_BOOTSTRAP##*/}"
aws iam delete-instance-profile --profile nlw-proof-admin --instance-profile-name "${REC_PROFILE_BOOTSTRAP##*/}"
for v in REC_ROLE_BOOTSTRAP REC_ROLE_API REC_ROLE_INGEST REC_ROLE_OPERATOR; do
  aws iam delete-role-policy --profile nlw-proof-admin --role-name "${!v##*/}" \
    --policy-name "nlw-dataset-${!v##*/nlw-staging-dataset-}"
  aws iam delete-role --profile nlw-proof-admin --role-name "${!v##*/}"
done
aws kms disable-key --profile nlw-proof-admin --key-id "${REC_KEY_ARN}"
aws kms schedule-key-deletion --profile nlw-proof-admin --key-id "${REC_KEY_ARN}" --pending-window-in-days 30
note "X06 dataset bucket, runtime roles and dataset key removed (key deletion pending 30 days)"
```

`delete-bucket` without `--force` fails on a non-empty bucket, which is the
intended last guard. The key is deleted only after the bucket is gone; its
30-day pending window allows `cancel-key-deletion` if anything was missed.

**X07 · MUTATING · workstation** — only when E3 = delete: stop the data-event trail

```bash
source "$PROOF_DIR/lib.sh"
[[ "${E3_DECISION:?}" == delete ]] || { note "E3 = retain: trail keeps logging"; exit 0; }
aws cloudtrail stop-logging --profile nlw-proof-audit-admin --name "${REC_TRAIL_ARN}"
aws cloudtrail delete-trail --profile nlw-proof-audit-admin --name "${REC_TRAIL_ARN}"
```

**Never deleted by this procedure:** the audit bucket, the audit key and the
two audit roles. The audit bucket cannot be emptied before Object Lock
retention ends, and the audit key must outlive every log it encrypts. Their
removal after retention is a separate, reviewed change.

**X09 · MUTATING · workstation** — always, after X01–X07 (or after a stop):
delete the two proof access keys

```bash
source "$PROOF_DIR/lib.sh"
if [[ -n "${REC_HUMAN_OPERATOR_KEY_ID:-}" ]]; then
  aws iam delete-access-key --profile nlw-proof-human-operator \
    --user-name "${REC_HUMAN_OPERATOR_USER}" --access-key-id "${REC_HUMAN_OPERATOR_KEY_ID}"
fi
if [[ -n "${REC_HUMAN_AUDIT_KEY_ID:-}" ]]; then
  aws iam delete-access-key --profile nlw-proof-human-audit \
    --user-name "${REC_HUMAN_AUDIT_USER}" --access-key-id "${REC_HUMAN_AUDIT_KEY_ID}"
fi
note "X09 proof access keys deleted"
```

Each person deletes their own key with that key, so the IAM user needs
`iam:DeleteAccessKey` on itself. If a key cannot be deleted this way, its
owner deletes it in the console at once; X08 still runs.

**X08 · LOCAL · workstation** — always, last: Keychain items, cached sessions,
local keys and a final scan

```bash
source "$PROOF_DIR/lib.sh"
for who in operator audit; do
  bash "$PROOF_DIR/credential-process.sh" "$PROOF_ID" "$who" remove || stop S7 "Keychain items for $who remain"
done
python3 - "$HOME/.aws/cli/cache" "$ACCOUNT" <<'PY'
import json, os, re, sys
cache, account = sys.argv[1], sys.argv[2]
ours = re.compile(r"^arn:aws:sts::%s:assumed-role/[^/]+/nlw-staging-"
                  r"(api|ingest|operator|audit-admin|audit-reader|proof-admin)$" % account)
removed = 0
for name in (os.listdir(cache) if os.path.isdir(cache) else []):
    path = os.path.join(cache, name)
    try:
        arn = json.load(open(path)).get("AssumedRoleUser", {}).get("Arn", "")
    except (OSError, ValueError, AttributeError):
        continue
    if ours.match(arn):
        os.remove(path)
        removed += 1
print(f"removed {removed} cached sessions of this proof's roles; others untouched")
PY
rm -f "$PROOF_DIR/proof-key" "$PROOF_DIR/proof-key.pub" "$PROOF_DIR"/*.bin
rm -rf "$PROOF_DIR/trail" "$PROOF_DIR/instance-bundle"
shopt -s nullglob
if grep -lE 'aws_access_key_id|aws_secret_access_key|aws_session_token|SecretAccessKey|SessionToken|ASIA[0-9A-Z]{16}' \
  "$PROOF_DIR/aws-config" "$PROOF_DIR/journal.log" "$PROOF_DIR"/evidence/* "$PROOF_DIR"/*.json \
  "$PROOF_DIR"/*.tsv "$PROOF_DIR"/*.out "$PROOF_DIR"/*.err; then
  stop S7 "a credential-like value remains in $PROOF_DIR"
fi
note "X08 Keychain items, this proof's cached sessions and local keys removed; scan clean"
```

X08 deletes only CLI cache files whose assumed-role session is one of this
proof's session names in the approved account; other sessions are left
alone. The raw CloudTrail downloads are removed because they carry session
key ids; the audit bucket keeps the originals.

### F. Recovery from a partial proof

The ledger is append-only and is written immediately after each create, so
it is the authority on what exists. A resource is never deleted because of
its name alone.

1. **Freeze.** Do not run another step. Read the last `STOP` line in
   `journal.log`.
2. **Reconcile (READ-ONLY).** Run P18-01 and compare `p18-tagged.txt` and
   `p18-roles.txt` with `created.env`.
   - In the ledger and in AWS: normal.
   - In the ledger, not in AWS: the create rolled back; remove nothing.
   - In AWS with this proof's tag, not in the ledger (a create succeeded but
     `record` did not run): the owner confirms the tag, name and creation
     time, then runs `record` for it by hand. Only then may cleanup touch it.
   - In AWS **without** this proof's tag: not ours. Never touch it (S8).
3. **Resume or abandon.** Every create is preceded by P02's absence check for
   its name, so a step may be resumed only after re-running P02 for the
   resources that step creates. Otherwise run X01–X07 in order, with X10–X12
   where they apply.
4. **Always, whatever else happens:** run X09 and then X08, so the proof's
   access keys, Keychain items and cached sessions do not outlive the run.

**R-OBJ: an EXPECT-DENIED write unexpectedly succeeded.** The stop (S4)
happened after the write, so an object version exists that the ledger does
not name, and X05 will refuse to finish. Every write the proof attempts uses
a key under one of its two random workspace prefixes, except P05-01's single
`outside/$REC_PROOF_WS/x` attempt. Recovery looks only there.

**X10 · READ-ONLY · workstation** — find and record unledgered versions under
the proof's own prefixes (MFA operator)

```bash
source "$PROOF_DIR/lib.sh"
[[ "$REC_PROOF_WS" =~ ^[0-9a-f-]{36}$ && "$REC_PROOF_WS2" =~ ^[0-9a-f-]{36}$ ]] \
  || stop S8 "the proof prefixes are not recorded UUIDs"
started="$(date -u -r "$PROOF_DIR/started" +%FT%TZ)"
n="$(compgen -v | grep -cE '^REC_RECOVERED_[0-9]+_KEY$' || true)"
for ws in "$REC_PROOF_WS" "$REC_PROOF_WS2"; do
  aws s3api list-object-versions --profile nlw-proof-operator --bucket "${REC_BUCKET}" \
    --prefix "versions/$ws/" \
    --query '[Versions[].[Key,VersionId,LastModified], DeleteMarkers[].[Key,VersionId,LastModified]][][]' \
    --output text > "$PROOF_DIR/recover-$ws.tsv"
  while IFS=$'\t' read -r key version modified; do
    [[ -n "$key" && "$key" != None ]] || continue
    [[ "$key" == "versions/$ws/"* ]] || stop S8 "listing returned a key outside the proof prefix"
    [[ "$modified" > "$started" ]] || stop S8 "a version predates this proof run: $key"
    grep -qF "$version" "$PROOF_DIR/created.env" && continue
    n=$((n + 1))
    record "REC_RECOVERED_${n}_KEY" "$key"
    record "REC_RECOVERED_${n}_VERSION" "$version"
  done < "$PROOF_DIR/recover-$ws.tsv"
done
m="$(compgen -v | grep -cE '^REC_RECOVERED_MPU_[0-9]+_KEY$' || true)"
for ws in "$REC_PROOF_WS" "$REC_PROOF_WS2"; do
  aws s3api list-multipart-uploads --profile nlw-proof-operator --bucket "${REC_BUCKET}" \
    --prefix "versions/$ws/" --query 'Uploads[].[Key,UploadId,Initiated]' \
    --output text > "$PROOF_DIR/recover-mpu-$ws.tsv"
  while IFS=$'\t' read -r key upload initiated; do
    [[ -n "$key" && "$key" != None ]] || continue
    [[ "$key" == "versions/$ws/"* ]] || stop S8 "listing returned an upload outside the proof prefix"
    [[ "$initiated" > "$started" ]] || stop S8 "an upload predates this proof run: $key"
    grep -qF "$upload" "$PROOF_DIR/created.env" && continue
    m=$((m + 1))
    record "REC_RECOVERED_MPU_${m}_KEY" "$key"
    record "REC_RECOVERED_MPU_${m}_UPLOAD" "$upload"
  done < "$PROOF_DIR/recover-mpu-$ws.tsv"
done
note "X10 recovered $n unledgered versions and $m open uploads under the proof prefixes"
```

**X11 · READ-ONLY · workstation** — the one write outside `versions/`
(administrator, exact key only)

```bash
source "$PROOF_DIR/lib.sh"
OUTSIDE="outside/$REC_PROOF_WS/x"
if aws s3api head-object --profile nlw-proof-admin --bucket "${REC_BUCKET}" --key "$OUTSIDE" \
    > "$PROOF_DIR/outside.json" 2> "$PROOF_DIR/last.err"; then
  record REC_OUTSIDE_KEY "$OUTSIDE"
  record REC_OUTSIDE_VERSION "$(jq -r .VersionId "$PROOF_DIR/outside.json")"
  stop S8 "an object exists outside versions/; no role may delete it under the bucket policy"
fi
grep -qE '\((404|NoSuchKey)\)' "$PROOF_DIR/last.err" || stop S9 "outside-prefix check failed"
note "X11 nothing outside versions/"
```

If X11 stops, deleting `REC_OUTSIDE_KEY` needs a separately reviewed,
temporary bucket-policy change, because `DenyDeleteExceptOperator` refuses
every principal but the operator and the operator's IAM scope is
`versions/*`. X06 cannot run until that is done; the bucket is kept.

After X10, run X01–X05 again: X04 purges the recovered versions and aborts
the recovered uploads by their recorded ids, and X05 must then find nothing.
An upload that an unexpected `CreateMultipartUpload` opened is found by X10
even though `expect_error` discarded its id; the lifecycle rule would also
abort it after one day.

**R-BUCKET: a bucket was created but never recorded.** If a pristine check in
P03-06 or P03-07 fails after `create-bucket` succeeded (for example a
transient error), the bucket exists, untagged and unrecorded. It is this
run's only if its name carries this run's random suffix **and** the journal
shows that this run confirmed the name absent just before creating it. X12
proves both, checks that the bucket is still empty and unconfigured, records
it and deletes it. Anything else is not ours (S8).

**X12 · MUTATING · workstation** — an unrecorded bucket created by this run

```bash
source "$PROOF_DIR/lib.sh"
orphan() { # orphan NAME PROFILE LEDGER_NAME
  local name="$1" profile="$2" ledger="$3"
  [[ -z "${!ledger:-}" ]] || return 0
  [[ "$name" == *"$SUFFIX" ]] || stop S8 "$name does not carry this run's suffix"
  grep -qF "absence confirmed: $name" "$PROOF_DIR/journal.log" || { note "no creation attempt for $name"; return 0; }
  if ! aws s3api head-bucket --profile "$profile" --bucket "$name" > /dev/null 2>&1; then
    note "$name does not exist"; return 0
  fi
  ON_ALLOWED=S8 expect_error NoSuchTagSet aws s3api get-bucket-tagging --profile "$profile" --bucket "$name"
  ON_ALLOWED=S8 expect_error NoSuchBucketPolicy aws s3api get-bucket-policy --profile "$profile" --bucket "$name"
  [[ "$(aws s3api list-object-versions --profile "$profile" --bucket "$name" --max-items 1 \
    --query 'sum([length(Versions || `[]`), length(DeleteMarkers || `[]`)])' --output text)" == 0 ]] \
    || stop S8 "$name holds objects; it is not an untouched orphan"
  record "REC_ORPHAN_${ledger#REC_}" "$name"
}
orphan "$BUCKET" nlw-proof-admin REC_BUCKET
orphan "$AUDIT_BUCKET" nlw-proof-audit-admin REC_AUDIT_BUCKET
if [[ -n "${REC_ORPHAN_BUCKET:-}" ]]; then
  aws s3api delete-bucket --profile nlw-proof-admin --bucket "${REC_ORPHAN_BUCKET}"
fi
if [[ -n "${REC_ORPHAN_AUDIT_BUCKET:-}" ]]; then
  aws s3api delete-bucket --profile nlw-proof-audit-admin --bucket "${REC_ORPHAN_AUDIT_BUCKET}"
fi
note "X12 orphan buckets handled"
```

**Special cases:**

| Case | Immediate action (MUTATING, by the named role) |
|---|---|
| **R-LOG:** a runtime role stopped the trail | audit administrator: `aws cloudtrail start-logging --name "$TRAIL_ARN"`; record the gap in the journal; the proof has failed (S4) |
| **R-PERM:** a role was allowed something it must not do | administrator: `aws iam delete-role-policy` for that role, so it fails closed; the template is fixed by review before any retry |
| **R-CRED:** a credential was printed or written to evidence | administrator: attach an inline deny on `aws:TokenIssueTime` earlier than now to the affected role, delete the evidence file, and record the exposure |
| **R-OBJ:** an EXPECT-DENIED write succeeded | X10 and X11 above, then X01–X05 |
| **R-MPU:** an upload was left open | X04 aborts the recorded upload ids; the lifecycle rule removes any other after one day |
| **R-INSTANCE:** the instance cannot be reached | X03 terminates it by recorded id; nothing on it is needed after P16 |
