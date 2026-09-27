# M12C demo-tool visibility: rollout authority correction

Branch: `fix/staging-demo-tool-enablement`. This correction follows `1b14405`
without amending it. The parent correction's service-scope and authority claims
are superseded by the evidence below. No VPS connection was made.

## Root cause and final scope

The parent wrote a reviewed value into staged `.env.prod`, but Compose gives an
exported shell variable precedence over `--env-file`. Later phases did not bind
that choice to staged pins or verify rendered/running values. A fresh-process
Settings test also mistook parsing a field for consuming its policy.

Only API consumes visibility: `api/capability.py::demo_tools_included` reads
`Settings.demo_tools_visible` for planning/materialization/tool listing, and
`api/routers/analytics.py::datasets` uses it for the pilot catalog. No worker or
scheduler code reads this policy. `tools/builtin.py` registers tools regardless
of visibility; `worker/actors.py` invokes `engine/execution.py`, which resolves
registered tools independently of this flag. Scheduler imports the actor for
enqueueing only. Their execution/compatibility behavior is unchanged.

Production Compose now forwards `DEMO_TOOLS_ENABLED` only to API, with
`${DEMO_TOOLS_ENABLED:-false}`. Worker, scheduler, web, Postgres, Redis, Caddy,
migrate, backup, restore, Prometheus and Alertmanager do not receive it.

## Authority chain

1. **Reviewed target:** `NLW_STAGING_DEMO_TOOLS_ENABLED` is required exactly once
   and accepts only unquoted lowercase `true` or `false`. Invalid/missing values
   fail locally before remote construction. Staging explicitly enables it;
   production stays disabled unless its reviewed target explicitly enables it.
2. **Manifest-bound state:** stage-release records the boolean and release SHA
   in the existing state document bound to the manifest digest. Later phases
   refuse missing bindings, foreign manifest/release evidence, missing/nonboolean
   evidence and disagreement with the currently loaded target.
3. **Staged environment:** the canonical non-secret flag is part of release-pin
   readback and verification, alongside existing image/key/hostname checks.
   Every phase from backup through GO rechecks agreement. Mismatch stops with
   `re-run stage-release`; no later phase rewrites a value. The staged rewrite
   removes prior flag assignments and leaves active bytes unchanged.
4. **Rendered Compose:** all reviewed rollout Compose commands use
   `env -u DEMO_TOOLS_ENABLED docker compose ...`. Only that variable is removed;
   unrelated required variables still reach Compose. Before activation, the
   full render (including inactive profiles) must contain exactly the reviewed
   boolean on API and no flag on any other service. The existing operator
   Alertmanager mount/config gates remain mandatory.
5. **Running API:** after recreation, during validation, before reopening and
   during GO, a Docker inspection template filters/computes the flag match
   internally. Only `match`/`mismatch` is returned; no complete environment or
   invalid flag content is returned/logged. Missing/duplicate values or a stopped
   container fail. A mismatch blocks reopening despite old successful evidence.

Re-staging an inactive release with a newly reviewed value updates the pin and
manifest-bound policy evidence, then clears prior recreation/validation/reopen
records. Backup/database/escrow facts retain their existing gates. Re-staging an
already active release is refused to prevent rewriting its environment through
`current`; use a new reviewed release.

## Rendered-Compose matrix

| Invocation and input | API | All other services |
|---|---|---|
| Unprotected parent-style invocation: file false, shell true | true (defect reproduced) | — |
| Reviewed file false, shell true/false/empty | false | absent |
| Reviewed file true, shell true/false/empty | true | absent |
| Ordinary production/staging render, missing/empty input | false | absent |
| Invalid/missing reviewed target | rejected before host contact | — |

The protected matrix runs through the actual active, staged and backup Compose
command builders. `NLW_LLM_MODEL` and all required shell-supplied settings survive
flag removal. Fresh-process API tests prove the pilot catalog and planner view
are populated only when enabled. Worker/scheduler actor processes receive no
flag and can still execute both registered pilot tool functions locally.

## Validation

| Check | Result |
|---|---|
| Focused rollout/Compose/visibility/capability/manifest/provenance/secret-isolation tests | **403 passed** |
| CI-equivalent `pytest -m 'not integration'` | **1,163 passed**, 34 opt-in live-model skips, 433 integration tests deselected |
| Ruff format/check | Passed repository-wide |
| mypy | Passed: 303 source files |
| YAML and rehearsal shell syntax | Passed: 16 tracked YAML files; `bash -n` |
| `git diff --check` | Passed |
| Committed disposable rehearsal | **Passed, exit 0**, including cleanup |

Unit coverage includes all eight boolean target/state/file combinations;
policy drift at every post-staging phase; missing/foreign manifest bindings and
foreign release state; noncanonical/missing/duplicate pins; explicit re-staging;
active-file byte identity; every forbidden rendered service; running mismatch
blocking recreation/validation/reopen/GO; and unchanged image/key/Alertmanager
checks. Existing visibility tests preserve already-materialized execution.
Four existing dependency/test warnings remained in the complete unit run.

The full committed rehearsal exercised both shell-override directions, target
mutation after staging, staged-file mutation, successful explicit re-staging,
and active-file byte identity. It then deliberately recreated API through an
unprotected invocation: validation and reopening both rejected the running
value. The reviewed invocation restored it. Worker execution and one scheduler
occurrence passed without receiving the flag.

The first local rollout reached `0021_analytics_handoff`; a second code-only
release activated through `current` with unchanged keys and preserved operator
Alertmanager authority. Local preflight-to-reopen timings were 139 seconds and
77 seconds respectively, excluding builds. The final disposable downgrade and
re-upgrade included `0020_schedule_authorization` → `0021_analytics_handoff`.
Cleanup removed the rehearsal containers, volumes, keys, manifests, registry and
temporary checkouts. This is local fixture evidence, not a VPS, backup-provider,
attestation or external-delivery claim.

Reproduction commands (repository root, local fixture sockets required):

```sh
UV_CACHE_DIR=/tmp/nlw-m12c-uv uv run pytest -m 'not integration' -q
UV_CACHE_DIR=/tmp/nlw-m12c-uv uv run ruff format --check .
UV_CACHE_DIR=/tmp/nlw-m12c-uv uv run ruff check .
UV_CACHE_DIR=/tmp/nlw-m12c-uv uv run mypy
bash -n scripts/ops/rehearse-0010-to-0016.sh
UV_CACHE_DIR=/tmp/nlw-m12c-uv bash scripts/ops/rehearse-0010-to-0016.sh
```

## Changed files in this correction

```text
docker-compose.prod.yml
src/nlw/ops/rollout/remote.py
src/nlw/ops/rollout/gates.py
src/nlw/ops/rollout/phases.py
scripts/ops/rehearse-0010-to-0016.sh
tests/unit/test_demo_tools_compose.py
tests/unit/test_rollout_gates.py
tests/unit/test_rollout_phases.py
docs/PROJECT_INDEX.md
docs/runbooks/staging-signed-context-rollout.md
docs/evidence/m12c/demo-tool-enablement.md
```

## Protected boundary

Migration 0021, analytics, datasets, contracts, frontend, planner/execution,
Slack, authorization, RLS, approval, audit, recovery and signed-context behavior
are unchanged. Backup/escrow/Alertmanager authority and release provenance policy
are unchanged. No migration or deployable manifest was created or edited. The
recorded staging source remains `0020_schedule_authorization`; a new attested
release still legitimately targets `0021_analytics_handoff`.

Nothing was pushed to Git or an external registry, deployed externally, or
changed on the VPS. The local rehearsal uses only disposable fixture resources
and a loopback registry. Independent delta verification is next; review/merge,
a new Delivery artifact and a matching escrow attestation precede any VPS rollout.
