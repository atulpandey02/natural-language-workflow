# M12C rollout correction: explicit demo-tool enablement

Baseline: local `main` at `549b19f`. Fix branch:
`fix/staging-demo-tool-enablement`. All verification was local; no VPS connection
or release operation was performed.

## Reproduction and correction

A local render of the original `549b19f:docker-compose.prod.yml`, with
`DEMO_TOOLS_ENABLED=true` supplied, omitted the variable from API, worker and
scheduler. Their application settings therefore kept new demo planning and the
pilot catalog disabled. The existing rollout rewrote only release pins and key
settings, while the operator override correctly allowed only Alertmanager mounts.

The target now requires `NLW_STAGING_DEMO_TOOLS_ENABLED` exactly once, with an
unquoted lowercase `true` or `false`. Missing, empty, duplicate or noncanonical
values fail before remote construction or phase execution. Staging explicitly
selects `true`; the disposable rehearsal explicitly selects `false`.

`stage-release` writes `DEMO_TOOLS_ENABLED` from that validated boolean into only
the staged `.env.prod`, replacing any value inherited from the active file. The
existing atomic rewrite, 0600 permissions and active-file hash check remain.
The phase evidence records only the boolean `demo_tools_enabled`. Production
targets must explicitly select `false` unless separately reviewed to enable it.
The application and ordinary Compose render remain default-off.

## Exact runtime service set

| Service | Inspected code path and reason |
|---|---|
| API | `api.app.create_app` loads Settings; `api.capability.demo_tools_included` gates new planning; `api.routers.analytics.datasets` gates the pilot catalog. API routers import `tools.builtin` to populate the registry. |
| Worker | `worker.actors` loads Settings and imports `engine.execution`, which imports `tools.builtin` and resolves tools through `REGISTRY`. It must receive the same environment policy as API. |
| Scheduler | `scheduler.__main__.main` loads Settings and imports `worker.actors.advance_run` for enqueueing, initializing the same registry/actor settings. It remains enqueue-only. |

Only these three services consume the production `x-app-env` anchor. The flag is
forwarded there as `${DEMO_TOOLS_ENABLED:-false}`. No service gains a secret or a
new mount. Disabling visibility still permits existing materialized workflows to
execute their registered tools, as required by the existing compatibility policy.

## Rendered-Compose matrix

Each render used dummy credentials, an empty project directory and `/dev/null`
as its environment file, including all service profiles. No containers started.

| Compose / reviewed setting | API | Worker | Scheduler | All other services |
|---|---|---|---|---|
| Original `549b19f`, explicit true | absent | absent | absent | absent |
| Production, missing or empty value | false | false | false | absent |
| Production, explicit false | false | false | false | absent |
| Production, explicit true | true | true | true | absent |
| Production + staging overlay, missing/empty/false | false | false | false | absent |
| Reviewed staging target, true | true | true | true | absent |
| Invalid or missing target setting | rejected before host contact | — | — | — |

The excluded services are Postgres, Redis, Caddy, web, migrate, backup, restore,
Prometheus and Alertmanager. Production enablement requires an explicit reviewed
target choice; the staging overlay itself does not enable demo tools.

## Validation

- **310 focused tests passed:** target parsing, rollout phases, new rendered
  Compose tests, existing deployment/secret/key/backup isolation checks, demo
  visibility, planner capabilities, release manifest and provenance tests.
- **1,070 CI-equivalent unit tests passed:** `uv run pytest -m 'not integration'`.
  The 34 skipped tests are opt-in live-model evaluations; 433 integration tests
  were deselected. Four existing dependency/test warnings remained. The first
  sandboxed attempt could not bind local fixture sockets; the rerun with local
  socket permission passed.
- **Ruff format/check passed** across the repository; **mypy passed** across 303
  source files. Shell syntax validation of the rehearsal script passed.
- **16 tracked YAML files parsed successfully.** CI's nine missing-required-value
  Compose cases still failed for the expected variable. An ordinary render
  succeeded without the migration credential; the credential appeared only in
  the profiled `migrate` service.
- Fresh processes initialized API and worker-actor Settings from each rendered
  runtime environment. Enabled API catalog/planning exposed both pilot tools;
  disabled catalog/planning exposed neither. Worker/scheduler actor imports saw
  the same boolean, and both registered pilot tool functions executed locally
  under either policy, preserving existing-workflow compatibility.
- Temporary-file tests executed the actual staged-env rewrite for missing,
  true, false and foreign manual active values, with both reviewed target values.
  Active bytes stayed identical; staged output contained one reviewed assignment,
  kept unrelated settings and retained 0600 permissions.
- Existing manifest/image-gate tests verified the recorded `0020` source and
  `0021` target, including rejection of an image missing the required migration.
  `git diff --check` passed.

No database migration, full integration suite, frontend build, container image
build or live smoke was run for this configuration-only correction. No release
manifest, downloaded artifact or existing `549b19f` release was changed.

## Changed files

```text
.env.prod.example
deploy/staging/target.env
docker-compose.prod.yml
scripts/ops/rehearse-0010-to-0016.sh
src/nlw/ops/rollout/remote.py
src/nlw/ops/rollout/phases.py
tests/unit/test_rollout_gates.py
tests/unit/test_rollout_phases.py
tests/unit/test_demo_tools_compose.py
docs/PROJECT_INDEX.md
docs/runbooks/staging-signed-context-rollout.md
docs/evidence/m12c/demo-tool-enablement.md
```

## Review boundary

Analytics, frontend, Slack, planner/execution semantics, authorization, RLS,
approvals, audit, recovery and signed context are unchanged. Migration 0021,
Alertmanager operator-authority restrictions, backup/escrow behavior and release
manifest/provenance authority are unchanged. No new migration was added.

Nothing was pushed, merged, staged on the VPS, deployed, drained, migrated or
restarted. No VPS was contacted or changed. Stop for review. After approval,
the new merged SHA needs its own Delivery artifact and escrow attestation before
the complete rollout; `549b19f` is unsuitable for deployment. Backup timer
installation/verification and real Sales/Support browser smoke remain subsequent
deployment work.
