# Runbook — Staging signed-context rollout (M12A: schema 0010 → 0016)

Applies to: the staging/pilot VPS currently running the M11 release (commit
`5151a2c`, Alembic `0010_readiness_schema_grant`) being upgraded to a `main`
release at Alembic `0016_signed_database_context` (ADR-024). The operator tool
is `python -m nlw.ops.rollout`; the reviewed Compose deployment
(`docker-compose.prod.yml` + `docker-compose.staging.yml`) is what it drives.

**The default invocation is read-only.** Nothing mutates the host until the
operator passes the exact authorization phrase, and even then each phase
re-verifies the target instance, the release manifest, the current migration
revision and every earlier gate recorded on that host. **No database mutation
of any kind happens before an off-host backup has been taken and verified.**

## Release authority: the CI-generated manifest (never a committed file)

Nothing in git is deployable release authority. The `Delivery` workflow
(`.github/workflows/staging.yml`) builds and pushes both images by digest for
the exact commit, then **generates** the manifest from those digests with
`python -m nlw.ops.release_manifest generate --generated-by ci`, validates it,
and uploads it as the run artifact `release-manifest-<sha>` (never committed).
It carries only identity: format version, `kind: release`, `deployable: true`,
git SHA, backend/web manifest digests, expected current + target migration
revisions, instance id / region / compose project / hostname, key ids,
creation time, the CI workflow/run id/run URL, an optional attestation
reference — and no secrets (the workflow greps for credential-like keys).

| file | role |
|---|---|
| `release-manifest-<sha>` (GitHub Actions artifact) | **the only deployable authority**; download it for the exact merged commit you intend to deploy — a PR-build digest is never the merged-main digest |
| `deploy/staging/release.example.json` | committed **template only**: `kind: example`, `deployable: false`, zero SHA/digests; every loader rejects it |
| `deploy/staging/target.env` | host identity + expected current revision + key ids (the generator's input; reviewed in git) |

`load_release` refuses: any `kind` other than `release`, `deployable != true`,
mutable tags, short SHAs, a manifest whose `generated_by` is `local-rehearsal`
unless `--local` is given (a rehearsal manifest is never authority for a real
target), and any credential-like key. **A locally edited JSON file cannot
silently become release authority**: without `--local` the loader only accepts
`generated_by: ci` with the run identity present, and `verify-release` then
proves the pulled images are that commit.

```
gh run download <run-id> -n release-manifest-<sha>     # or the Actions UI
uv run python -m nlw.ops.release_manifest validate release-manifest.json
uv run python -m nlw.ops.rollout preflight --release release-manifest.json
```

## Identity model

| what | where | why |
|---|---|---|
| EC2 **instance id** (authoritative) | `deploy/staging/target.env` and the manifest | compared with IMDSv2 on the connected host; mismatch = stop |
| SSH address / user | `deploy/staging/target.env` (`NLW_STAGING_SSH_HOST`; override with `SSH_HOST`) | the public IPv4 is auto-assigned and can change after STOP+START; it is only how SSH reaches the box |
| Release SHA, backend/web image **digests**, expected current + target revisions, key ids | the CI manifest | mutable tags are never deployment authority |
| Compose project | `target.env` / manifest (`app`) | leftover-container and state-file scoping; every Compose call passes `-p` explicitly |
| Ops root layout | `target.env` (`NLW_STAGING_OPS_ROOT=/opt/nlw`) | `app` = active checkout, `releases/<sha>` = staged release, `current` = activation symlink, `rollout/` = state |

Every Mac-side ops script sources `scripts/ops/lib/staging-target.sh`; none
hard-codes an address. `deploy-staging.sh` / `verify-staging-deployment.sh`
take the manifest from `NLW_STAGING_RELEASE_FILE` and validate it first.

## Host layout: staging is separate from activation

```
/opt/nlw/app                     ACTIVE M11 checkout + .env.prod (services run from it) — untouched until activation
/opt/nlw/releases/<release_sha>  STAGED release: clone at the release SHA, its OWN .env.prod (digests, key ids, key dir)
/opt/nlw/current -> releases/…   created by recreate-runtime; the systemd backup timer follows it
/opt/nlw/rollout/<sha>.json      rollout state + evidence (outside every git checkout)
/opt/nlw/rollout/alert-delivery.json   operator record of a verified controlled test alert (see docs/ops/alerting.md)
/opt/nlw/.env.backup             backup env (systemd + rollout use the same file)
```

Allowed **before** the verified backup (host staging only): pulling images,
placing key files, validating their permissions, writing the attestation,
staging the release directory and its config, building the backup image,
running the backup. **Not** allowed before it: touching the active `.env.prod`
or checkout, recreating any container, changing Caddy routing, any DB change,
stopping traffic. A failure anywhere before `recreate-runtime` leaves the M11
runtime exactly as it was.

## Phases

```
uv run python -m nlw.ops.rollout preflight             --release M   # READ-ONLY (default phase)
uv run python -m nlw.ops.rollout verify-release        --release M --authorize <phrase>
uv run python -m nlw.ops.rollout prepare-keys          --release M --authorize <phrase>
uv run python -m nlw.ops.rollout verify-escrow         --release M --authorize <phrase> --escrow-confirm <phrase> --attestation FILE
uv run python -m nlw.ops.rollout stage-release         --release M --authorize <phrase>
uv run python -m nlw.ops.rollout backup                --release M --authorize <phrase>
uv run python -m nlw.ops.rollout verify-backup         --release M --authorize <phrase>
# ---------------- no database mutation above this line ----------------
uv run python -m nlw.ops.rollout drain                 --release M --authorize <phrase>
uv run python -m nlw.ops.rollout prepare-roles         --release M --authorize <phrase>
uv run python -m nlw.ops.rollout migrate               --release M --authorize <phrase>
uv run python -m nlw.ops.rollout install-context-keys  --release M --authorize <phrase>
uv run python -m nlw.ops.rollout recreate-runtime      --release M --authorize <phrase>
uv run python -m nlw.ops.rollout validate              --release M --authorize <phrase>
uv run python -m nlw.ops.rollout reopen                --release M --authorize <phrase>
uv run python -m nlw.ops.rollout go-check              --release M   # READ-ONLY M12 GO evaluation
```

| phase | mutates | gates re-checked | what it does |
|---|---|---|---|
| `preflight` | no | manifest schema/kind/deployability; instance id + region; hostname ↔ public IPv4; active `.env.prod` hostname; roles model (M11 set acceptable); drain counters; current revision = expected | prints a sanitized report (manifest sha256, active checkout SHA); run it as often as you like |
| `verify-release` | host image cache | authorization; identity | `docker pull` both digests; `org.opencontainers.image.revision` label == release SHA on both; runs `nlw.ops.rollout.image_info` in the backend image and checks reported git SHA, migrations 0011–0016 present, Alembic head == target; runs `--help` of `nlw.ops.rollout`, `nlw.ops.roles`, `nlw.ctxkeys prepare/fingerprint/verify-files`, `nlw.backup evidence` inside the exact image. An older image (e.g. `1eebf2e`, no label, no tooling) is refused |
| `prepare-keys` | host files | authorization; identity | generates three independent 32-byte keys **on the host** through the release image running as root (`nlw.ctxkeys prepare`): dir `0700` root, files `0400` uid 10001, never overwrites, prints fingerprints only |
| `verify-escrow` | state only | authorization; **escrow phrase**; attestation fingerprints == host fingerprints; release SHA/env; ≤ 30 days old | the operator must have escrowed the files first — see the escrow section of [signed-context-keys](signed-context-keys.md) |
| `stage-release` | `releases/<sha>` only | authorization; verify-release + verify-escrow done; identity | clone the active checkout into `releases/<sha>`, `git checkout --detach <release_sha>` (clean), write the staged `.env.prod` (active copy with only digests/key ids/key dir rewritten; temp-file rewrite, 0600), render `config`, build the backup image from the pinned digest; verifies the active `.env.prod` hash is unchanged afterwards |
| `backup` | nothing on the host DB | authorization; stage-release done; staged checkout clean; revision = expected | runs the real off-host backup job from the staged release (`--profile backup run --rm --no-deps`, owner credential, read-only dump) with the source binding `instance id / environment / active release SHA`; the backup manifest records the DB system identifier and revision |
| `verify-backup` | state only | authorization; stage-release done | `nlw.backup evidence` from the staged release; requires: real `s3:https://` off-host repository (MinIO/loopback/private/same-host refused), `nlw_backup_success=1`, `repository_verify_success=1`, verified within 26 h, newest `nlw-db` snapshot tagged `rev-<expected current revision>` within 1 h of the metrics timestamp, the manifest **inside the snapshot** bound to this instance id, environment, `pg_control_system()` identifier, active release SHA and revision, no key-like artifacts. Operator-edited JSON is never accepted alone |
| `drain` | runtime | authorization; **verify-backup done**; identity; staged checkout | recreate **caddy only** from the staged config (`--no-deps --force-recreate`, brief edge blip) so the maintenance matcher exists; maintenance 503 (`caddy_maint` flag, no reload); stop scheduler; wait ≤ 120 s for non-terminal runs / queue to reach zero (never force-retries ambiguous work); stop worker + api; require zero runtime DB sessions |
| `prepare-roles` | DB roles | verify-backup + drain done; identity; no sessions | `python -m nlw.ops.roles ensure` via the staged `migrate` service: creates `nlw_membership_admin` (NOLOGIN, BYPASSRLS) and `nlw_ctx_verifier` (NOLOGIN, NOBYPASSRLS) if absent, verifies every nlw role, grants nothing on tables |
| `migrate` | DB | verify-backup/drain/prepare-roles done; identity; staged checkout; no sessions; revision = expected; roles complete | runs the staged `migrate` service (0011–0016), verifies revision = target, 51 policies, 0 legacy-GUC policies, registry owner/grants |
| `install-context-keys` | DB registry | migrate done; no sessions; revision = target | `nlw.ctxkeys install` ×3 from mounted files (throwaway `migrate` container, removed after), `ctxkeys check` ×3, ≥ 3 active keys, audit contains no material |
| `recreate-runtime` | `current` symlink, containers | install done; revision; staged pins | **activation**: `current -> releases/<sha>`, `up -d --force-recreate --no-deps api worker scheduler web` (+ prometheus/alertmanager) from the staged release; each runtime runs the release digest and mounts **only its own** key read-only; no runtime mounts the backup evidence volume; no key-like env values; no leftover one-shot containers |
| `validate` | none | recreate done | `/health/ready` → `signed_context: ok`; policy cutover; mount isolation; **unsigned forgery as the real `nlw_app` sees no rows**; worker/scheduler healthy; Prometheus rule groups loaded + Alertmanager reachable. Then run `nlw.ops.rollout.smoke` inside the api container with synthetic ids for the invitation / four-eyes checks |
| `reopen` | Caddy flag | validate done; readiness re-checked; rules + connectivity | removes the maintenance flag and **records the open launch gates** — with the null receiver: `alert delivery unverified` (technical deployment only, not an M12 GO) |
| `go-check` | no | reopen done | the M12 GO evaluation: NO-GO on a null receiver, missing credential files, or no verified controlled test alert on record |

Rollout state (`<ops_root>/rollout/<release_sha>.json`) records completion
times and non-secret evidence (manifest sha256, image identity, snapshot id,
repository host, fingerprints, digests, counts, alerting status, open launch
gates). It never contains phrases, credentials, repository URLs or key
material, and the writer refuses anything that looks like one. It lives
outside every git checkout, so no checkout is ever dirtied by a rollout.

## What cannot happen

* **No database mutation before a verified off-host backup**: `drain`,
  `prepare-roles`, `migrate`, `install-context-keys` all require the recorded
  `verify-backup`; a failed or missing backup leaves roles, schema, active
  config and the old runtime untouched (`tests/unit/test_rollout_phases.py`
  records every command up to `verify-backup` and proves none touches the DB,
  the active `.env.prod`, the checkout, Caddy or a container).
* The **wrong image never deploys**: `verify-release` rejects an image whose
  revision label / reported SHA differ from the manifest or which lacks the
  0011–0016 migrations or the rollout commands.
* The **old runtime never starts against schema 0016**: runtimes are stopped
  before `migrate` and only recreated from the release digests after all three
  keys verify.
* The **new runtime never starts without keys**: `install-context-keys` must
  succeed for all three classes and be recorded before `recreate-runtime`.
* **No `--yes`**, no environment override, no partial phrase: only the exact
  phrases below authorize anything, and they are never stored.
* **No automatic downgrade** below 0016. A failure after `migrate` leaves the
  runtimes stopped and the database at 0016 (fail closed); fix forward per
  [failed-migration](failed-migration.md) and re-run the failed phase. The
  pre-deployment backup is the only true rollback; before activation, the
  untouched `/opt/nlw/app` runtime is.
* **A null Alertmanager receiver never becomes "alert delivery configured"**:
  see [alerting](../ops/alerting.md); `go-check` fails on it.

## Human phrases (documented; never pre-filled)

* `AUTHORIZE_M12A_SIGNED_CONTEXT_STAGING_DEPLOYMENT` — passed as `--authorize`
  to every mutating phase. It authorizes **this host and this release** only.
* `SIGNED_CONTEXT_KEYS_ESCROWED_AND_RECOVERY_TESTED` — passed as
  `--escrow-confirm` to `verify-escrow`, together with the attestation file.

**Neither phrase is a substitute for backup-provider configuration.** The
`verify-backup` gate needs a real, verified, off-host backup bound to this
database and stops without one regardless of what the operator types.

## Rehearsal

`scripts/ops/rehearse-0010-to-0016.sh` runs the identical external-manifest
flow against a disposable local stack: throwaway registry; an OLD backend
image built from the M11 pin and NEW images built with the release SHA; an ops
root laid out like `/opt/nlw`; manifests produced by the same generator
(`--generated-by local-rehearsal`, accepted only with `--local`); proofs that
the committed example is rejected, that a manifest naming the old image fails
`verify-release`, that two forced backup failures (no evidence; broken
repository credential) leave roles / schema / active config / old runtime
untouched and `drain`/`prepare-roles`/`migrate` refused; then the real P2
backup into a MinIO **fixture** (accepted only with
`--local --allow-fixture-repository`; not DR evidence), the remaining phases,
`reopen` recording `alert delivery unverified`, `go-check` failing, the
invitation/four-eyes, worker, scheduler and rule-group proofs, a separate
downgrade proof, and cleanup of keys, manifests, volumes and the registry.

## Evidence to keep

`preflight` output, the manifest artifact name + sha256, the rollout state
file, `scripts/ops/verify-staging-deployment.sh` output after `reopen`, the
`go-check` result, and the attestation file (fingerprints only). Record
digests and the instance id, never credentials.
