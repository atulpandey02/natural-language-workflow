# Runbook — Staging signed-context rollout (M12A: schema 0010 → the release head)

Applies to: the staging/pilot VPS currently running the M11 release (commit
`5151a2c`, Alembic `0010_readiness_schema_grant`, legacy layout `/opt/nlw/app`)
being upgraded to a `main` release whose manifest names the target head (the
release at `7c3d350` targets `0020_schedule_authorization`; the tooling is
head-agnostic — `migrate` runs `alembic upgrade head` and verifies it equals the
manifest's `target_revision`). The operator tool is `python -m nlw.ops.rollout`;
the reviewed Compose deployment (`docker-compose.prod.yml` +
`docker-compose.staging.yml`) is what it drives. **For the first rollout from
the legacy layout read [First rollout from the legacy layout](#first-rollout-from-the-legacy-layout-optnlwapp--optnlwcurrent) below.**

**The default invocation is read-only.** Nothing mutates the host until the
operator passes the exact authorization phrase, and even then each phase
re-verifies the target instance, the release manifest, the current migration
revision and every earlier gate recorded on that host. **No database mutation
of any kind happens before an off-host backup has been taken and verified.**

## Release authority: schema + images + provenance (ADR-025)

Nothing in git is deployable release authority, and **structural validity is
not authority either**: a JSON written by hand with `kind: release`,
`deployable: true`, `generated_by: ci`, a real SHA and real digests passes the
schema check, and can pass the image check when it names real images. Three
independent checks are therefore all mandatory before any host is contacted:

| check | tool | what it prevents |
|---|---|---|
| **Schema validity** | `python -m nlw.ops.release_manifest validate` | malformed, non-deployable, secret-bearing or inconsistent manifests (the committed `deploy/staging/release.example.json` is rejected) |
| **Image capability / identity** | rollout `verify-release` | incompatible or mismatched images: revision labels, `image_info` SHA, every migration from expected+1 to the target head, head == `target_revision`, required commands (the old `1eebf2e` image is refused) |
| **Provenance / authenticity** | `python -m nlw.ops.release_provenance verify` (run automatically by every rollout invocation) | any manifest not produced by the trusted Delivery workflow for the exact merged-main commit; substituted digests; edited bytes; PR/fork/non-main/other-workflow/other-repository/other-commit provenance; failed or artifact-less runs |

The Delivery workflow (`.github/workflows/staging.yml`; trigger: `push` to
`main` **only**) builds both images by digest, generates the manifest from
those digests, **attests** the manifest bytes and both image digests
(GitHub artifact attestations: Sigstore keyless signing with the workflow's
OIDC identity, SLSA v1 provenance), and uploads `release-manifest-<sha>`. A
separate proof job downloads it and runs the same verifier the operator runs.

Provenance policy enforced by the verifier (code, not only CLI flags):
repository `atulpandey02/natural-language-workflow`; signer workflow
`.github/workflows/staging.yml@refs/heads/main`; ref `refs/heads/main`; event
`push`; GitHub-hosted runner; OIDC issuer `token.actions.githubusercontent.com`;
source commit == `release_sha`; attested run == the run named in the manifest,
for the manifest **and** both images; that run completed successfully and
uploaded `release-manifest-<sha>`; subject digest == sha256 of the manifest
bytes / == each image digest.

**Trust boundary.** Verification needs network access to GitHub (attestation
API, Sigstore trust root, Actions API) and an authenticated `gh` with read
access to the repository and its packages; it is not offline-verifiable, and
without it the rollout fails closed. GitHub itself and the repository's
administration (the trusted workflow file, `main` branch protection, Actions
settings) are inside the trust boundary: a compromise there is outside what
this check can detect. Rehearsals use a separate unsigned fixture mechanism
(`--local --provenance-fixture`) that carries a different identity and never
satisfies the staging/production policy.

### Operator artifact-selection flow (exact)

1. Identify the **successful Delivery run for the merged-main commit** you
   intend to deploy (`gh run list --workflow Delivery --branch main`; never a
   PR run, never a re-run of a different commit). Note its run id.
2. Download the artifact for that run:
   `gh run download <run-id> -n release-manifest-<full-sha>`.
3. Provenance is fetched by the verifier from GitHub/Sigstore; nothing else to
   download. Confirm `gh auth status` on the operator machine.
4. Verify provenance against the policy and write the receipt:
   `uv run python -m nlw.ops.release_provenance verify release-manifest.json --receipt receipt.json`
   (exit 3 = not release authority; stop).
5. The same command verified the **manifest digest** (subject sha256 == the
   downloaded bytes) — the receipt records it; record the sha256 in the change
   log.
6. Image identities and capabilities are verified on the host by
   `verify-release` (labels, `image_info`, migrations, commands) — and their
   attestations were already checked in step 4 for the same commit and run.
7. Only now run the read-only preflight:
   `uv run python -m nlw.ops.rollout preflight --release release-manifest.json`
   (every rollout invocation repeats step 4 before touching the target).
8. `verify-release` stores the verified manifest bytes and the receipt under
   `/opt/nlw/rollout/<sha>.manifest.json` / `<sha>.receipt.json` (the evidence
   directory, outside every checkout).
9. Rollout state is bound to the **manifest digest**, not the file name: if the
   manifest file is replaced later (even by a whitespace change), every phase
   stops with "recorded for a different release manifest" and the earlier
   evidence is invalid.

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
/opt/nlw/rollout/alert-delivery.json   operator record of a verified controlled test alert (root:nlwops 0640,
                                 written by scripts/ops/record-alert-delivery.sh; see docs/ops/alerting.md)
/opt/nlw/alertmanager/alertmanager.yml   OPERATOR Alertmanager config (root:root 0644) — authority for the receiver
/opt/nlw/alertmanager.secrets/   receiver credentials, root:65534 0750 / files root:65534 0640 (Alertmanager = uid 65534)
/opt/nlw/docker-compose.operator.yml   reviewed override mounting both into the alertmanager service (every
                                 Compose invocation from a release directory carries it)
/opt/nlw/.env.backup             backup env (systemd + rollout use the same file; MUST be readable by the
                                 rollout SSH user — preflight refuses a missing/unreadable/world-readable file)
/opt/nlw/app/docker/worker.secrets.env   git-IGNORED worker connector secrets: stage-release copies it (0600) into the
                                 staged release; otherwise the recreated worker would start without them
```

Allowed **before** the verified backup (host staging only): pulling images,
placing key files, validating their permissions, writing the attestation,
staging the release directory and its config, building the backup image,
running the backup. **Not** allowed before it: touching the active `.env.prod`
or checkout, recreating any container, changing Caddy routing, any DB change,
stopping traffic. A failure anywhere before `recreate-runtime` leaves the M11
runtime exactly as it was.

## First rollout from the legacy layout (`/opt/nlw/app` → `/opt/nlw/current`)

The tooling never *discovers* the active deployment: `deploy/staging/target.env`
names it (`NLW_STAGING_REMOTE_APP=/opt/nlw/app`, `NLW_STAGING_COMPOSE_PROJECT=app`)
and the manifest must agree. `/opt/nlw/current` and `/opt/nlw/releases/` do
**not** need to exist — `recreate-runtime` is the only phase that creates or
moves `current` (it refuses a real directory there and verifies the link
afterwards). Every Compose invocation passes `-p app` explicitly, so the staged
release joins the **existing** project: `app_pgdata`, `app_caddy_*`,
`app_internal` are reused, no second database is created, and one-shot runs
(`backup`, `evidence`, roles, migrate, key install) use `--no-deps` so Compose
never recreates the live `postgres`/`redis` containers from the staged directory.

### Who runs what

| where | as | what |
|---|---|---|
| **Mac** (repo root, `main` at the release SHA) | you | `gh run download`, `release_provenance verify`, **every** `uv run python -m nlw.ops.rollout …` phase (SSH → host as `nlwops`, no sudo) |
| `ubuntu@32.197.83.193` (or the sudo-capable operator login) | **root** (`sudo`) | one-time host prerequisites only: backup env file + ownership, key escrow tarball, the operator Alertmanager files (config, secrets dir, override — permissions in `docs/ops/alerting.md`), the delivery record (`scripts/ops/record-alert-delivery.sh` after a human saw the test alert), systemd units **after** activation |
| host | **nlwops** | nothing by hand — the rollout acts as this user; the only manual `nlwops` action is `docker login ghcr.io` if the packages are private |
| host | anyone | read-only checks (`docker compose -p app ps`, `readlink /opt/nlw/current`, `journalctl -u nlw-backup`) |

Secret-entry steps (root, on the host): values are typed/pasted into the editor
of a `0600` file and **never** echoed, logged, passed on argv, or committed.

### Prerequisites and decisions (STOP gate — nothing below runs until all hold)

1. **Backup env file** — the rollout and the systemd unit read the SAME file,
   `/opt/nlw/.env.backup` (or the path set in `NLW_STAGING_BACKUP_ENV_FILE`,
   which must then also be the path in the systemd unit). It is read
   *client-side* by `docker compose --env-file` as **nlwops**, so a `root:root
   0600` file makes `preflight` stop with "not readable by the rollout user",
   and an **empty** file (the host's current state: created, never filled)
   stops it with "is empty" — the mode and size are checked, never the
   contents.
   Decision to record: `root:nlwops 0640` (recommended — `nlwops` is in the
   `docker` group and is therefore already root-equivalent on this host) **or**
   `nlwops:nlwops 0600`. Fill it from `.env.backup.example`: the DB host is the
   Compose service name `postgres` (not `db`); `RESTIC_PASSWORD` is the inline
   repository passphrase (a separate password *file* is not read by the job);
   set `NLW_BACKUP_SOURCE_INSTANCE_ID` and `NLW_BACKUP_ENVIRONMENT`.
2. **Retention mode vs the IAM writer** — measured (disposable MinIO, restic
   0.18): every writer needs `s3:DeleteObject` on `<prefix>/locks/*`, otherwise
   restic cannot remove its own lock and the job's post-upload `restic check`
   fails ("repository is already locked") — **every backup fails**. With a
   locks-only delete writer, `NLW_BACKUP_RETENTION_MODE=immutable` works;
   `simple` fails at `forget --prune` *after* the verified upload (`Fatal:
   Access Denied`, `nlw_backup_success 0`, gate refuses). Decide explicitly
   before the first backup: `immutable` (prune later off-host with a
   delete-capable key) **or** grant delete on the whole prefix and keep
   `simple`. See `docs/ops/backup-providers.md`.
3. **Image pull access** — `verify-release` runs `docker pull` as `nlwops`; if
   the GHCR packages are private, `docker login ghcr.io` (read:packages) first.
4. **Keys** — `--keys-dir` defaults to `/srv/nlw/ctx-keys`; the parent
   `/srv/nlw` is created root-owned by Docker if absent. Escrow + attestation
   per [signed-context-keys](signed-context-keys.md) before `verify-escrow`.
5. **Manifest** — the attested `release-manifest-<sha>` downloaded for the
   Delivery run of the merged-main commit; keep it **outside** the repo (it is
   not tracked) and never edit it (the attestation binds the exact bytes).
6. **Disk** — the rollout does not check free space; confirm ≥ 10 GiB free on
   `/` before `verify-release` (two image pulls + the backup image build).
7. **Do not** run `scripts/ops/deploy-staging.sh` (it re-pins `/opt/nlw/app` in
   place and now refuses a host with `releases/` or `current`), any
   `scripts/ops/smoke-*.sh` (they `down -v`; they now refuse to run under
   `/opt`), or a bare `cd /opt/nlw/app && docker compose up …` after activation
   (that would recreate runtimes from the **old** image against the new schema).

### Mutation boundaries and stop/go gates

| gate | proven by | what is still safe if it fails |
|---|---|---|
| provenance rejected | every invocation, before host contact | nothing was contacted |
| `preflight` STOP (identity, revision ≠ `expected_current_revision`, backup env file, roles) | read-only | nothing changed |
| `verify-release` / `prepare-keys` / `verify-escrow` / `stage-release` STOP | host staging only | old runtime serving from `/opt/nlw/app`; `.env.prod` hash-verified unchanged; DB untouched |
| `backup` / `verify-backup` STOP | one-shot containers only (`--no-deps`) | same as above — **retry after fixing the provider**; drain/roles/migrate stay refused |
| `drain` STOP | edge on maintenance, scheduler stopped | DB untouched; manual: `cd /opt/nlw/releases/<sha> && docker compose -p app --env-file .env.prod -f docker-compose.prod.yml -f docker-compose.staging.yml exec -T caddy rm -f /srv/maint/MAINTENANCE` and `… start scheduler` to resume the OLD runtime |
| `prepare-roles` / `migrate` / `install-context-keys` STOP | DB mutated, runtimes stopped | **halted state, never silently old code**: fix forward (`failed-migration.md`) and re-run the failed phase; the verified backup is the rollback |
| `recreate-runtime` STOP | `current` may already point at the release | re-run the phase; do not touch `/opt/nlw/app` |

### After activation: every later rollout follows `current` (N → N+1)

* The first rollout is done: `deploy/staging/target.env` now names
  `NLW_STAGING_REMOTE_APP=/opt/nlw/current` and
  `NLW_STAGING_CURRENT_REVISION=0020_schedule_authorization`. Every phase
  reads, stops, `exec`s into and clones **through `current`** (the previous
  release N); `stage-release` fetches the release SHA from the reviewed
  `NLW_STAGING_GIT_REMOTE` (GitHub), not the local clone chain; `prepare-keys`
  verifies and fingerprints the existing keys (the operator writes a new escrow
  attestation for the new release SHA with the **same** fingerprints);
  `install-context-keys` reports `unchanged:`; activation re-points `current`
  to `releases/<N+1>`. The Compose project stays `app`, volumes and the live
  `postgres`/`redis` containers are untouched (`--no-deps` everywhere).
  Rehearsed end to end by `scripts/ops/rehearse-0010-to-0016.sh` step 9b.
* Fail-closed mismatches (nothing changed): a follows-current target on a host
  with no `current` ("no activated release"); a legacy target
  (`/opt/nlw/app`) on a host whose `current` points at a release ("set
  NLW_STAGING_REMOTE_APP=/opt/nlw/current"); `current` pointing outside
  `releases/`; a release SHA not reachable from the git remote ("merge/push it
  first"). Re-running a phase for the release that is already active is
  allowed (`current_link: THIS_RELEASE`).
* **Code-only releases** (no new migration, `expected_current_revision ==
  target_revision` — the shape of a hotfix) are supported: CI generates the
  manifest as usual, `migrate` runs `alembic upgrade head` as a verified no-op
  and every other gate (verified backup, live revision, keys, activation,
  effective alerting) applies unchanged. Rehearsed as the N → N+1 cycle.
* `/opt/nlw/app` is a rollback artefact of the first rollout only; nothing
  reads it any more.
* Install the systemd backup units only now (`docs/ops/backup-systemd.md`): the
  unit runs from `/opt/nlw/current`, which exists only after activation, and the
  pre-M12A checkout has no `backup` service. The rollout's own `backup` phase
  covered the pre-migration point.
* `scripts/ops/verify-staging-deployment.sh` still inspects `/opt/nlw/app` and
  will FLAG the SHA/pins after activation (known limitation); use the rollout's
  `validate`/`go-check` evidence and `readlink /opt/nlw/current` instead.

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
| *(every invocation)* | no | manifest schema; **provenance** (GitHub attestation policy; fixture only under `--local`) | stops before any host contact when the manifest is not release authority |
| `preflight` | no | manifest schema/kind/deployability; instance id + region; hostname ↔ public IPv4; active `.env.prod` hostname; roles model (M11 set acceptable); drain counters; current revision = expected; backup env file readable by the rollout user, not world-readable and not empty (mode and size only, contents never read); `current` absent or pointing at this release | prints a sanitized report (manifest sha256, active checkout SHA, backup env mode); run it as often as you like |
| `verify-release` | host image cache, evidence dir | authorization; provenance receipt for this exact manifest digest; identity | `docker pull` both digests; `org.opencontainers.image.revision` label == release SHA on both; runs `nlw.ops.rollout.image_info` in the backend image and checks reported git SHA, every migration from expected+1 to the target present, Alembic head == `target_revision`; runs `--help` of `nlw.ops.rollout`, `nlw.ops.roles`, `nlw.ctxkeys prepare/fingerprint/verify-files`, `nlw.backup evidence` inside the exact image. An older image (e.g. `1eebf2e`, no label, no tooling) is refused |
| `prepare-keys` | host files | authorization; identity | generates three independent 32-byte keys **on the host** through the release image running as root (`nlw.ctxkeys prepare`): dir `0700` root, files `0400` uid 10001, never overwrites, prints fingerprints only. On a follow-up release the complete existing set is verified + fingerprinted instead (`reused_existing`); a partial set stops |
| `verify-escrow` | state only | authorization; **escrow phrase**; attestation fingerprints == host fingerprints; release SHA/env; ≤ 30 days old | the operator must have escrowed the files first — see the escrow section of [signed-context-keys](signed-context-keys.md) |
| `stage-release` | `releases/<sha>` only | authorization; verify-release + verify-escrow done; identity | clone the active checkout into `releases/<sha>`, `git checkout --detach <release_sha>` (clean), write the staged `.env.prod` (active copy with only digests/key ids/key dir rewritten; temp-file rewrite, 0600), copy the git-ignored `docker/worker.secrets.env` (0600) when present (recorded as `staged`/`absent`), render `config`, build the backup image from the pinned digest; verifies the active `.env.prod` hash is unchanged afterwards |
| `backup` | nothing on the host DB | authorization; stage-release done; staged checkout clean; revision = expected | runs the real off-host backup job from the staged release (`--profile backup run --rm --no-deps`, owner credential, read-only dump) with the source binding `instance id / environment / active release SHA`; the backup manifest records the DB system identifier and revision |
| `verify-backup` | state only | authorization; stage-release done | `nlw.backup evidence` from the staged release; requires: real `s3:https://` off-host repository (MinIO/loopback/private/same-host refused), `nlw_backup_success=1`, `repository_verify_success=1`, verified within 26 h, newest `nlw-db` snapshot tagged `rev-<expected current revision>` within 1 h of the metrics timestamp, the manifest **inside the snapshot** bound to this instance id, environment, `pg_control_system()` identifier, active release SHA and revision, no key-like artifacts. Operator-edited JSON is never accepted alone |
| `drain` | runtime | authorization; **verify-backup done**; identity; staged checkout | recreate **caddy only** from the staged config (`--no-deps --force-recreate`, brief edge blip) so the maintenance matcher exists; maintenance 503 (`caddy_maint` flag, no reload); stop scheduler; wait ≤ 120 s for non-terminal runs / queue to reach zero (never force-retries ambiguous work); stop worker + api; require zero runtime DB sessions |
| `prepare-roles` | DB roles | verify-backup + drain done; identity; no sessions | `python -m nlw.ops.roles ensure` via the staged `migrate` service: creates `nlw_membership_admin` (NOLOGIN, BYPASSRLS) and `nlw_ctx_verifier` (NOLOGIN, NOBYPASSRLS) if absent, verifies every nlw role, grants nothing on tables |
| `migrate` | DB | verify-backup/drain/prepare-roles done; identity; staged checkout; no sessions; revision = expected; roles complete | runs the staged `migrate` service (`alembic upgrade head`, `--no-deps`), verifies revision = `target_revision`, 51 policies, 0 legacy-GUC policies, registry owner/grants |
| `install-context-keys` | DB registry | migrate done; no sessions; revision = target | `nlw.ctxkeys install` ×3 (throwaway `migrate` container, uid 10001, removed after), each mounting **only its own key file** — the `root 0700` key directory is never mounted or loosened (mounting the directory made every key unreadable on the pilot host); `ctxkeys check` ×3, ≥ 3 active keys, audit contains no material |
| `recreate-runtime` | `current` symlink, containers | install done; identity; revision; staged pins; **operator Alertmanager authority** (files, permissions, override, rendered Compose mounts — before anything is recreated); `current` absent or a symlink (a real directory is refused); the link is re-read and must point at the staged release | **activation**: `current -> releases/<sha>`, `up -d --force-recreate --no-deps api worker scheduler web` (+ prometheus/alertmanager, with the operator override) from the staged release; each runtime runs the release digest and mounts **only its own** key read-only; no runtime mounts the backup evidence volume or Alertmanager secrets; no key-like env values; no leftover one-shot containers; the running Alertmanager mounts the operator paths and loaded the operator config |
| `validate` | none | recreate done | `/health/ready` → `signed_context: ok`; policy cutover; mount isolation; **unsigned forgery as the real `nlw_app` sees no rows**; worker/scheduler healthy; Prometheus rule groups loaded + Alertmanager reachable; the **running** Alertmanager's effective configuration (mounts, mounted bytes, loaded config, credential readability as uid 65534) is the operator's. Then run `nlw.ops.rollout.smoke` inside the api container with synthetic ids for the invitation / four-eyes checks |
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
  migrations up to the target head or the rollout commands.
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
  see [alerting](../ops/alerting.md). For staging/production the operator's
  host-side configuration is required and evaluated from the **running**
  container (mounts, mounted bytes, loaded config, credential readability as
  uid 65534); a null operator config, an inline credential, a world-readable or
  unreadable credential, a dropped override, or a stale/malformed delivery
  record all fail closed; `go-check` needs the human delivery record.

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
(`--generated-by local-rehearsal`, accepted only with `--local`) with unsigned
fixture provenance (`nlw.ops.release_provenance fixture`; no GitHub trust claim);
proofs that the committed example is rejected, that a hand-written
`generated_by: ci` manifest passes schema validation but is not authority,
that an unattested manifest, a fixture outside `--local` and a manifest edited
after attestation are rejected, that a replaced manifest invalidates the
recorded state, that a manifest naming the old image fails
`verify-release`, that two forced backup failures (no evidence; broken
repository credential) leave roles / schema / active config / old runtime
untouched and `drain`/`prepare-roles`/`migrate` refused; then the real P2
backup into a MinIO **fixture** (accepted only with
`--local --allow-fixture-repository`; not DR evidence), the remaining phases,
`reopen` recording `alert delivery unverified`, `go-check` failing, the
invitation/four-eyes, worker, scheduler and rule-group proofs, a separate
downgrade proof, and cleanup of keys, manifests, volumes and the registry.

## Evidence to keep

`preflight` output, the manifest artifact name + sha256, the provenance
receipt, the rollout state file, `scripts/ops/verify-staging-deployment.sh` output after `reopen`, the
`go-check` result, and the attestation file (fingerprints only). Record
digests and the instance id, never credentials.
