# Runbook — Staging signed-context rollout (M12A: schema 0010 → 0016)

Applies to: the staging/pilot VPS currently running the M11 release (commit
`5151a2c`, Alembic `0010_readiness_schema_grant`) being upgraded to the current
`main` release (Alembic `0016_signed_database_context`, ADR-024). The operator
tool is `python -m nlw.ops.rollout`; the reviewed Compose deployment
(`docker-compose.prod.yml` + `docker-compose.staging.yml`) is what it drives.

**The default invocation is read-only.** Nothing mutates the host until the
operator passes the exact authorization phrase, and even then each phase
re-verifies the target instance, the immutable release pins, the current
migration revision and every earlier gate recorded on that host.

## Identity model

| what | where | why |
|---|---|---|
| EC2 **instance id** (authoritative) | `deploy/staging/target.env` and `deploy/staging/release.json` | compared with IMDSv2 on the connected host; mismatch = stop |
| SSH address / user | `deploy/staging/target.env` (`NLW_STAGING_SSH_HOST`; override with `SSH_HOST`) | the public IPv4 is auto-assigned and can change after STOP+START; it is only how SSH reaches the box |
| Release SHA, backend/web image **digests**, expected current + target revisions, key ids | `deploy/staging/release.json` | mutable tags are never deployment authority |
| Compose project | `target.env` / `release.json` (`app`) | leftover-container and state-file scoping |

Every Mac-side ops script sources `scripts/ops/lib/staging-target.sh`; none
hard-codes an address. The bootstrap-era address is kept only in historical
evidence under `docs/staging/`.

## Phases

```
uv run python -m nlw.ops.rollout                 # == preflight (READ-ONLY)
uv run python -m nlw.ops.rollout prepare-keys          --authorize <phrase>
uv run python -m nlw.ops.rollout verify-escrow         --authorize <phrase> --escrow-confirm <phrase> --attestation FILE
uv run python -m nlw.ops.rollout pin-release           --authorize <phrase>
uv run python -m nlw.ops.rollout prepare-roles         --authorize <phrase>
uv run python -m nlw.ops.rollout verify-backup         --authorize <phrase>
uv run python -m nlw.ops.rollout drain                 --authorize <phrase>
uv run python -m nlw.ops.rollout migrate               --authorize <phrase>
uv run python -m nlw.ops.rollout install-context-keys  --authorize <phrase>
uv run python -m nlw.ops.rollout recreate-runtime      --authorize <phrase>
uv run python -m nlw.ops.rollout validate              --authorize <phrase>
uv run python -m nlw.ops.rollout reopen                --authorize <phrase>
```

| phase | mutates | gates re-checked | what it does |
|---|---|---|---|
| `preflight` | no | instance id + region; hostname ↔ public IPv4; `.env.prod` hostname; roles model (M11 set acceptable); drain counters; current revision = expected | prints a sanitized report; run it as often as you like |
| `prepare-roles` | DB roles | authorization; identity; pin done (the `migrate` service and `nlw.ops.roles` exist only in the release) | `python -m nlw.ops.roles ensure` via the `migrate` service: creates `nlw_membership_admin` (NOLOGIN, BYPASSRLS) and `nlw_ctx_verifier` (NOLOGIN, NOBYPASSRLS) if absent, verifies every nlw role's attributes and memberships, fails on any incompatible role; grants nothing on tables |
| `prepare-keys` | host files | authorization; identity | generates three independent 32-byte keys **on the host** through the release image running as root (`nlw.ctxkeys prepare`): dir `0700` root, files `0400` uid 10001, never overwrites, prints fingerprints only |
| `verify-escrow` | state only | authorization; **escrow phrase**; attestation fingerprints == host fingerprints; release SHA/env; ≤ 30 days old | the operator must have escrowed the files first — see the escrow section of [signed-context-keys](signed-context-keys.md) |
| `pin-release` | app checkout, `.env.prod` | authorization; identity; escrow done | `git checkout --detach <release_sha>` in the app dir (must be clean; the reviewed Compose files/Caddyfile travel with the code), writes the release digests + `NLW_CTX_KEYS_DIR` + key ids into `.env.prod` (backup copy kept), builds the backup image from the pinned digest. Running containers are untouched — pins only apply on recreate |
| `verify-backup` | state only | authorization; escrow + pin done; checkout = release | runs `nlw.backup evidence` (backup profile, both env files) and evaluates: real `s3:https://` off-host repository (MinIO/loopback/private/same-host refused), `nlw_backup_success=1`, `repository_verify_success=1`, verified within 26 h, newest `nlw-db` snapshot tagged `rev-<expected current revision>`, no key-like artifacts |
| `drain` | runtime | authorization; escrow + pin + backup done; identity; checkout + pins; revision | recreate **caddy only** on the release config (`--no-deps --force-recreate`, brief edge blip) so the maintenance matcher exists; Caddy maintenance 503 (`caddy_maint` flag, no reload); stop scheduler; wait ≤ 120 s for non-terminal runs / queue to reach zero (never force-retries ambiguous work); stop worker + api; require zero runtime DB sessions |
| `migrate` | DB | roles/escrow/pin/backup/drain done; identity; checkout + pins; no sessions; revision = expected; roles complete | pulls the digests, runs the `migrate` service (0011–0016), verifies revision = target, 51 policies, 0 legacy-GUC policies, registry owner/grants |
| `install-context-keys` | DB registry | migrate done; no sessions; revision = target | `nlw.ctxkeys install` ×3 from mounted files (throwaway `migrate` container, removed after), `ctxkeys check` ×3, ≥ 3 active keys, audit contains no material |
| `recreate-runtime` | containers | install done; revision; pins | `config` render, `up -d --force-recreate --no-deps api worker scheduler web`, verifies each runtime runs the release digest and mounts **only its own** key read-only; web/postgres/redis/caddy/prometheus mount none; no key-like env values; no leftover migrate/installer containers |
| `validate` | none | recreate done | `/health/ready` → `signed_context: ok`; policy cutover; mount isolation; **unsigned forgery as the real `nlw_app` sees no rows**; worker/scheduler healthy. Then run `nlw.ops.rollout.smoke` inside the api container with synthetic ids for the invitation / four-eyes checks |
| `reopen` | Caddy flag | validate done; readiness re-checked | removes the maintenance flag |

Rollout state (`<remote_app>/.rollout/<release_sha>.json`) records completion
times and non-secret evidence (snapshot id, fingerprints, digests, counts). It
never contains phrases, credentials or key material, and the writer refuses
anything that looks like one.

## What cannot happen

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
  pre-deployment backup is the only true rollback.

## Human phrases (documented; never pre-filled)

* `AUTHORIZE_M12A_SIGNED_CONTEXT_STAGING_DEPLOYMENT` — passed as `--authorize`
  to every mutating phase. It authorizes **this host and this release** only.
* `SIGNED_CONTEXT_KEYS_ESCROWED_AND_RECOVERY_TESTED` — passed as
  `--escrow-confirm` to `verify-escrow`, together with the attestation file.

**Neither phrase is a substitute for backup-provider configuration.** The
`verify-backup` gate needs a real, verified, off-host backup and stops without
one regardless of what the operator types.

## Rehearsal

`scripts/ops/rehearse-0010-to-0016.sh` runs the identical phases against a
disposable local stack (M11 image + 5-role bootstrap → 0010 → old runtimes →
backup into a MinIO **fixture** → all phases → invitation/four-eyes, worker,
scheduler, Prometheus rule groups → separate downgrade proof → cleanup). The
fixture repository is accepted only with `--local --allow-fixture-repository`;
it is not DR evidence.

## Evidence to keep

`preflight` output, the rollout state file, `scripts/ops/verify-staging-deployment.sh`
output after `reopen`, and the attestation file (fingerprints only). Record
digests and the instance id, never credentials.
