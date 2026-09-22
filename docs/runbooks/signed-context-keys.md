# Runbook — Signed database context keys (M11.5 P3B)

Applies to: PostgreSQL row-level security authorization after migration
`0016_signed_database_context` (ADR-024).

## What this is

Every tenant-aware database transaction carries a **signed, purpose-bound,
expiring context** (`app.ctx_*`, transaction-local). PostgreSQL recomputes the
HMAC-SHA256 tag inside `app_ctx_claims()` and RLS trusts **only** verified
claims. Bare `app.user_id` / `app.tenant_id` settings grant nothing.

Three runtime classes, three keys, three login roles:

| class       | signer purpose(s)                 | DB login role   | key file (in container)      |
|-------------|-----------------------------------|-----------------|------------------------------|
| `api`       | `api_identity`, `api_request`     | `nlw_app`       | `/run/nlw/keys/api.key`      |
| `worker`    | `worker_execution`                | `nlw_worker`    | `/run/nlw/keys/worker.key`   |
| `scheduler` | `scheduler_reconcile`             | `nlw_scheduler` | `/run/nlw/keys/scheduler.key`|

**Be precise about what the key is.** HMAC is symmetric: the material in the
`ctx_keys` registry is *signing-capable*. "Verify-only" describes the exposed
`app_ctx_claims()` interface (it returns claims or NULL, never material, never a
tag over caller data) — not the nature of the key. The registry is owned by the
NOLOGIN `nlw_ctx_verifier` role and **no login role has any privilege on it**.

Protected: SQL injection or possession of a runtime DB credential *without* the
matching key file. **Not** protected (non-goals): a runtime process compromised
together with its key, the installer/owner credential, the bypass roles, the
superuser, host root, or malicious code already inside a trusted runtime.

## Deployment order (security sensitive — follow exactly)

1. **Provision the verifier role** on the database (fresh volumes: `00-roles.sh`;
   existing databases: `CREATE ROLE nlw_ctx_verifier NOLOGIN NOSUPERUSER
   NOBYPASSRLS ...; GRANT nlw_ctx_verifier TO nlw;`).
2. **Generate key files** on the host (never commit, never paste into env):
   ```bash
   mkdir -p /srv/nlw/ctx-keys && chmod 700 /srv/nlw/ctx-keys
   for c in api worker scheduler; do
     (umask 077; openssl rand -hex 32 > /srv/nlw/ctx-keys/$c.key)
     chown 10001:10001 /srv/nlw/ctx-keys/$c.key && chmod 400 /srv/nlw/ctx-keys/$c.key
   done
   ```
   Put `NLW_CTX_KEYS_DIR` and the three `NLW_CTX_*_KEY_ID` values in `.env.prod`.
3. **Stop the runtimes** (`api`, `worker`, `scheduler`). Pre-P3B runtimes set
   unsigned context; after the migration they would fail closed anyway.
4. **Apply the migration** (`--profile migration run --rm migrate`). Until keys
   are installed **every tenant query is denied** — there is no unsigned fallback.
5. **Install the keys** with the owner credential (migration profile image), one
   per class, reading secrets from the mounted files:
   ```bash
   docker compose --env-file .env.prod -f docker-compose.prod.yml --profile migration \
     run --rm -v /srv/nlw/ctx-keys:/run/nlw/keys:ro migrate \
     python -m nlw.ctxkeys install --class api       --key-id "$NLW_CTX_API_KEY_ID"       --secret-file /run/nlw/keys/api.key
   # ... --class worker ... worker.key ; --class scheduler ... scheduler.key
   ```
   `install` is idempotent by key id; a different class or material for an
   existing id **fails** (exit 3) rather than replacing it.
6. **Verify without exposing material**: `python -m nlw.ctxkeys list` (ids,
   class, status, fingerprint only) and `python -m nlw.ctxkeys check --class ...`.
7. **Start the runtimes** with their key files mounted. Readiness now includes a
   signed-context self-check: the API's `/health/ready` reports
   `signed_context: down` and the worker/scheduler healthchecks fail if the key a
   process holds is not the key the database verifies with.

## Production/staging key preparation and off-host escrow (M12A)

Generate keys with the reviewed file-only command — never the dev helper, never
`openssl` into a world-readable path:

```bash
# On the host, via the release image as root (bind-mounts the parent dir).
# The rollout does exactly this in its `prepare-keys` phase.
docker run --rm --user 0:0 --network none -v /srv/nlw:/host/srv/nlw <backend digest> \
  python -m nlw.ctxkeys prepare --dir /host/srv/nlw/ctx-keys --class api --owner 10001:10001
# repeat for worker and scheduler -> prints "prepared <class> <sha256 fingerprint>" only
```

Rules enforced by `prepare` / `fingerprint` / `verify-files`: directory `0700`
root-owned, files `0400` owned by uid 10001, regular files only (symlinks and
directories rejected), ≥ 32 random bytes as hex, never overwrite existing
material, key ids validated (`[a-z0-9][a-z0-9._-]{2,63}`) and kept separate from
material. Nothing prints material: not stdout, stderr, argv, env, logs or the
rollout state.

### Escrow (mandatory before migration 0016)

The rollout will not migrate until an **operator-written attestation** proves
the three files are in an encrypted **off-host** escrow — separate from the VPS,
from the restic backup repository, from git, and from deployment artifacts.
The tooling never chooses the destination. Procedure:

1. Copy the three files **without printing them** to a machine you control,
   preserving names and the id→purpose mapping:
   `sudo tar -C /srv/nlw -cf - ctx-keys | ssh you@escrow-host 'cat > ctx-keys.tar'`
   (or `sudo tar … | gpg --symmetric --cipher-algo AES256 > ctx-keys.tar.gpg`
   directly on the host and copy the encrypted archive).
2. Encrypt at rest with a key/passphrase held by the recovery owners, e.g.
   `gpg --symmetric --cipher-algo AES256 ctx-keys.tar` or `age -p`; restrict the
   escrow object/folder to the recovery owners.
3. Verify the encrypted archive is readable: decrypt into a private temp dir
   (`umask 077; mkdir -p /tmp/kt && gpg -d ctx-keys.tar.gpg | tar -C /tmp/kt -xf -`).
4. Verify by **fingerprint**, never by displaying contents:
   `python -m nlw.ctxkeys fingerprint --dir /tmp/kt/ctx-keys --key-id-api … --key-id-worker … --key-id-scheduler … --insecure-permissions`
   must print the same three sha256 values `prepare` printed on the host.
5. Shred the temporary plaintext copies (`shred -u` / `rm -P` / a tmpfs) and the
   unencrypted tar; keep only the encrypted archive.
6. Record recovery ownership: who holds the passphrase, who may fetch the
   archive, and the recovery steps (restore the files to `/srv/nlw/ctx-keys`
   with the same owner/modes, `ctxkeys verify-files`, `ctxkeys check` ×3).
7. Write the attestation (fingerprints only) and run
   `python -m nlw.ops.rollout verify-escrow --escrow-confirm SIGNED_CONTEXT_KEYS_ESCROWED_AND_RECOVERY_TESTED --attestation FILE`.

Attestation format (`format_version` 1; **contains no material or credential**):

```json
{
  "format_version": 1,
  "environment": "staging",
  "release_sha": "<40-hex git sha>",
  "keys": [
    {"purpose_class": "api",       "key_id": "<id>", "sha256_fingerprint": "<64 hex>"},
    {"purpose_class": "worker",    "key_id": "<id>", "sha256_fingerprint": "<64 hex>"},
    {"purpose_class": "scheduler", "key_id": "<id>", "sha256_fingerprint": "<64 hex>"}
  ],
  "escrow_verified_at": "2026-09-22T11:00:00Z",
  "operator": "<name or handle>",
  "recovery_test_confirmed": true,
  "escrow_location_label": "<non-secret label, not a URL with credentials>"
}
```

The gate compares every fingerprint with the files on the host, requires the
same key ids as the CI-generated release manifest, and rejects attestations older
than 30 days, from another release/environment, or containing anything that
looks like a credential. Pasting material into the fingerprint field cannot
pass (sha256(material) ≠ material). Key preparation never writes this file —
that would make the gate meaningless. Backups must **exclude** the key files
(the restore validator and the backup gate both check); the registry rows are
restored with the database, but a restored registry cannot recreate a missing
key file — only escrow can.

## Rotation (overlap) and revocation

- Install the NEW key under a new id (`--activate-at` optional). Both keys verify
  during the overlap.
- Point the runtime at the new id/file (`NLW_CTX_*_KEY_ID`, file contents) and
  restart it. Contexts are short-lived (≤ 120 s by default, hard cap 600 s), so
  old contexts expire on their own.
- Retire the old key: `python -m nlw.ctxkeys revoke --key-id OLD --retire-at
  <iso>` (scheduled) or `revoke --key-id OLD` (immediate).
- **Emergency revocation** (suspected key disclosure): `revoke --key-id ID` at
  once. Every context signed with it fails immediately (fail closed); the affected
  runtime must be restarted with a freshly installed key. Expect a short outage of
  that runtime class — that is the intended blast-radius boundary.
- Every install/activate/retire/revoke is appended to `ctx_key_events`
  (id, class, event, actor, time) — never material. Runtime roles cannot read it.

Unknown, revoked, retired or wrong-class keys, wrong login role, wrong purpose,
expired / future-issued / over-long contexts, and any tampered field all verify to
NULL. Runtime roles cannot read or mutate the registry and have no signing oracle.

## Rollback (security sensitive)

Downgrading below `0016` **re-installs the legacy unsigned-GUC policies and
re-opens context forgery**. Never downgrade a live customer environment without
explicit security review; prefer fix-forward. Runtime and database versions must
match: P3B runtimes against a downgraded database fail **closed** (they set no
legacy settings); pre-P3B runtimes against a 0016 database also fail closed
(unsigned context verifies to nothing). A mismatch is an outage, never an open
door.

## Local / test provisioning

`scripts/ops/ctx-keys-dev.sh` generates git-ignored dev keys under
`docker/ctx-keys/` and installs them via the same installer. Run it with
`--generate-only` **before** the first `docker compose run api …` (the migration)
and again without flags after the migration to install: on Linux hosts Docker
auto-creates a missing bind-mount source as a root-owned directory, which would
break key provisioning. Dev key files are deliberately `0644` (container uid
10001 must read them; the local runtime does not enforce strict key-file
permissions — staging/production do). The integration test fixture installs
fresh random keys per test database. **None of these are production keys.**
Never reuse a test key outside its throwaway database.
