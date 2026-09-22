# Off-host backup providers (S3-compatible)

The backup engine (restic) talks to any **S3-compatible** object store. The
platform is provider-neutral: only a handful of environment variables change
between providers. This guide covers **AWS S3** and **Backblaze B2**. MinIO is used
only as a disposable **drill fixture** (see `scripts/ops/dr-drill.sh`) — it is
**not** a production off-host provider.

> Secrets below are placeholders. Put real values in the host's secret store /
> `.env.backup` (mode `0600`, never committed). See `.env.backup.example`.

## What "off-host" and "durable" require

A backup on the same VPS/disk as the database is not disaster recovery. The
provider MUST be a **different failure domain** from the VPS (different account,
region, and ideally vendor). Durability claims come from the provider's own SLA,
not from this platform.

## AWS S3

1. Create a bucket in a region **different** from the VPS (e.g. VPS in `eu-central-1`
   → bucket in `eu-west-1`). Block all public access. Enable **default SSE**
   (SSE-S3 or SSE-KMS) — restic also encrypts client-side, so data is doubly
   protected.
2. Create a **dedicated IAM user** (backup-only) with a least-privilege policy
   scoped to that bucket:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       { "Effect": "Allow",
         "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
         "Resource": "arn:aws:s3:::YOUR-BUCKET" },
       { "Effect": "Allow",
         "Action": ["s3:PutObject", "s3:GetObject"],
         "Resource": "arn:aws:s3:::YOUR-BUCKET/nlw/*" }
     ]
   }
   ```
   Note: the write path intentionally has **no `s3:DeleteObject`** — see
   ransomware resistance below.
3. Environment:
   ```
   RESTIC_REPOSITORY=s3:https://s3.eu-west-1.amazonaws.com/YOUR-BUCKET/nlw
   BACKUP_AWS_ACCESS_KEY_ID=AKIA...
   BACKUP_AWS_SECRET_ACCESS_KEY=...
   BACKUP_AWS_REGION=eu-west-1
   RESTIC_PASSWORD=<the repository encryption passphrase — store separately>
   ```

## Backblaze B2 (S3-compatible endpoint)

1. Create a **private** bucket. Note its endpoint region (e.g. `s3.us-west-004.backblazeb2.com`).
2. Create an **application key** restricted to that single bucket (read + write).
3. Environment (B2 encodes the region in the URL; `BACKUP_AWS_REGION` may be omitted):
   ```
   RESTIC_REPOSITORY=s3:https://s3.us-west-004.backblazeb2.com/YOUR-BUCKET/nlw
   BACKUP_AWS_ACCESS_KEY_ID=<keyID>
   BACKUP_AWS_SECRET_ACCESS_KEY=<applicationKey>
   RESTIC_PASSWORD=<the repository encryption passphrase — store separately>
   ```

## Initialize the repository (one time)

The backup job auto-initializes the repo on first run (`restic init` via
`ensure_repository`). To do it explicitly:
```bash
docker compose -f docker-compose.prod.yml --profile backup run --rm \
  --entrypoint restic backup init
```

## The `RESTIC_PASSWORD` (repository encryption key)

- This is the key that decrypts **every** backup. **Losing it makes all backups
  unrecoverable.** Store it **separately** from the object-store credentials
  (different secret, ideally different system), and record it in your break-glass
  procedure. Do **not** store it only on the VPS being backed up.
- It is independent of the object-store keys: rotating S3 keys does not require
  re-encrypting the repo; changing the repo password uses `restic key`.

## Retention modes (pick one, explicitly)

Retention (`restic forget --prune`, which **deletes**) and a non-delete
backup-writer credential are different operational modes. A non-delete writer
cannot prune; giving the VPS delete-capable repo credentials weakens
compromise resistance. Choose one with `NLW_BACKUP_RETENTION_MODE`:

### Mode 1 — Simple pilot (`NLW_BACKUP_RETENTION_MODE=simple`, default)

- The VPS backup job has permissions for both `backup` and retention.
- `restic forget --prune` runs automatically after each **verified** backup, using
  `NLW_BACKUP_RETENTION_DAILY/WEEKLY/MONTHLY` (defaults 14/8/6).
- **Versioning is recommended** at the provider.
- This mode does **not** claim protection from a fully compromised VPS deleting
  backups (the writer can delete).

### Mode 2 — Immutable / append-only (`NLW_BACKUP_RETENTION_MODE=immutable`)

- The VPS backup credential can `PutObject`/`GetObject` but **cannot** delete or
  overwrite protected objects.
- The ordinary backup job **never** prunes (it logs `backup.retention_delegated`);
  selecting immutable mode **and** forcing a local prune
  (`NLW_BACKUP_FORCE_LOCAL_PRUNE=true`) is a contradiction and **fails closed**.
- Retention is a **separate, human-gated** admin process run from a trusted host
  (not the VPS) with delete-capable credentials **not stored on the VPS**, and only
  after the object-lock retention window allows deletion:
  ```bash
  # off-VPS, with a delete-capable key, explicit confirmation required:
  NLW_BACKUP_ALLOW_PRUNE=1 RESTIC_REPOSITORY=... RESTIC_PASSWORD=... \
    AWS_ACCESS_KEY_ID=<prune-key> AWS_SECRET_ACCESS_KEY=<prune-secret> \
    python -m nlw.backup prune
  ```
- **restic + object-lock implications:** restic prune deletes/repacks pack and
  index objects. Under object-lock, locked objects cannot be pruned until their
  window expires, so the repo grows within the window — size the bucket for it.
  Provider **lifecycle rules must not** delete arbitrary restic pack/index objects
  (that corrupts the repo); use object-lock retention windows, not blanket
  age-based expiry, and never expire objects the newest snapshots still reference.

## Ransomware / deletion resistance (must be explicitly configured)

Client-side encryption protects **confidentiality**, not availability. To resist
an attacker (or a compromised VPS) **deleting** your backups, configure at the
provider — these are operator gates, not defaults, and until they are in place do
**not** claim ransomware resistance:

- **Object Lock / immutability** in *compliance* mode with a retention window
  ≥ your longest retention (AWS S3 Object Lock; B2 Object Lock). This makes
  objects append-only for the window even to the account owner.
- **Versioning** so overwrites/deletes are recoverable.
- **Isolated write credentials**: the backup key can `PutObject`/`GetObject` but
  **not** `DeleteObject`; pruning (which deletes) uses a **separate**,
  human-gated credential run from a trusted host — never the automated timer's
  key. (Trade-off: with immutability, `forget --prune` cannot reclaim space
  inside the lock window; size the bucket accordingly.)
- **MFA-delete** / provider account MFA and separate account from the VPS host.

## Verifying a provider before go-live

Run the disposable drill against MinIO to prove the *mechanism*
(`scripts/ops/dr-drill.sh`), then do a **real** provider dry run following
`docs/runbooks/dr-real-vps-checklist.md` (human-gated). A provider is not
"working" until a restore from it has been verified — see
`docs/runbooks/dr-fresh-host-restore.md`.
