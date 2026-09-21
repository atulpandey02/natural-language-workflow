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
   AWS_ACCESS_KEY_ID=AKIA...
   AWS_SECRET_ACCESS_KEY=...
   AWS_DEFAULT_REGION=eu-west-1
   RESTIC_PASSWORD=<the repository encryption passphrase — store separately>
   ```

## Backblaze B2 (S3-compatible endpoint)

1. Create a **private** bucket. Note its endpoint region (e.g. `s3.us-west-004.backblazeb2.com`).
2. Create an **application key** restricted to that single bucket (read + write).
3. Environment (B2 encodes the region in the URL; `AWS_DEFAULT_REGION` may be omitted):
   ```
   RESTIC_REPOSITORY=s3:https://s3.us-west-004.backblazeb2.com/YOUR-BUCKET/nlw
   AWS_ACCESS_KEY_ID=<keyID>
   AWS_SECRET_ACCESS_KEY=<applicationKey>
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
