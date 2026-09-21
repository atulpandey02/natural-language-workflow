# VPS provisioning & hardening (Stage 0 + Stage 1)

Operator runbook for the **real-VPS staging validation** phase. It brings a bare
Ubuntu 24.04 LTS host to a hardened baseline ready to run the production-shaped
Compose stack. It **does not deploy** the application — that is a later stage.

> Scope: **Stage 0** (host baseline) + **Stage 1** (host hardening) only.
> This is NOT M12. Do not create real secrets here. Do not run
> `docker-compose.e2e.yml` on a real VPS. Do not expose FastAPI publicly.

Conventions used below (replace with your values):

- `OPERATOR` — the non-root sudo account name (e.g. `nlwops`).
- `ADMIN_IP` — the fixed IP/CIDR you administer from (for restricting SSH).
- `STAGING_HOST` — the DNS name Caddy will serve (e.g. `staging.example.com`).
- Run commands as `root` only where shown; otherwise as `OPERATOR` with `sudo`.

Every hardening step is followed by a **Verify** block. Do not proceed until it
passes. Keep your current SSH session open until the final acceptance checklist.

---

## Stage 0 — Baseline

### 0.1 Record the host facts

Fill this table into the validation report (do not skip — capacity claims later
must reference this exact machine):

| Field | Value |
|---|---|
| Provider | _e.g. Hetzner / DigitalOcean / AWS Lightsail_ |
| Region | |
| Instance type | |
| vCPU | |
| RAM | |
| Disk (size + type) | |
| Public IPv4 | |
| Public IPv6 (global, if any) | _none / the address — see below_ |
| IPv6 policy | _use (validate + AAAA) / not-used (no AAAA)_ |
| OS | Ubuntu 24.04 LTS |
| Docker version | _filled in 1.4_ |
| Compose version | _filled in 1.4_ |

**Collect the facts:**

```bash
. /etc/os-release && echo "$PRETTY_NAME"     # must be Ubuntu 24.04 LTS
uname -srm
nproc                                         # vCPU
free -h                                        # RAM
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT             # disk
df -h /                                        # root filesystem
ip -4 addr show scope global | awk '/inet/{print $2}'   # public IPv4 (or provider console)
ip -6 addr show scope global                    # globally routable IPv6 (if any)
ip -6 route                                     # default v6 route => provider gives public v6
timedatectl                                    # clock + timezone (detail in 1.6)
```

**Verify:** `PRETTY_NAME` is `Ubuntu 24.04 LTS`. If not, stop — this runbook
targets 24.04 only.

**Decide the IPv6 policy now** and record it in the table: if `ip -6 addr show
scope global` shows a globally routable address AND `ip -6 route` has a default
route, the host has **public IPv6** → follow the "IPv6 enabled" branch in §1.3
and validate it externally in §1.13 before publishing any `AAAA`. Otherwise the
deployment is **IPv4-only** → document that, publish no `AAAA`, and still confirm
in §1.13 that no unintended public IPv6 listener exists. Do not validate only
IPv4 and assume IPv6 is covered.

### 0.2 Update the base system

```bash
sudo apt-get update && sudo apt-get -y dist-upgrade
sudo apt-get -y install ca-certificates curl gnupg ufw
sudo reboot     # only if a new kernel/libc was installed
```

**Verify:** after reboot, `apt list --upgradable` shows no held security
updates: `sudo apt-get -s upgrade | grep -i security || echo "no pending security upgrades"`.

---

## Stage 1 — Hardening

### 1.1 Non-root sudo operator account

Do NOT operate as `root`. Create a dedicated operator with key-only SSH.

```bash
# As root:
adduser --gecos "" OPERATOR            # set a strong password (console fallback only)
usermod -aG sudo OPERATOR
install -d -m 700 -o OPERATOR -g OPERATOR /home/OPERATOR/.ssh
# Install YOUR public key (paste the contents of your local ~/.ssh/id_ed25519.pub):
printf '%s\n' "ssh-ed25519 AAAA... you@laptop" \
  | install -m 600 -o OPERATOR -g OPERATOR /dev/stdin /home/OPERATOR/.ssh/authorized_keys
```

**Verify (from your laptop, in a NEW terminal — keep the root session open):**

```bash
ssh OPERATOR@STAGING_HOST 'id && sudo -n true && echo "sudo OK"'
```

You must land as `OPERATOR`, be in group `sudo`, and `sudo` must work. Do not
continue until this succeeds.

### 1.2 SSH hardening (key-only, no passwords, no root)

Use a drop-in so the base config stays intact. **Safety: keep one working
`OPERATOR` SSH session open the entire time; you will test a second one before
trusting the change.**

```bash
sudo tee /etc/ssh/sshd_config.d/10-nlw-hardening.conf >/dev/null <<'EOF'
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
EOF

sudo sshd -t                 # validate config; MUST print nothing (exit 0)
sudo systemctl reload ssh    # 'ssh' on 24.04 (socket-activated); reload, do not stop
```

**Verify the EFFECTIVE (merged) sshd config** — `-T` prints what sshd will
actually enforce, so a drop-in that failed to apply is caught:

```bash
sudo sshd -t                 # config valid (exit 0, no output)
sudo sshd -T | grep -Ei 'passwordauthentication|permitrootlogin|pubkeyauthentication'
```

Expected effective settings:

```
passwordauthentication no
permitrootlogin no
pubkeyauthentication yes
```

**Verify live logins (new terminals, do NOT close the existing session).** Keep
the original session open, reload ssh, and successfully establish a SECOND
key-authenticated session before closing the first:

```bash
ssh OPERATOR@STAGING_HOST 'echo ssh-key-login-ok'         # 2nd key session: must succeed
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    OPERATOR@STAGING_HOST 'true'                            # must be REJECTED
ssh root@STAGING_HOST 'true'                                # must be REJECTED
```

Only after the second key-authenticated session works and the rejections behave
as expected should you close the original session.

**Rollback / safety:** if a new login fails, do NOT log out of your open
session. Revert with `sudo rm /etc/ssh/sshd_config.d/10-nlw-hardening.conf &&
sudo systemctl reload ssh`, then retry. If fully locked out, use the provider's
web/serial console to fix the file. Only after the Verify block passes should you
consider the change trusted.

### 1.3 Firewall (ufw): public 80/443 + restricted SSH; everything else denied

Application service ports (web 3000, API 8000, Postgres 5432, Redis 6379, all
metrics ports) are **never published on a public interface** — only Caddy
publishes 80/443, and the staging overlay binds the API to `127.0.0.1:8000`
(loopback, unreachable off-host). ufw is defense-in-depth.

ufw applies each rule to **both** IPv4 and IPv6 when `IPV6=yes` in
`/etc/default/ufw` (the default on Ubuntu 24.04). Confirm that before enabling so
the policy below is not silently IPv4-only:

```bash
grep -E '^IPV6=' /etc/default/ufw     # must be IPV6=yes (edit + save if not)
```

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
# SSH: restrict to your admin IP if you have a fixed one …
sudo ufw allow from ADMIN_IP to any port 22 proto tcp
# … otherwise (dynamic IP) rate-limit instead of the line above:
# sudo ufw limit 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
```

**Verify (host-local — necessary but NOT sufficient):**

```bash
sudo ufw status verbose        # default deny incoming; only 22 (restricted), 80, 443
# No app port listens on a public interface (expect only sshd, and later caddy):
sudo ss -tlnp '( sport = :3000 or sport = :8000 or sport = :5432 or sport = :6379 or sport = :9100 )' \
  | awk 'NR==1 || ($4 !~ /127\.0\.0\.1|\[::1\]/)'  # any non-loopback (v4 OR v6) row is a problem
```

`ss` shows only what the host *believes* it is listening on; it does **not**
prove what the Internet can actually reach (a provider security group, a second
NIC, or an IPv6 path can differ). Firewall correctness is proven from a different
machine in **§1.13**, not from `ss` alone.

**IPv6 branch.** If §0.1 found **public IPv6**: the ufw rules above already cover
v6 (given `IPV6=yes`); confirm with `sudo ufw status verbose` (each rule appears
with a `(v6)` counterpart) and validate externally in §1.13. If the deployment is
**IPv4-only**: keep `IPV6=yes` so ufw still *denies* inbound v6 by default,
publish no `AAAA`, and confirm in §1.13 that nothing is reachable over v6.

**Rollback / safety:** enable ufw only after the `allow ... 22` rule exists (done
above). If you get locked out, use the provider console: `sudo ufw disable`.

### 1.4 Docker Engine + Compose plugin (official apt repo)

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get -y install docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
# Let the operator run docker without sudo:
sudo usermod -aG docker OPERATOR      # log out/in (or `newgrp docker`) to take effect
```

**Verify:**

```bash
docker --version                  # record in the Stage 0 table
docker compose version            # record in the Stage 0 table (v2 plugin)
docker run --rm hello-world       # pulls + runs; prints "Hello from Docker!"
systemctl is-enabled docker       # 'enabled' → starts on boot
```

### 1.5 Unattended security updates

Security updates are applied automatically, but the node must **never reboot
itself** — reboots are operator-controlled and validated later in the explicit
reboot drill. So: unattended security updates **ON**, automatic reboot **OFF**.

```bash
sudo apt-get -y install unattended-upgrades
sudo tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
# Explicitly DISABLE automatic reboot (own drop-in so a package update can't
# re-enable it). No scheduled reboot time either.
sudo tee /etc/apt/apt.conf.d/51nlw-no-auto-reboot >/dev/null <<'EOF'
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
EOF
sudo systemctl enable --now unattended-upgrades
```

**Verify (show the EFFECTIVE merged config):**

```bash
# Effective values across all apt.conf.d drop-ins — must both be "false":
apt-config dump 2>/dev/null | grep -iE 'Unattended-Upgrade::Automatic-Reboot(-WithUsers)?\s'
# Periodic unattended-upgrade is enabled (value "1"):
apt-config dump 2>/dev/null | grep -i 'APT::Periodic::Unattended-Upgrade '
sudo unattended-upgrades --dry-run --debug 2>&1 | grep -iE "Allowed origins|reboot|would" | head
systemctl is-active unattended-upgrades
```

Expected: `Unattended-Upgrade::Automatic-Reboot "false"`,
`...Automatic-Reboot-WithUsers "false"`, `APT::Periodic::Unattended-Upgrade "1"`,
and the dry-run reporting it would NOT reboot.

### 1.6 Time synchronization

Ubuntu 24.04 ships `systemd-timesyncd`.

```bash
sudo timedatectl set-ntp true
timedatectl show -p NTP -p NTPSynchronized
```

**Verify:** `NTP=yes` and `NTPSynchronized=yes`. (If you prefer chrony:
`sudo apt-get -y install chrony && chronyc tracking`.)

### 1.7 Backup client tooling

The backup path is `pg_dump` (custom format) → `gpg` (AES256) → off-host copy
(see `docker/scripts/backup.sh`, `docs/ops/backup-restore.md`). Install the
encryption tool plus your chosen off-host client:

```bash
sudo apt-get -y install gnupg
# Off-host destination — install ONE (matches OFFSITE_DEST in backup.sh):
sudo apt-get -y install rclone      # for rclone remotes, or:
# sudo apt-get -y install awscli    # for s3://... destinations
```

**Verify:** `gpg --version` and `rclone version` (or `aws --version`) print
versions. (Configuring the remote credentials happens in the later backup stage,
stored in root-owned, `chmod 600` config — never committed.)

### 1.8 Docker log rotation / disk controls

Cap container log growth so a chatty container can't fill the disk.

```bash
sudo tee /etc/docker/daemon.json >/dev/null <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "5" },
  "live-restore": true
}
EOF
sudo systemctl restart docker
```

**Verify:**

```bash
docker info --format '{{.LoggingDriver}}'                 # json-file
docker info --format '{{json .}}' | grep -o '"live-restore":true'   # live-restore on
python3 -c 'import json;json.load(open("/etc/docker/daemon.json"));print("daemon.json valid")'
```

> `live-restore` keeps containers running across a Docker daemon restart. A full
> host reboot is validated in a later stage.

### 1.9 Application directory + restrictive layout

Create an operator-owned tree. Secrets are `chmod 600`; nothing world-readable.

```bash
sudo install -d -m 750 -o OPERATOR -g OPERATOR /opt/nlw
install -d -m 750 /opt/nlw/app        # compose files + docker/ (from the repo)
install -d -m 700 /opt/nlw/backups    # local backup staging (pre off-host copy)
install -d -m 750 /opt/nlw/logs       # operational logs
```

**Exact layout:**

```
/opt/nlw/
├── app/
│   ├── docker-compose.prod.yml            # from the repo (checked out / copied)
│   ├── docker-compose.staging.yml         # from the repo
│   ├── docker/                            # postgres initdb, caddy, prometheus, scripts
│   ├── .env.prod                          # chmod 600, NEVER committed (created later)
│   └── docker/worker.secrets.env          # chmod 600, NEVER committed (if used)
├── backups/                               # chmod 700
└── logs/
```

Populate `app/` from the repo at the **exact approved deployment-config Git SHA**
(no build on the VPS). The VPS consumes more than container images — it also runs
`docker-compose.prod.yml`, `docker-compose.staging.yml`, the Caddyfile, the
`docker/` scripts, and the runbooks — so those files must be pinned to a known
revision, exactly as the images are pinned to digests. **Do not run an
unqualified `git pull` before deploying**; fetch and check out the specific SHA:

```bash
DEPLOYMENT_CONFIG_GIT_SHA=<approved-commit-sha>      # from the reviewed PR/main
git clone <repo> /opt/nlw/app        # first time; or: git -C /opt/nlw/app fetch --all
git -C /opt/nlw/app fetch origin
# REQUIRED: the tree must be clean BEFORE switching. If this prints anything,
# stop and investigate the unexpected tracked change — do NOT blindly
# `reset --hard` over it (that would discard drift you have not reviewed).
git -C /opt/nlw/app status --porcelain      # MUST be empty before checkout
git -C /opt/nlw/app checkout --detach "$DEPLOYMENT_CONFIG_GIT_SHA"
# (On an existing clean checkout, `git -C /opt/nlw/app reset --hard
#  "$DEPLOYMENT_CONFIG_GIT_SHA"` is equivalent — but only once the porcelain
#  check above is clean.)
# Confirm the pinned revision and a still-clean tree:
git -C /opt/nlw/app rev-parse HEAD
git -C /opt/nlw/app status --porcelain      # empty = no local drift
```

**Record three immutable references in the validation evidence** (the images by
GHCR digest, the config by Git SHA):

```
BACKEND_IMAGE_DIGEST     = ghcr.io/<owner>/nlw@sha256:...        # NLW_IMAGE in .env.prod
WEB_IMAGE_DIGEST         = ghcr.io/<owner>/nlw/web@sha256:...    # NLW_WEB_IMAGE in .env.prod
DEPLOYMENT_CONFIG_GIT_SHA= <git rev-parse HEAD of /opt/nlw/app>
```

`.env.prod` and `worker.secrets.env` are created in the later secrets stage from
`.env.prod.example`:

```bash
# (later stage — placeholders only here)
cp /opt/nlw/app/.env.prod.example /opt/nlw/app/.env.prod
chmod 600 /opt/nlw/app/.env.prod
chmod 600 /opt/nlw/app/docker/worker.secrets.env   # if using connector secrets
```

**Verify:**

```bash
ls -ld /opt/nlw /opt/nlw/app /opt/nlw/backups /opt/nlw/logs   # owner OPERATOR, perms 750/700
# Once created, secrets must be 600 and owned by OPERATOR:
# stat -c '%a %U %n' /opt/nlw/app/.env.prod
```

### 1.10 Canonical Compose invocation (real VPS)

Compose does **not** auto-load `.env.prod`. Every production/staging command must
pass it explicitly, and use **only** the prod + staging overlays (never e2e):

```bash
cd /opt/nlw/app
docker compose \
  --env-file .env.prod \
  -f docker-compose.prod.yml \
  -f docker-compose.staging.yml \
  <config|pull|--profile migration run --rm migrate|up -d|down|ps|logs>
```

The same `--env-file .env.prod` + `-f prod -f staging` prefix applies to
config, pull, migrations, up, down, drills, and restore operations.

**Verify (config only — safe, renders nothing to run yet; requires a filled
`.env.prod`, done in the later secrets stage):**

```bash
docker compose --env-file .env.prod \
  -f docker-compose.prod.yml -f docker-compose.staging.yml config >/dev/null \
  && echo "compose config OK"
```

### 1.11 Health & exposure model (reference)

- **Public** validation is the browser edge only:
  `https://STAGING_HOST/login` (proves DNS, TLS, Caddy, and Next.js).
- **API readiness** is checked **only from the VPS host** over the staging
  overlay's loopback seam:
  `curl -fsS http://127.0.0.1:8000/health/ready`.
- FastAPI `/health` and `/health/ready` are **never** exposed publicly; the only
  public service is Caddy (80/443). Do not add a public API route or reverse-proxy
  the API for health checks.

### 1.12 IPv6 exposure policy

IPv6 must be handled explicitly — never validate IPv4 and assume v6 is covered.
Follow the branch chosen in §0.1.

**If the host has public IPv6 (using it):**

- `IPV6=yes` in `/etc/default/ufw` (§1.3) so SSH / 80 / 443 policy applies to v6;
  confirm each rule shows a `(v6)` counterpart in `sudo ufw status verbose`.
- Do the external IPv6 exposure checks in §1.13 (v6 scan).
- Confirm application/internal ports are unreachable over v6 (§1.13).
- Publish the `AAAA` record **only after** those external checks pass.

**If the deployment is IPv4-only (not using IPv6):**

- Document the decision (§0.1 table) and publish **no `AAAA`** record.
- Keep `IPV6=yes` so ufw still denies inbound v6 by default.
- Verify there is no unintended public v6 listener or path — host-local first,
  then externally in §1.13:

```bash
# Host-local: nothing app/internal should listen on a GLOBAL v6 address
# (loopback ::1 is fine). Empty output = good.
sudo ss -6 -tlnp | awk 'NR>1 && $4 !~ /\[::1\]/ {print}'
```

### 1.13 External exposure verification (from a DIFFERENT host)

Host-local listening-state inspection (`ss`) shows only what the host thinks it
is serving; it is **not** proof of what the Internet can reach. A provider
security group, a second interface, or an IPv6 path can expose (or block) a port
regardless of local `ss`/ufw output. So verify the actual reachability from a
**different machine on a different network** (your laptop, a bastion, or a cloud
shell) — never conclude firewall correctness from `ss` alone.

From that other host (replace `VPS_IP` / `VPS_V6`):

```bash
# IPv4 — public edge + SSH policy + that app/internal ports are NOT reachable:
nmap -Pn -p 22,80,443,3000,8000,5432,6379,9100 VPS_IP

# IPv6 — ONLY if the host uses public IPv6 (§0.1 / §1.12):
nmap -6 -Pn -p 22,80,443,3000,8000,5432,6379,9100 VPS_V6
```

Expected results (same for v4 and, when applicable, v6):

| Port(s) | Expected from the Internet |
|---|---|
| 80, 443 | **reachable** — `open` after Caddy is deployed; `closed` (not `filtered`) at this stage, since ufw permits them but nothing listens yet |
| 22 | reachable **only** per your SSH policy — `open`/`closed` from `ADMIN_IP`; `filtered` from anywhere else if you restricted it |
| 3000, 8000, 5432, 6379, 9100 (metrics) | **NOT reachable** — must be `filtered` (ufw drops); never `open` |

If any of 3000/8000/5432/6379/9100 shows `open` (or `closed` rather than
`filtered`), stop and fix the firewall/provider security group before continuing.
Re-run this scan **after deployment** to confirm 80/443 are `open` and the
app/internal ports are still `filtered`. If a spot-check tool is unavailable,
substitute explicit per-port probes (e.g. `nc -vz -w3 VPS_IP 8000` must fail/time
out; `nc -vz -w3 VPS_IP 443` must connect once Caddy is up).

### 1.14 Docker published-port verification (after deployment)

`ufw` alone is **not proof of exposure**: Docker programs its own `iptables`
(the `DOCKER` chain) and can publish a container port straight to `0.0.0.0`,
bypassing ufw's `INPUT` rules. So a port bound to all interfaces by Docker can be
Internet-reachable even when `ufw status` looks correct. Verify the **actual
Docker bindings** in addition to ufw (§1.3), host `ss` (§1.3/§1.12), and the
external scan (§1.13) — all three are required, none alone is sufficient.

Once the stack is deployed (later stage), from the VPS host:

```bash
docker compose --env-file .env.prod \
  -f docker-compose.prod.yml -f docker-compose.staging.yml ps \
  --format 'table {{.Names}}\t{{.Ports}}'
# Or across all containers:
docker ps --format 'table {{.Names}}\t{{.Ports}}'
# Per-container binding detail (host IP:port -> container):
docker inspect <container> --format '{{json .NetworkSettings.Ports}}'
```

**Acceptance — every published host binding must be exactly:**

| Service | Required published binding |
|---|---|
| caddy | `0.0.0.0:80->80`, `0.0.0.0:443->443` (+ their `[::]` v6 forms) — the ONLY public bindings |
| api | `127.0.0.1:8000->8000` **only** (staging-overlay loopback seam); never `0.0.0.0` |
| web (`:3000`) | **no** host publish (internal network only) |
| postgres (`:5432`) | **no** host publish |
| redis (`:6379`) | **no** host publish |
| metrics (`:9100`, `9090`) | **no** host publish |

Any binding to `0.0.0.0` / `[::]` other than caddy's 80/443 — or an API binding
that is not `127.0.0.1` — is a defect: stop and fix the compose overlay/topology
before continuing. (`grep -E '0.0.0.0|\[::\]' ` over the `ps`/`inspect` output
must match caddy only.)

---

## Stage 1 acceptance checklist

All must be true before leaving Stage 1 (record evidence in the validation
report). Do this from a fresh terminal, then close your original root session.

- [ ] Host facts recorded (provider, region, vCPU, RAM, disk, public IP, Docker
      + Compose versions).
- [ ] `OPERATOR` is a non-root sudo account; SSH login works with your key.
- [ ] SSH: `sshd -t` clean and effective `sshd -T` shows
      `passwordauthentication no` / `permitrootlogin no` /
      `pubkeyauthentication yes`; a SECOND key session works before the first is
      closed; password + root logins **rejected**.
- [ ] ufw: `default deny incoming`; only 22 (restricted/limited), 80, 443 open;
      `/etc/default/ufw` has `IPV6=yes` and each rule shows a `(v6)` counterpart.
- [ ] Host-local check: no app port (3000/8000/5432/6379/9100) listens on a
      non-loopback v4 **or** v6 address (`ss` / `ss -6`; sshd/caddy excepted).
- [ ] **External scan from a different host** (§1.13): 80/443 permitted, 22 per
      policy, and 3000/8000/5432/6379/9100 **filtered/not reachable** — over IPv4
      and, if applicable, IPv6.
- [ ] **Docker published-port check** (§1.14, after deployment): only caddy
      publishes 80/443; API is `127.0.0.1:8000` only; web/postgres/redis/metrics
      have no host publish (ufw alone is not proof — Docker bindings verified).
- [ ] IPv6 policy decided and applied (§0.1/§1.12): if used, v6 firewall + external
      checks pass and `AAAA` is published only after; if not used, no `AAAA` and no
      unintended public v6 listener.
- [ ] Docker Engine + Compose v2 installed, `docker` runs without sudo, Docker
      `enabled` on boot.
- [ ] Unattended security upgrades **ON** and automatic reboot **OFF**
      (`apt-config dump` shows `Automatic-Reboot "false"` +
      `APT::Periodic::Unattended-Upgrade "1"`); time sync `NTP=yes` /
      `NTPSynchronized=yes`.
- [ ] Backup tooling (`gpg` + off-host client, once the provider is chosen)
      installed.
- [ ] Docker `json-file` logging with `max-size`/`max-file`; `daemon.json` valid.
- [ ] `/opt/nlw` layout created, operator-owned, secrets slots `chmod 600`
      (values created in a later stage — NOT now).
- [ ] `app/` checked out at the approved `DEPLOYMENT_CONFIG_GIT_SHA` —
      `git status --porcelain` was empty **before** the checkout (no blind
      `reset --hard` over drift), no `git pull` before deploy; backend digest, web
      digest, and config Git SHA recorded in the evidence.
- [ ] Canonical `docker compose --env-file .env.prod -f prod -f staging` pattern
      documented and (once `.env.prod` exists) `config` renders clean.
- [ ] `docker-compose.e2e.yml` is NOT used on this host; FastAPI is not public.

When every box is checked, Stage 1 is complete. Next stages (image delivery,
real Supabase, secrets/`.env.prod`, DB bring-up, TLS, E2E, drills, DR, load) are
covered by `docs/staging/real-vps-checklist.md`.
