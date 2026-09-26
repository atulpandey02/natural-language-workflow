# Alerting (Prometheus rules + Alertmanager) — staging/pilot

## What is wired now (M12A-Prep)

* **Prometheus** (`docker-compose.staging.yml`) runs as `nobody`, mounts
  `docker/prometheus/prometheus.yml` and the whole `docker/prometheus/alerts/`
  directory read-only, and loads two rule groups:
  * `nlw-backup` (`alerts/backup.rules.yml`, ADR-022) — dead-man + failure alerts
    fed by the backup job's textfile metrics;
  * `nlw-signed-context` (`alerts/signed-context.rules.yml`, ADR-024) —
    **sustained** signed-context self-check failures and a missing signer.

  Every referenced rule file must exist in that directory: a unit test checks
  the references and `promtool check config` runs against the exact mounts.
* **Alertmanager** (`prom/alertmanager`, internal network only, no published
  port, state on `alertmanager_data`) receives every firing alert from
  Prometheus (`alerting:` block in `prometheus.yml`). Its config
  (`docker/alertmanager/alertmanager.yml`) routes everything to a **null
  receiver**: grouping, repeat intervals and inhibition are real; **delivery is
  not**. `amtool check-config` validates it.

Labels on every rule are bounded (`severity`, `component`, plus the scrape
`role`); no user, tenant, run, nonce, signature or key id ever becomes a label.

## What is deliberately NOT decided here

Which channel receives infrastructure alerts — e-mail, PagerDuty, an ops Slack
webhook, … — is an operator decision that needs a credential. This package is
provider-neutral: it does **not** invent a receiver, commit a credential, or
touch the deferred **product** Slack connector (a separate feature, tested last).

### Wiring a real receiver — operator authority (staging/production)

The receiver configuration is **operator authority on the host, outside every
release checkout**, named in `deploy/staging/target.env`
(`NLW_STAGING_ALERTMANAGER_CONFIG`, `NLW_STAGING_ALERTMANAGER_SECRETS_DIR`,
`NLW_STAGING_COMPOSE_OVERRIDE` — all three required; `preflight` and every
Alertmanager (re)creation fail closed without them). The committed
`docker/alertmanager/alertmanager.yml` (null receiver) is never consulted for
staging/production.

**Alertmanager runs as uid 65534 (`nobody`).** A `root:root 0600` credential
inside a `root:root 0700` directory is unreadable to it — reproduced on the
pilot host and in `scripts/ops/rehearse-0010-to-0016.sh` with real Linux
permission semantics. The working least-privilege layout (nothing
world-readable, no credential inline):

| host path | owner | mode | why |
|---|---|---|---|
| `/opt/nlw/alertmanager/alertmanager.yml` | `root:root` | `0644` | non-secret config; readable by the rollout user for validation, writable by root only |
| `/opt/nlw/alertmanager.secrets/` | `root:65534` | `0750` | uid 65534 traverses it through the group; others get nothing |
| `/opt/nlw/alertmanager.secrets/<name>` | `root:65534` | `0640` | one credential per file, group-readable by 65534, never world-readable |
| `/opt/nlw/docker-compose.operator.yml` | `root:root` | `0644` | the reviewed override (`deploy/staging/docker-compose.operator.example.yml`) |
| `/opt/nlw/rollout/` | `nlwops:nlwops` | `0700` | rollout state — **never chown/chmod'ed** when the record below is written |
| `/opt/nlw/rollout/alert-delivery.json` | `root:nlwops` | `0640` | the human delivery record, readable by the rollout user |

Steps (root on the host):

1. Copy `deploy/staging/alertmanager.operator.example.yml` to
   `/opt/nlw/alertmanager/alertmanager.yml` and set the default route (and the
   `severity = critical` route) to the real receiver; every credential is a
   `*_file` reference under `/etc/alertmanager/secrets/` (`api_url_file`,
   `routing_key_file`, `auth_password_file`, …) — inline values are refused.
2. Put each credential in `/opt/nlw/alertmanager.secrets/<name>` with the
   ownership/mode above (`install -d -o root -g 65534 -m 0750 …`,
   `install -o root -g 65534 -m 0640 …`).
3. Copy `deploy/staging/docker-compose.operator.example.yml` to
   `/opt/nlw/docker-compose.operator.yml`. It may only add the two
   `alertmanager` volumes; anything else is refused.
4. `python -m nlw.ops.rollout preflight` (read-only) proves the files, the
   permissions, the override and — via a throwaway container running as uid
   65534 — that every credential is readable by Alertmanager, before anything
   is recreated. `recreate-runtime`, `validate`, `reopen` and `go-check` then
   evaluate the **running** container (see below).
5. Send a **controlled test alert** (`amtool alert add
   --alertmanager.url=http://alertmanager:9093 test severity=warning` from the
   internal network) and **watch it arrive** in the real channel.
6. Record what you saw — the rollout never writes this file itself:
   ```bash
   sudo scripts/ops/record-alert-delivery.sh --receiver <name> --confirmed-by "<operator>"
   ```
   writes `/opt/nlw/rollout/alert-delivery.json` as `root:nlwops 0640`
   (`{"receiver", "delivered_at" (ISO-8601 with timezone), "confirmed_by"}`)
   without touching the rollout directory. The record counts for 7 days and
   only for the receiver that is the default route.

Until this is done, "alert delivery" is an **open launch gate** in the M12
checklist — never report it as complete because the null pipeline is healthy.

### What "effective configuration" means

`validate`, `reopen` and `go-check` do **not** read a file in a checkout. They
prove, in this order, all of which fail closed:

1. the operator files exist, parse, route to a real receiver, reference only
   `*_file` credentials inside the secrets mount, and carry the permissions
   above (probed through a root container; readability proved **as uid 65534**);
2. the override mounts exactly the operator config and secrets directory,
   read-only, and the release's **rendered** Compose config carries those
   mounts (checked before Alertmanager is recreated);
3. the **running** container's mount sources are those host paths, the mounted
   config's bytes equal the host file, the configuration Alertmanager
   **loaded** (`/api/v2/status` → `config.original`) routes to the same
   receiver with the same credential files, and each credential is readable
   inside the container;
4. the delivery record is present, readable, well-formed, names that receiver,
   is human-confirmed and ≤ 7 days old.

A recreation that drops the override (e.g. a bare `docker compose up` from the
release directory) reverts the container to the committed null file — step 3
then stops `reopen`/`go-check` with "mount disagreement" instead of reporting a
null pipeline as configured.

## The three things the rollout distinguishes (and never conflates)

`nlw.ops.rollout.alerting` evaluates and records three separate facts in the
rollout state (`validate` / `reopen` / `go-check`):

| fact | how it is established | what it proves |
|---|---|---|
| `rules_loaded` | Prometheus `/api/v1/rules` lists `nlw-backup` and `nlw-signed-context` | the rule files are mounted and parse |
| `alertmanager_reachable` | Prometheus `/api/v1/alertmanagers` lists an active Alertmanager **and** `/-/healthy` answers | firing alerts reach Alertmanager |
| `delivery_verified` | the default receiver of the **running** container is **not** `null`, every credential `*_file` it references is present and readable as uid 65534, and the operator record above names that receiver, is confirmed, and is ≤ 7 days old (`delivery_status` records why not: `absent`, `stale`, `receiver-mismatch`, `unconfirmed`, …; an `unreadable`/`malformed` record stops outright) | a real human channel received a controlled alert |

Boundaries enforced in code (`tests/unit/test_alerting_boundary.py`):

* The **null receiver is acceptable only to finish a local rehearsal or a
  staging technical deployment** — `reopen` proceeds but records the open
  launch gate `alert delivery unverified` in the state file, and the report
  must carry it. It is never "delivery configured".
* `go-check` (the M12 GO evaluation) is **NO-GO** for staging/production on a
  null receiver, on missing credential files, or without a verified controlled
  test on record. A synthetic alert sent to the null receiver verifies nothing.
* Inline credentials in `alertmanager.yml` (`api_url`, `routing_key`,
  `service_key`, `auth_password`, `bot_token`) are refused outright; only
  `*_file` references are accepted.
* For staging/production the **operator** config is required and may not be
  null; the committed null file can neither stand in for it nor misrepresent
  the running container (`tests/unit/test_rollout_phases.py`, post-rollout
  hotfix section). A reachable container is never delivery proof.

## Checks

```bash
docker compose --env-file .env.prod -f docker-compose.prod.yml -f docker-compose.staging.yml \
  exec -T prometheus wget -qO- http://127.0.0.1:9090/api/v1/rules | python3 -c \
  'import sys,json; print([g["name"] for g in json.load(sys.stdin)["data"]["groups"]])'
# -> ['nlw-backup', 'nlw-signed-context']
docker compose ... exec -T alertmanager wget -qO- http://127.0.0.1:9093/-/healthy
```
