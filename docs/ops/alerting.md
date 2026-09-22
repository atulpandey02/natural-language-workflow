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

### Wiring a real receiver (when chosen)

1. Put the credential in a root-only file on the host, e.g.
   `/opt/nlw/alertmanager.secrets/<receiver>.txt` (`0600`), and mount it into the
   `alertmanager` service at `/etc/alertmanager/secrets/` read-only.
2. Reference it from the config with the receiver's `*_file` option
   (`api_url_file`, `routing_key_file`, `auth_password_file`, …) — never inline.
3. Point the `severity = critical` route (and the default) at the new receiver;
   keep `null` for tests.
4. `amtool check-config`, restart Alertmanager, then send a **controlled test
   alert** (`amtool alert add --alertmanager.url=http://alertmanager:9093 test
   severity=warning`) and confirm delivery.

5. Record the verified test in `/opt/nlw/rollout/alert-delivery.json` (root
   owned, outside every checkout) — `{"receiver": "<name>", "delivered_at":
   "<ISO-8601, tz>", "confirmed_by": "<operator>"}` — naming the receiver that
   is now the default route. The record counts for 7 days.

Until this is done, "alert delivery" is an **open launch gate** in the M12
checklist — never report it as complete because the null pipeline is healthy.

## The three things the rollout distinguishes (and never conflates)

`nlw.ops.rollout.alerting` evaluates and records three separate facts in the
rollout state (`validate` / `reopen` / `go-check`):

| fact | how it is established | what it proves |
|---|---|---|
| `rules_loaded` | Prometheus `/api/v1/rules` lists `nlw-backup` and `nlw-signed-context` | the rule files are mounted and parse |
| `alertmanager_reachable` | Prometheus `/api/v1/alertmanagers` lists an active Alertmanager **and** `/-/healthy` answers | firing alerts reach Alertmanager |
| `delivery_verified` | the default receiver is **not** `null`, every credential `*_file` it references exists in the secrets dir, and the operator record above names that receiver, is confirmed, and is ≤ 7 days old | a real human channel received a controlled alert |

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

## Checks

```bash
docker compose --env-file .env.prod -f docker-compose.prod.yml -f docker-compose.staging.yml \
  exec -T prometheus wget -qO- http://127.0.0.1:9090/api/v1/rules | python3 -c \
  'import sys,json; print([g["name"] for g in json.load(sys.stdin)["data"]["groups"]])'
# -> ['nlw-backup', 'nlw-signed-context']
docker compose ... exec -T alertmanager wget -qO- http://127.0.0.1:9093/-/healthy
```
