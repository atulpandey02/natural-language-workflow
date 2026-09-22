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

Until this is done, "alert delivery" is an **open launch gate** in the M12
checklist — never report it as complete because the null pipeline is healthy.

## Checks

```bash
docker compose --env-file .env.prod -f docker-compose.prod.yml -f docker-compose.staging.yml \
  exec -T prometheus wget -qO- http://127.0.0.1:9090/api/v1/rules | python3 -c \
  'import sys,json; print([g["name"] for g in json.load(sys.stdin)["data"]["groups"]])'
# -> ['nlw-backup', 'nlw-signed-context']
docker compose ... exec -T alertmanager wget -qO- http://127.0.0.1:9093/-/healthy
```
