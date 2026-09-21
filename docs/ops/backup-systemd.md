# Scheduling backups with a systemd timer

Backups run from a **systemd timer on the VPS host**, deliberately **not** from the
in-app Dramatiq scheduler (see [ADR-022](../adr/ADR-022-encrypted-offhost-backup-dr.md)):
a backup must keep running even when the application is wedged — coupling it to
the thing it exists to recover would be self-defeating.

> Do **not** enable these units on a developer machine. Installing on a real VPS
> is an operator step outside the M11.5 P2 implementation package.

## Units

- [`docker/systemd/nlw-backup.service`](../../docker/systemd/nlw-backup.service) —
  `Type=oneshot`, `TimeoutStartSec=1800`, runs the `backup` Compose profile once.
- [`docker/systemd/nlw-backup.timer`](../../docker/systemd/nlw-backup.timer) —
  daily `OnCalendar=03:00`, `RandomizedDelaySec=3600` (jitter so many hosts don't
  hit the provider at once), `Persistent=true` (run once after boot if the host
  was off at 03:00, so a missed daily backup is not silently skipped).

## Install

```bash
# 1. Backup credentials in a root-only env file (never committed, never on argv).
sudo install -m 0600 /dev/null /opt/nlw/.env.backup
sudo editor /opt/nlw/.env.backup     # fill from .env.backup.example

# 2. Install the units.
sudo cp /opt/nlw/docker/systemd/nlw-backup.service /etc/systemd/system/
sudo cp /opt/nlw/docker/systemd/nlw-backup.timer   /etc/systemd/system/
sudo systemctl daemon-reload

# 3. Enable the timer (not the service).
sudo systemctl enable --now nlw-backup.timer
```

## Why overlap can never corrupt the repository

Three independent guards:
1. `Type=oneshot` — systemd runs a single instance of the unit.
2. The timer waits for the service to finish before the next fire.
3. **restic locks the repository** — even if two runs somehow overlapped, the
   second writer cannot corrupt the repo; it fails and exits non-zero.

A failed run exits non-zero, so the unit shows `failed` in journald and the
freshness metric (`nlw_backup_last_success_timestamp_seconds`) is **not** advanced
— the dead-man alert will fire (see
[`backup-alerts`](../../docker/prometheus/alerts/backup.rules.yml)).

## Operate

```bash
systemctl list-timers nlw-backup.timer      # next/last fire
systemctl status  nlw-backup.service        # last run result
journalctl -u nlw-backup.service -n 200     # logs (secrets never printed)
sudo systemctl start nlw-backup.service     # run one backup now (ad hoc)
```

## Metrics wiring

The job atomically writes a node_exporter **textfile** with the freshness/success
series. Under the `backup` Compose service the path is fixed to
`/textfile/nlw_backup.prom` inside the **`backup_textfile`** named volume (the
compose file sets `NLW_BACKUP_METRICS_FILE` explicitly, so the value in
`.env.backup` is only used for a bare, non-Compose run). Mount that same
`backup_textfile` volume into your node_exporter container and point
`--collector.textfile.directory` at it, so Prometheus scrapes the series. The file
is written even on failure (with `nlw_backup_success 0`), and the last-success
timestamp advances **only** on a verified off-host snapshot.

## Retention

Retention runs inside each backup (`restic forget --prune`) using
`NLW_BACKUP_RETENTION_DAILY/WEEKLY/MONTHLY` (pilot defaults 14/8/6). If you enable
provider object-lock/immutability for ransomware resistance, automated pruning
cannot reclaim locked objects — see
[`backup-providers.md`](backup-providers.md) and run pruning as a separate
human-gated step.
