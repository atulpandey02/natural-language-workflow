"""Contract: staging-validation proves the backup-freshness chain end to end.

``scripts/ci/backup_metric_evidence.sh`` runs the unchanged real ``backup``
service against a LOCAL, EPHEMERAL restic repository and proves, on the running
containers, backup -> backup_textfile -> hardened node-exporter -> Prometheus
``nlw-backup`` -> timestamp series -> NlwBackupStale loaded and not firing.

Static checks pin where the step runs, what it may reference and how it cleans
up. Behavioural checks EXECUTE the script's own runtime-hardening and Prometheus
checkers against synthetic ``docker inspect`` / Prometheus API documents, so a
weakened checker fails here, not only in a live run.
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/backup_metric_evidence.sh"
IMAGE = "prom/node-exporter:v1.12.1"
VOLUME = "proj_backup_textfile"
STALE_EXPR = (
    "(time() - nlw_backup_last_success_timestamp_seconds > 26 * 3600)"
    " or absent(nlw_backup_last_success_timestamp_seconds)"
)


def _script() -> str:
    return SCRIPT.read_text()


def _steps() -> list[dict[str, Any]]:
    doc = yaml.safe_load((ROOT / ".github/workflows/staging-validation.yml").read_text())
    steps: list[dict[str, Any]] = doc["jobs"]["validate"]["steps"]
    return steps


def _pos(name_prefix: str) -> int:
    hits = [i for i, s in enumerate(_steps()) if str(s.get("name", "")).startswith(name_prefix)]
    assert len(hits) == 1, (name_prefix, hits)
    return hits[0]


# --- where it runs ----------------------------------------------------------------------


def test_evidence_runs_right_after_bring_up_and_before_seeding_drills_k6_and_playwright() -> None:
    ev = _pos("Backup metric ingestion evidence")
    assert ev == _pos("Bring up staging profile") + 1
    for later in (
        "Seed fixtures",
        "Failure drills",
        "k6 capacity",
        "k6 rate-limit",
        "Required Playwright E2E",
    ):
        assert ev < _pos(later), later


def test_evidence_step_is_gating_and_cannot_be_skipped_by_a_browser_failure() -> None:
    step = _steps()[_pos("Backup metric ingestion evidence")]
    assert "if" not in step and "continue-on-error" not in step
    assert step["run"].strip() == "bash scripts/ci/backup_metric_evidence.sh"
    assert step["env"] == {"COMPOSE": "${{ env.COMPOSE }}"}  # no secrets, no repository


# --- what it runs and may reference -----------------------------------------------------------


def test_it_runs_the_unchanged_real_backup_service_and_never_fabricates_metrics() -> None:
    text = _script()
    assert '--profile backup run --name "$BACKUP_CONTAINER" backup' in text
    assert "write_metrics" not in text and "render(" not in text
    # No literal Prometheus text is emitted (reading "$FILE" back is fine).
    assert not re.search(r"(echo|printf)\s+[\"'][^\"'\n]*nlw_backup_\w+ [0-9]", text)
    assert "set -euo pipefail" in text


def test_repository_is_allowlisted_local_and_ephemeral() -> None:
    text = _script()
    assert 'REPO="local:/run/nlw/ci-restic-repository"' in text
    assert re.search(r"case \"\$REPO\" in\n  local:/run/nlw/ci-restic-repository\) ;;", text)
    for forbidden in ("s3:", "http://", "https://", "32.197.83.193", "nlwplatform.com"):
        assert f'"{forbidden}"' in text  # rejected by the guard loop


def test_no_real_host_backend_object_store_or_secret_is_referenced() -> None:
    text = _script()
    guard = next(line for line in text.splitlines() if line.startswith("for forbidden in"))
    rest = text.replace(guard, "")
    for needle in ("32.197.83.193", "nlwplatform.com", "amazonaws.com", "s3:http", "sslip.io"):
        assert needle not in rest, needle
    for image in ("minio", "seaweed", "chainguard", "localstack"):
        assert image not in text.lower(), image
    assert "secrets." not in text and "${{" not in text
    assert "::add-mask::" in text  # generated values are masked


def test_cleanup_runs_on_failure_in_the_script_and_the_workflow() -> None:
    text = _script()
    assert "trap cleanup EXIT" in text
    assert 'docker rm -f "$BACKUP_CONTAINER"' in text
    teardown = _steps()[_pos("Tear down")]
    assert teardown["if"] == "always()"
    run = teardown["run"]
    assert "--profile backup --profile migration down -v --remove-orphans" in run
    assert "docker ps -aq --filter name=nlw-ci-backup-evidence" in run


def test_alert_rule_keeps_threshold_absent_and_for() -> None:
    rules = yaml.safe_load((ROOT / "docker/prometheus/alerts/backup.rules.yml").read_text())
    stale = next(
        r for g in rules["groups"] for r in g["rules"] if r.get("alert") == "NlwBackupStale"
    )
    assert "26 * 3600" in stale["expr"]
    assert "absent(nlw_backup_last_success_timestamp_seconds)" in stale["expr"]
    assert stale["for"] == "15m"


# --- behavioural: the script's own checkers -----------------------------------------------------


def _hardening_checker() -> str:
    m = re.search(
        r"docker inspect \"\$NE\" \| python3 -c '\n(.*?)\n' \"\$EXPECTED_IMAGE\"", _script(), re.S
    )
    assert m, "hardening checker not found"
    return m.group(1)


def _prom_checker() -> str:
    m = re.search(r"<<'PY'\n(.*?)\nPY\n", _script(), re.S)
    assert m, "prometheus checker not found"
    return m.group(1)


def _good_inspect() -> dict[str, Any]:
    return {
        "Config": {"Image": IMAGE, "User": "65534:65534"},
        "HostConfig": {
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "SecurityOpt": ["no-new-privileges:true"],
            "Privileged": False,
            "PortBindings": {},
        },
        "NetworkSettings": {"Ports": {"9100/tcp": None}, "Networks": {"proj_internal": {}}},
        "Mounts": [{"Type": "volume", "Name": VOLUME, "Destination": "/textfile", "RW": False}],
        "Args": [
            "--collector.disable-defaults",
            "--collector.textfile",
            "--collector.textfile.directory=/textfile",
            "--web.listen-address=:9100",
        ],
    }


def _run_hardening(doc: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", _hardening_checker(), IMAGE, VOLUME],
        input=json.dumps([doc]),
        capture_output=True,
        text=True,
        check=False,
    )


def test_hardening_checker_accepts_the_reviewed_runtime() -> None:
    res = _run_hardening(_good_inspect())
    assert res.returncode == 0, res.stdout + res.stderr


def _mutate(path: list[Any], value: Any) -> dict[str, Any]:
    doc = copy.deepcopy(_good_inspect())
    target: Any = doc
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return doc


HARDENING_MUTATIONS = {
    "reverted to v1.9.1": (["Config", "Image"], "prom/node-exporter:v1.9.1"),
    "runs as root": (["Config", "User"], "0:0"),
    "writable rootfs": (["HostConfig", "ReadonlyRootfs"], False),
    "capability restored": (["HostConfig", "CapAdd"], ["NET_RAW"]),
    "capabilities not dropped": (["HostConfig", "CapDrop"], []),
    "no-new-privileges removed": (["HostConfig", "SecurityOpt"], []),
    "privileged": (["HostConfig", "Privileged"], True),
    "port published": (["HostConfig", "PortBindings"], {"9100/tcp": [{"HostPort": "9100"}]}),
    "port mapped": (["NetworkSettings", "Ports"], {"9100/tcp": [{"HostPort": "9100"}]}),
    "mount writable": (
        ["Mounts"],
        [{"Type": "volume", "Name": VOLUME, "Destination": "/textfile", "RW": True}],
    ),
    "host mount added": (
        ["Mounts"],
        [
            {"Type": "volume", "Name": VOLUME, "Destination": "/textfile", "RW": False},
            {"Type": "bind", "Name": "", "Destination": "/host/proc", "RW": False},
        ],
    ),
    "extra network": (["NetworkSettings", "Networks"], {"proj_internal": {}, "bridge": {}}),
    "host collector enabled": (
        ["Args"],
        [
            "--collector.disable-defaults",
            "--collector.textfile",
            "--collector.cpu",
            "--collector.textfile.directory=/textfile",
        ],
    ),  # fmt: skip
    "defaults not disabled": (
        ["Args"],
        ["--collector.textfile", "--collector.textfile.directory=/textfile"],
    ),
}


@pytest.mark.parametrize("name", sorted(HARDENING_MUTATIONS))
def test_hardening_checker_rejects_each_weakening(name: str) -> None:
    path, value = HARDENING_MUTATIONS[name]
    res = _run_hardening(_mutate(path, value))
    assert res.returncode != 0, name
    assert "hardening violations" in res.stdout


def _prom_docs(ts: float) -> dict[str, Any]:
    return {
        "targets": {
            "data": {
                "activeTargets": [
                    {
                        "labels": {"job": "nlw-backup", "instance": "node-exporter:9100"},
                        "health": "up",
                        "lastError": "",
                        "lastScrape": "2026-10-04T13:00:00.123456789Z",
                    },
                    {"labels": {"job": "nlw-api", "instance": "api:9100"}, "health": "up",
                     "lastError": ""},
                ]
            }
        },
        "query": {
            "data": {
                "result": [
                    {"metric": {"job": "nlw-backup", "role": "backup"}, "value": [ts, str(int(ts))]}
                ]
            }
        },
        "rules": {
            "data": {
                "groups": [
                    {
                        "rules": [
                            {
                                "name": "NlwBackupStale",
                                "query": STALE_EXPR,
                                "duration": 900,
                            }
                        ]
                    }
                ]
            }
        },
    }  # fmt: skip


def _run_prom(docs: dict[str, Any], file_ts: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-",
            str(file_ts),
            "900",
            json.dumps(docs["targets"]),
            json.dumps(docs["query"]),
            json.dumps(docs["rules"]),
        ],
        input=_prom_checker(),
        capture_output=True,
        text=True,
        check=False,
    )


def test_prometheus_checker_accepts_fresh_ingested_evidence() -> None:
    ts = float(int(time.time()))
    res = _run_prom(_prom_docs(ts), ts)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "target=up series=1" in res.stdout
    assert "LAST_SCRAPE=2026-10-04T13:00:00.123456789Z" in res.stdout


def _prom_mutations(ts: float) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}

    def m(name: str, fn: Any) -> None:
        docs = copy.deepcopy(_prom_docs(ts))
        fn(docs)
        out[name] = docs

    m("scrape job removed", lambda d: d["targets"]["data"]["activeTargets"].pop(0))
    m(
        "target changed",
        lambda d: d["targets"]["data"]["activeTargets"][0]["labels"].update(instance="api:9100"),
    )
    m("target unhealthy", lambda d: d["targets"]["data"]["activeTargets"][0].update(health="down"))
    m(
        "scrape error",
        lambda d: d["targets"]["data"]["activeTargets"][0].update(lastError="connection refused"),
    )
    m("timestamp series missing", lambda d: d["query"]["data"].update(result=[]))
    m(
        "wrong series labels",
        lambda d: d["query"]["data"]["result"][0]["metric"].update(role="api"),
    )
    m("rule missing", lambda d: d["rules"]["data"]["groups"][0].update(rules=[]))
    m(
        "absent removed",
        lambda d: d["rules"]["data"]["groups"][0]["rules"][0].update(
            query="(time() - nlw_backup_last_success_timestamp_seconds > 26 * 3600)"
        ),
    )
    m(
        "threshold changed",
        lambda d: d["rules"]["data"]["groups"][0]["rules"][0].update(
            query="(time() - nlw_backup_last_success_timestamp_seconds > 48 * 3600)"
            " or absent(nlw_backup_last_success_timestamp_seconds)"
        ),
    )
    m("for changed", lambda d: d["rules"]["data"]["groups"][0]["rules"][0].update(duration=3600))
    return out


@pytest.mark.parametrize(
    "name",
    [
        "scrape job removed",
        "target changed",
        "target unhealthy",
        "scrape error",
        "timestamp series missing",
        "wrong series labels",
        "rule missing",
        "absent removed",
        "threshold changed",
        "for changed",
    ],
)
def test_prometheus_checker_rejects_each_broken_link(name: str) -> None:
    ts = float(int(time.time()))
    res = _run_prom(_prom_mutations(ts)[name], ts)
    assert res.returncode != 0, name


def test_prometheus_checker_rejects_mismatched_or_stale_timestamps() -> None:
    ts = float(int(time.time()))
    assert _run_prom(_prom_docs(ts), ts + 30).returncode != 0  # not what the backup wrote
    old = ts - 3600
    assert _run_prom(_prom_docs(old), old).returncode != 0  # not fresh


def test_the_exact_timestamp_series_is_queried() -> None:
    text = _script()
    assert (
        "QUERY='nlw_backup_last_success_timestamp_seconds%7Bjob%3D%22nlw-backup%22%2C"
        "role%3D%22backup%22%7D'" in text
    )
    assert '"$(api "query?query=${QUERY}")"' in text
    for endpoint in ('"$(api targets)"', '"$(api rules)"'):
        assert endpoint in text
    # Alert state is judged only by the settle program (rules + alerts APIs).
    assert 'fetch(prefix, "rules"), fetch(prefix, "alerts")' in _settle_program()


def test_compose_exporter_has_no_extra_privilege_port_or_mount() -> None:
    svc = yaml.safe_load((ROOT / "docker-compose.staging.yml").read_text())["services"][
        "node-exporter"
    ]
    assert svc["image"] == IMAGE
    assert svc["user"] == "65534:65534" and svc["read_only"] is True
    assert svc["cap_drop"] == ["ALL"] and "cap_add" not in svc
    assert "privileged" not in svc and "ports" not in svc and "network_mode" not in svc
    assert svc["volumes"] == ["backup_textfile:/textfile:ro"]
    assert svc["networks"] == ["internal"]


# --- behavioural: the alert must SETTLE to inactive (pending/firing never pass) ------------

SCRAPE = "2026-10-04T13:00:00.500000000Z"
BEFORE = "2026-10-04T12:59:59.900000000Z"
AFTER = "2026-10-04T13:00:10.250000000Z"

FAKE_PROM = r"""
import json, sys
from pathlib import Path
plan, endpoint = Path(sys.argv[1]), sys.argv[-1].rsplit("/", 1)[-1]
docs = json.loads(plan.read_text())
counter = plan.with_suffix("." + endpoint + ".n")
n = int(counter.read_text()) if counter.exists() else 0
counter.write_text(str(n + 1))
seq = docs[endpoint]
item = seq[min(n, len(seq) - 1)]
if item == "API_ERROR":
    sys.exit(7)
print(item if isinstance(item, str) else json.dumps(item))
"""


def _settle_program() -> str:
    m = re.search(r"<<'SETTLE'\n(.*?)\nSETTLE\n", _script(), re.S)
    assert m, "settle program not found"
    return m.group(1)


def _rules(state: str, last_eval: str = AFTER) -> dict[str, Any]:
    return {
        "status": "success",
        "data": {
            "groups": [
                {"rules": [{"name": "NlwBackupStale", "state": state, "lastEvaluation": last_eval}]}
            ]
        },
    }


def _alerts(*states: str) -> dict[str, Any]:
    alerts = [{"labels": {"alertname": "NlwBackupStale"}, "state": st} for st in states]
    return {"status": "success", "data": {"alerts": alerts}}


def _settle(
    tmp_path: Path, rules: list[Any], alerts: list[Any], timeout: str = "2"
) -> subprocess.CompletedProcess[str]:
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"rules": rules, "alerts": alerts}))
    fake = tmp_path / "fake_prom.py"
    fake.write_text(FAKE_PROM)
    return subprocess.run(
        [sys.executable, "-", SCRAPE, "0.05", timeout, sys.executable, str(fake), str(plan)],
        input=_settle_program(),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def test_settle_passes_when_inactive_and_absent_after_a_post_scrape_evaluation(
    tmp_path: Path,
) -> None:
    res = _settle(tmp_path, [_rules("inactive")], [_alerts()])
    assert res.returncode == 0, res.stdout
    assert res.stdout.splitlines() == ["alert state: inactive"]


def test_settle_rejects_pending(tmp_path: Path) -> None:
    res = _settle(tmp_path, [_rules("pending")], [_alerts("pending")], timeout="0.3")
    assert res.returncode == 1
    assert "alert state: pending" in res.stdout and "timeout (last state: pending)" in res.stdout


def test_settle_rejects_firing(tmp_path: Path) -> None:
    res = _settle(tmp_path, [_rules("firing")], [_alerts("firing")], timeout="0.3")
    assert res.returncode == 1
    assert "alert state: firing" in res.stdout and "timeout" in res.stdout


def test_settle_accepts_pending_followed_by_inactive(tmp_path: Path) -> None:
    res = _settle(
        tmp_path,
        [_rules("pending"), _rules("pending"), _rules("inactive")],
        [_alerts("pending"), _alerts("pending"), _alerts()],
    )
    assert res.returncode == 0, res.stdout
    assert res.stdout.splitlines() == ["alert state: pending", "alert state: inactive"]


def test_settle_requires_an_evaluation_after_the_scrape(tmp_path: Path) -> None:
    res = _settle(tmp_path, [_rules("inactive", last_eval=BEFORE)], [_alerts()], timeout="0.3")
    assert res.returncode == 1 and "timeout" in res.stdout


def test_settle_requires_no_active_alert_even_if_the_rule_reads_inactive(tmp_path: Path) -> None:
    res = _settle(tmp_path, [_rules("inactive")], [_alerts("pending")], timeout="0.3")
    assert res.returncode == 1 and "alert state: pending" in res.stdout


@pytest.mark.parametrize(
    ("rules", "alerts"),
    [
        (["API_ERROR"], [_alerts()]),
        ([_rules("inactive")], ["API_ERROR"]),
        (["not json"], [_alerts()]),
        ([{"status": "error", "data": {}}], [_alerts()]),
        ([_rules("weird")], [_alerts()]),
        ([_rules("inactive")], [_alerts("unknown")]),
        ([_rules("inactive", last_eval="not-a-time")], [_alerts()]),
        ([{"status": "success", "data": {"groups": []}}], [_alerts()]),
    ],
)
def test_settle_fails_closed_on_api_errors_malformed_or_unknown_state(
    tmp_path: Path, rules: list[Any], alerts: list[Any]
) -> None:
    res = _settle(tmp_path, rules, alerts)
    assert res.returncode == 1
    assert "api-error" in res.stdout


def test_settle_output_is_state_names_only(tmp_path: Path) -> None:
    alerts = _alerts("pending")
    alerts["data"]["alerts"][0]["labels"]["secretish"] = "do-not-print-me"
    alerts["data"]["alerts"][0]["annotations"] = {"summary": "do-not-print-me"}
    res = _settle(tmp_path, [_rules("pending")], [alerts], timeout="0.2")
    assert "do-not-print-me" not in res.stdout + res.stderr
    for line in res.stdout.splitlines():
        assert re.fullmatch(
            r"alert state: (inactive|pending|firing)|timeout \(last state: \w+\)", line
        )


def test_settle_polling_is_bounded(tmp_path: Path) -> None:
    text = _script()
    assert 'SETTLE_INTERVAL_S="${EVIDENCE_SETTLE_INTERVAL_S:-5}"' in text
    assert 'SETTLE_TIMEOUT_S="${EVIDENCE_SETTLE_TIMEOUT_S:-90}"' in text
    assert "MAX_TIMEOUT_S = 90" in _settle_program()
    res = _settle(tmp_path, [_rules("inactive")], [_alerts()], timeout="120")
    assert res.returncode == 1 and "bad settle bounds" in res.stdout


def test_the_script_cannot_accept_merely_not_firing() -> None:
    text = _script()
    assert "not firing for fresh evidence" not in text
    program = _settle_program()
    assert 'if state == "inactive" and not active and evaluated_after_scrape:' in program
    assert program.count('return "pass", state') == 1  # the ONLY way to pass
    assert 'fail "NlwBackupStale did not settle to inactive' in text
