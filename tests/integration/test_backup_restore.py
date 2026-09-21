"""Backup -> restore drill (M9, ADR-018).

Proves the custom-format logical dump restores with full fidelity into a FRESH
database. pg_dump/pg_restore run inside the Postgres container (so the host needs
no client tools); this exercises the exact dump/restore path the runbook uses.
This is the M9 fidelity drill; the M11.5 P2 DR mechanism (encrypted off-host
restic + guarded restore + quiescence + validation, ADR-022) is exercised by the
`tests/*/test_dr_*` suites and `scripts/ops/dr-drill.sh`.
"""

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

pytestmark = pytest.mark.integration


def test_custom_format_dump_restores_into_fresh_db() -> None:
    with PostgresContainer("postgres:16") as pg:
        host, port = pg.get_container_host_ip(), pg.get_exposed_port(5432)
        url = f"postgresql://{pg.username}:{pg.password}@{host}:{port}/{pg.dbname}"

        # Seed representative data.
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE TABLE widget (id int PRIMARY KEY, name text)")
            conn.execute("INSERT INTO widget VALUES (1,'a'),(2,'b'),(3,'c')")

        container = pg.get_wrapped_container()
        env = {"PGPASSWORD": pg.password}

        def _exec(cmd: list[str]) -> tuple[int, str]:
            code, output = container.exec_run(cmd, environment=env)
            return code, output.decode()

        # 1) Backup (custom format).
        code, out = _exec(
            ["pg_dump", "-U", pg.username, "-d", pg.dbname, "-F", "c", "-f", "/tmp/nlw.dump"]
        )
        assert code == 0, out

        # 2) Restore into a brand-new database.
        code, out = _exec(["createdb", "-U", pg.username, "restored"])
        assert code == 0, out
        code, out = _exec(["pg_restore", "-U", pg.username, "-d", "restored", "/tmp/nlw.dump"])
        assert code == 0, out

        # 3) Verify fidelity in the restored database.
        code, out = _exec(
            ["psql", "-U", pg.username, "-d", "restored", "-tAc", "SELECT count(*) FROM widget"]
        )
        assert code == 0, out
        assert out.strip() == "3"
