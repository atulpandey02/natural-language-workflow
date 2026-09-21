"""Production-equivalent TLS PostgreSQL proof (M11.5 P1B, review addendum).

A disposable TLS-enabled Postgres with a test CA and a server certificate whose
SAN matches a controlled hostname. Runs a real query through the COMPLETE
connector path under a production/staging destination policy
(``require_public`` + ``require_verify_full``), with the loopback fixture
permitted via the operator CIDR allowlist (the "approved private staging DB"
path). Proves verify-full succeeds with the correct hostname + trusted CA +
pinned ``hostaddr``, and fails closed on an untrusted CA or a hostname/SAN
mismatch — never downgrading to plaintext, never letting a tenant weaken TLS.
"""

import base64
import datetime
import ipaddress
import json
import socket
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

from nlw.connectors.pg_destination import (
    PostgresDestinationPolicy,
    PostgresTlsPolicyError,
)
from nlw.connectors.postgres import (
    PostgresAuthError,
    PostgresConnectorConfig,
    PostgresSecret,
    PostgresUnavailableError,
    parse_secret,
    run_read_only_query,
)

pytestmark = pytest.mark.integration

CERT_HOST = "pg.test.local"
READER_USER = "tls_reader"
READER_PW = "tls-reader-pw-must-not-leak"


def _gen_ca_and_server(directory: Path, san_host: str) -> SimpleNamespace:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.UTC)

    def _pem_key(key: rsa.RSAPrivateKey) -> bytes:
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

    # Test CA.
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nlw-test-ca")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # Server cert signed by the CA, SAN = san_host.
    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, san_host)]))
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(san_host)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    # A DIFFERENT, untrusted CA (never signs the server cert).
    other_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nlw-untrusted-ca")])
    other_ca = (
        x509.CertificateBuilder()
        .subject_name(other_name)
        .issuer_name(other_name)
        .public_key(other_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(other_ca_key, hashes.SHA256())
    )

    ca_crt = directory / "ca.crt"
    other_ca_crt = directory / "untrusted-ca.crt"
    srv_crt = directory / "server.crt"
    srv_key_path = directory / "server.key"
    ca_crt.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    other_ca_crt.write_bytes(other_ca.public_bytes(serialization.Encoding.PEM))
    srv_crt.write_bytes(srv_cert.public_bytes(serialization.Encoding.PEM))
    srv_key_path.write_bytes(_pem_key(srv_key))
    return SimpleNamespace(
        ca_crt=str(ca_crt),
        untrusted_ca_crt=str(other_ca_crt),
        server_crt=srv_crt.read_bytes(),
        server_key=srv_key_path.read_bytes(),
    )


def _write_in_container(raw: object, content: bytes, path: str) -> None:
    b64 = base64.b64encode(content).decode()
    rc, out = raw.exec_run(["sh", "-c", f"echo {b64} | base64 -d > {path}"])  # type: ignore[attr-defined]
    assert rc == 0, out


@pytest.fixture(scope="module")
def tls_pg(tmp_path_factory: pytest.TempPathFactory) -> Iterator[SimpleNamespace]:
    certs = _gen_ca_and_server(tmp_path_factory.mktemp("tlspg"), CERT_HOST)
    with PostgresContainer("postgres:16") as pg:
        raw = pg.get_wrapped_container()
        _write_in_container(raw, certs.server_crt, "/var/lib/postgresql/server.crt")
        _write_in_container(raw, certs.server_key, "/var/lib/postgresql/server.key")
        for cmd in (
            ["chown", "postgres:postgres", "/var/lib/postgresql/server.crt"],
            ["chown", "postgres:postgres", "/var/lib/postgresql/server.key"],
            ["chmod", "600", "/var/lib/postgresql/server.key"],
        ):
            rc, out = raw.exec_run(cmd)
            assert rc == 0, out

        host_ip_name = pg.get_container_host_ip()
        port = int(pg.get_exposed_port(5432))
        db = pg.dbname
        owner = f"postgresql://{pg.username}:{pg.password}@{host_ip_name}:{port}/{db}"
        with psycopg.connect(owner, autocommit=True) as c:
            c.execute("ALTER SYSTEM SET ssl = on")
            c.execute("ALTER SYSTEM SET ssl_cert_file = '/var/lib/postgresql/server.crt'")
            c.execute("ALTER SYSTEM SET ssl_key_file = '/var/lib/postgresql/server.key'")
            c.execute("SELECT pg_reload_conf()")
        # Confirm TLS is actually enabled before proceeding.
        with psycopg.connect(owner, autocommit=True) as c:
            ssl_row = c.execute("SHOW ssl").fetchone()
            assert ssl_row is not None and ssl_row[0] == "on"
            c.execute("CREATE TABLE public.people (id int PRIMARY KEY, name text)")
            c.execute("INSERT INTO public.people VALUES (1,'a'),(2,'b')")
            c.execute(
                f"CREATE ROLE {READER_USER} LOGIN PASSWORD '{READER_PW}' "
                "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"
            )
            c.execute(f"GRANT CONNECT ON DATABASE {db} TO {READER_USER}")
            c.execute(f"GRANT USAGE ON SCHEMA public TO {READER_USER}")
            c.execute(f"GRANT SELECT ON public.people TO {READER_USER}")

        # hostaddr must be an IP literal; testcontainers may report "localhost".
        host_ip = (
            "127.0.0.1" if host_ip_name in ("localhost", "") else socket.gethostbyname(host_ip_name)
        )
        yield SimpleNamespace(host_ip=host_ip, port=port, db=db, certs=certs)


def _config(tls: SimpleNamespace, sslmode: str = "verify-full") -> PostgresConnectorConfig:
    return PostgresConnectorConfig.model_validate(
        {
            "host": CERT_HOST,  # the hostname the cert SAN is issued for
            "port": tls.port,
            "database": tls.db,
            "sslmode": sslmode,
            "allowed_schemas": ["public"],
            "allowed_tables": ["public.people"],
        }
    )


def _reader_secret() -> PostgresSecret:
    return parse_secret(json.dumps({"username": READER_USER, "password": READER_PW}))


def _prod_policy(
    tls: SimpleNamespace, *, resolve_host: str = CERT_HOST, ca: str | None = None
) -> PostgresDestinationPolicy:
    """Production/staging policy: require_public + require_verify_full, with the
    loopback fixture permitted via the operator CIDR allowlist (approved private
    staging DB). ``ca`` overrides the trust root (default: the trusted test CA)."""
    return PostgresDestinationPolicy(
        require_public=True,
        require_verify_full=True,
        allow_networks=(ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")),
        extra_allowed_ports=frozenset({tls.port}),  # operator-approved mapped test port
        resolver=lambda h: [tls.host_ip] if h == resolve_host else [],
        ssl_root_cert=ca if ca is not None else tls.certs.ca_crt,
    )


def test_verify_full_succeeds_with_correct_host_trusted_ca_and_pinned_hostaddr(
    tls_pg: SimpleNamespace,
) -> None:
    result = run_read_only_query(
        _config(tls_pg),
        _reader_secret(),
        "SELECT id, name FROM public.people ORDER BY id",
        policy=_prod_policy(tls_pg),
    )
    assert result.columns == ["id", "name"]
    assert result.rows == [[1, "a"], [2, "b"]]


def test_verify_full_fails_with_untrusted_ca(tls_pg: SimpleNamespace) -> None:
    with pytest.raises((PostgresUnavailableError, PostgresAuthError)):
        run_read_only_query(
            _config(tls_pg),
            _reader_secret(),
            "SELECT id FROM public.people",
            policy=_prod_policy(tls_pg, ca=tls_pg.certs.untrusted_ca_crt),
        )


def test_verify_full_fails_on_hostname_san_mismatch(tls_pg: SimpleNamespace) -> None:
    wrong = "wrong.host.local"
    cfg = PostgresConnectorConfig.model_validate(
        {
            "host": wrong,  # cert SAN is pg.test.local, not this
            "port": tls_pg.port,
            "database": tls_pg.db,
            "sslmode": "verify-full",
            "allowed_schemas": ["public"],
            "allowed_tables": ["public.people"],
        }
    )
    with pytest.raises((PostgresUnavailableError, PostgresAuthError)):
        run_read_only_query(
            cfg,
            _reader_secret(),
            "SELECT id FROM public.people",
            policy=_prod_policy(tls_pg, resolve_host=wrong),
        )


def test_tenant_cannot_replace_verify_full_with_weaker_mode(tls_pg: SimpleNamespace) -> None:
    # Even though the plaintext-capable server would accept it, the production
    # policy rejects a weaker tenant sslmode BEFORE any connection.
    with pytest.raises(PostgresTlsPolicyError):
        run_read_only_query(
            _config(tls_pg, sslmode="prefer"),
            _reader_secret(),
            "SELECT id FROM public.people",
            policy=_prod_policy(tls_pg),
        )


def test_password_not_present_in_successful_result(tls_pg: SimpleNamespace) -> None:
    result = run_read_only_query(
        _config(tls_pg),
        _reader_secret(),
        "SELECT id, name FROM public.people ORDER BY id",
        policy=_prod_policy(tls_pg),
    )
    assert READER_PW not in json.dumps({"columns": result.columns, "rows": result.rows})
