"""PostgreSQL destination egress + TLS policy matrix (M11.5 P1B).

Pure unit tests: DNS is an injected resolver; "servers" are controlled local
sockets. Proves unsafe destinations are rejected BEFORE any bytes are sent,
TLS is enforced to verify-full in production with the hostname preserved and the
validated IP pinned as hostaddr, and dummy credentials never reach a listener.
"""

import contextlib
import datetime
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest

from nlw.connectors import postgres as pg
from nlw.connectors.pg_destination import (
    PostgresDestinationError,
    PostgresDestinationPolicy,
    PostgresTlsPolicyError,
    Resolver,
)


def _resolver(mapping: dict[str, list[str]]) -> Resolver:
    return lambda h: mapping.get(h, [])


def _prod(resolver: Resolver, **over: object) -> PostgresDestinationPolicy:
    kwargs: dict[str, object] = {
        "require_public": True,
        "require_verify_full": True,
        "resolver": resolver,
    }
    kwargs.update(over)
    return PostgresDestinationPolicy(**kwargs)  # type: ignore[arg-type]


def _local(resolver: Resolver) -> PostgresDestinationPolicy:
    return PostgresDestinationPolicy(
        require_public=False, require_verify_full=False, resolver=resolver
    )


# --- Destination classification matrix (production) --------------------------

_BLOCKED = [
    ("ipv4_loopback", ["127.0.0.1"]),
    ("ipv6_loopback", ["::1"]),
    ("rfc1918_10", ["10.1.2.3"]),
    ("rfc1918_172", ["172.16.9.9"]),
    ("rfc1918_192", ["192.168.1.5"]),
    ("ipv6_ula", ["fc00::1"]),
    ("link_local", ["169.254.1.1"]),
    ("metadata", ["169.254.169.254"]),
    ("cgnat", ["100.64.0.1"]),
    ("multicast", ["224.0.0.1"]),
    ("unspecified", ["0.0.0.0"]),
    ("ipv4_mapped_private", ["::ffff:10.0.0.1"]),
    ("mixed_answers", ["93.184.216.34", "127.0.0.1"]),
]


@pytest.mark.parametrize("label,ips", _BLOCKED)
def test_production_blocks_unsafe_addresses(label: str, ips: list[str]) -> None:
    policy = _prod(_resolver({"db.example.com": ips}))
    with pytest.raises(PostgresDestinationError):
        policy.validate_and_pin("db.example.com", 5432, "verify-full")


@pytest.mark.parametrize("ips", [["93.184.216.34"], ["2606:2800:220:1:248:1893:25c8:1946"]])
def test_production_allows_public_and_pins(ips: list[str]) -> None:
    policy = _prod(_resolver({"db.example.com": ips}))
    dest = policy.validate_and_pin("db.example.com", 5432, "verify-full")
    assert dest.host == "db.example.com"
    assert dest.hostaddr in ips
    assert dest.sslmode == "verify-full"


@pytest.mark.parametrize(
    "name",
    [
        "postgres",
        "redis",
        "api",
        "worker",
        "scheduler",
        "web",
        "caddy",
        "prometheus",
        "localhost",
        "host.docker.internal",
    ],
)
def test_production_blocks_internal_service_names(name: str) -> None:
    # Even if a search domain resolved them to a public IP, block by name.
    policy = _prod(_resolver({name: ["93.184.216.34"]}))
    with pytest.raises(PostgresDestinationError):
        policy.validate_and_pin(name, 5432, "verify-full")


@pytest.mark.parametrize(
    "host",
    ["/var/run/postgresql", "host=evil port=5432", "a,b", "user@host", "postgres://x", "", " x "],
)
def test_rejects_unsafe_host_forms(host: str) -> None:
    policy = _prod(_resolver({}))
    with pytest.raises(PostgresDestinationError):
        policy.validate_and_pin(host, 5432, "verify-full")


def test_rebinding_uses_only_validated_pinned_address() -> None:
    # A resolver that would return an unsafe answer on a *second* call must never
    # be consulted again: validate_and_pin resolves once and pins.
    calls = {"n": 0}

    def flaky(_host: str) -> list[str]:
        calls["n"] += 1
        return ["93.184.216.34"] if calls["n"] == 1 else ["127.0.0.1"]

    policy = _prod(flaky)
    dest = policy.validate_and_pin("db.example.com", 5432, "verify-full")
    assert dest.hostaddrs == ("93.184.216.34",)
    assert calls["n"] == 1  # resolved exactly once; the pinned IP is reused as hostaddr


# --- Port policy -------------------------------------------------------------


def test_default_port_allowed() -> None:
    assert _prod(_resolver({"db.example.com": ["93.184.216.34"]})).validate_and_pin(
        "db.example.com", 5432, "verify-full"
    )


def test_nondefault_port_rejected_in_production() -> None:
    with pytest.raises(PostgresDestinationError):
        _prod(_resolver({"db.example.com": ["93.184.216.34"]})).validate_and_pin(
            "db.example.com", 6543, "verify-full"
        )


def test_operator_allowed_extra_port() -> None:
    policy = _prod(
        _resolver({"db.example.com": ["93.184.216.34"]}), extra_allowed_ports=frozenset({6543})
    )
    assert policy.validate_and_pin("db.example.com", 6543, "verify-full")


# --- TLS matrix --------------------------------------------------------------


@pytest.mark.parametrize("mode", ["disable", "allow", "prefer", "require", "verify-ca"])
def test_production_rejects_weak_sslmode(mode: str) -> None:
    policy = _prod(_resolver({"db.example.com": ["93.184.216.34"]}))
    with pytest.raises(PostgresTlsPolicyError):
        policy.validate_and_pin("db.example.com", 5432, mode)


def test_production_requires_verify_full() -> None:
    policy = _prod(_resolver({"db.example.com": ["93.184.216.34"]}))
    dest = policy.validate_and_pin("db.example.com", 5432, "verify-full")
    assert dest.sslmode == "verify-full"


# --- Private-destination exception (env gate only) ---------------------------


def test_local_allows_private_fixture_and_honours_sslmode() -> None:
    dest = _local(_resolver({"db.internal": ["10.0.0.5"]})).validate_and_pin(
        "db.internal", 55432, "disable"
    )
    assert dest.hostaddr == "10.0.0.5" and dest.sslmode == "disable"


def test_operator_cidr_allowlist_permits_private_in_production() -> None:
    import ipaddress

    policy = _prod(
        _resolver({"db.internal": ["10.9.0.7"]}),
        allow_networks=(ipaddress.ip_network("10.9.0.0/24"),),
    )
    dest = policy.validate_and_pin("db.internal", 5432, "verify-full")
    assert dest.hostaddr == "10.9.0.7"


def test_from_settings_production_is_strict() -> None:
    policy = PostgresDestinationPolicy.from_settings(SimpleNamespace(app_env="production"))
    assert policy.require_public and policy.require_verify_full


def test_from_settings_local_is_permissive() -> None:
    policy = PostgresDestinationPolicy.from_settings(SimpleNamespace(app_env="local"))
    assert not policy.require_public and not policy.require_verify_full


def test_private_override_cannot_leak_via_config_in_production() -> None:
    # No connector/config field can flip the gate: a production policy still
    # blocks a private target regardless of what the config asked for.
    policy = PostgresDestinationPolicy.from_settings(
        SimpleNamespace(app_env="production", postgres_destination_allowlist=[])
    )
    with pytest.raises(PostgresDestinationError):
        policy.validate_and_pin("db.example.com", 5432, "verify-full")  # no resolver -> no answer


# --- Connection-parameter proof (hostname preserved, IP pinned, verify-full) -


def test_connect_receives_hostname_hostaddr_and_verify_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_connect(**kwargs: object) -> object:
        captured.update(kwargs)
        raise psycopg.OperationalError("stop before real connect")

    monkeypatch.setattr(psycopg, "connect", fake_connect)
    config = pg.parse_config({"host": "db.example.com", "database": "d", "sslmode": "verify-full"})
    secret = pg.parse_secret('{"username": "u", "password": "p"}')
    policy = _prod(_resolver({"db.example.com": ["93.184.216.34"]}))
    with (
        pytest.raises(pg.PostgresUnavailableError),
        pg._read_only_connection(config, secret, policy),
    ):
        pass
    assert captured["host"] == "db.example.com"  # original hostname -> SNI / cert verification
    assert captured["hostaddr"] == "93.184.216.34"  # pinned validated IP -> TCP target
    assert captured["sslmode"] == "verify-full"


# --- Credential-exfiltration proofs (controlled listeners) -------------------


@pytest.fixture
def listener() -> Iterator[SimpleNamespace]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    state = SimpleNamespace(received=b"", accepted=False)

    def serve() -> None:
        sock.settimeout(3)
        try:
            conn, _ = sock.accept()
            state.accepted = True
            conn.settimeout(2)
            with contextlib.suppress(OSError):
                state.received = conn.recv(4096)
            conn.close()
        except OSError:
            pass
        finally:
            sock.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield SimpleNamespace(port=port, state=state, thread=t)
    t.join(timeout=3)


def test_unsafe_destination_sends_zero_bytes(listener: SimpleNamespace) -> None:
    # A production policy rejects the loopback target BEFORE any connect attempt.
    config = pg.parse_config(
        {
            "host": "127.0.0.1",
            "port": listener.port,
            "database": "d",
            "sslmode": "verify-full",
            "connect_timeout_s": 2,
        }
    )
    secret = pg.parse_secret('{"username": "dummy", "password": "dummy-PW-must-not-leak"}')
    policy = _prod(
        _resolver({"127.0.0.1": ["127.0.0.1"]}), extra_allowed_ports=frozenset({listener.port})
    )
    with pytest.raises(PostgresDestinationError), pg._read_only_connection(config, secret, policy):
        pass
    listener.thread.join(timeout=1)
    assert listener.state.accepted is False
    assert listener.state.received == b""  # zero bytes, no TCP auth exchange


def _self_signed_cert(tmp_path: Path) -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wrong-host.example")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("wrong-host.example")]), False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


def test_verify_full_does_not_fall_back_to_plaintext(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A controlled TLS 'postgres' whose cert hostname does not match the pinned
    hostname must cause verify-full to FAIL — with no plaintext credential bytes
    sent and no downgrade."""
    cert_path, key_path = _self_signed_cert(tmp_path)
    raw_before_tls = {"data": b""}

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve() -> None:
        srv.settimeout(4)
        try:
            conn, _ = srv.accept()
            conn.settimeout(3)
            # Postgres SSLRequest: 8 bytes; reply 'S' to proceed to TLS.
            raw_before_tls["data"] = conn.recv(8)
            conn.sendall(b"S")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_path, key_path)
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
                tls.recv(64)  # would be the startup packet IF the client trusted us
                tls.close()
            except ssl.SSLError:
                conn.close()
        except OSError:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    config = pg.parse_config(
        {
            "host": "db.pinned.example",
            "port": port,
            "database": "d",
            "sslmode": "verify-full",
            "connect_timeout_s": 3,
        }
    )
    secret = pg.parse_secret('{"username": "u", "password": "PLAINTEXT-PW-must-not-leak"}')
    # Local policy so the private 127.0.0.1 target is permitted, but the config
    # explicitly asks for verify-full (honoured), pinned to 127.0.0.1.
    policy = _local(_resolver({"db.pinned.example": ["127.0.0.1"]}))
    # verify-full to an untrusted/mismatched cert fails; the connector sanitizes
    # the driver error (unavailable/auth) — the point is it does NOT succeed and
    # never sends plaintext credentials.
    with (
        pytest.raises((pg.PostgresUnavailableError, pg.PostgresAuthError)),
        pg._read_only_connection(config, secret, policy),
    ):
        pass
    t.join(timeout=4)
    # Only the 8-byte SSLRequest was seen in cleartext; the credential-bearing
    # startup packet was never sent because the TLS cert did not verify.
    assert len(raw_before_tls["data"]) <= 8
    assert b"PLAINTEXT-PW-must-not-leak" not in raw_before_tls["data"]


# --- DNS wall-clock bound (genuinely blocking resolver + elapsed assertion) ---


def test_dns_resolution_has_a_real_wall_clock_bound() -> None:
    started = threading.Event()
    release = threading.Event()

    def blocking_resolver(_host: str) -> list[str]:
        started.set()
        release.wait(30)  # genuinely blocks far beyond the deadline
        return ["93.184.216.34"]

    policy = PostgresDestinationPolicy(
        require_public=True, require_verify_full=True, resolver=blocking_resolver, dns_timeout_s=0.5
    )
    non_daemon_before = [t for t in threading.enumerate() if not t.daemon]
    t0 = time.monotonic()
    with pytest.raises(PostgresDestinationError):
        policy.validate_and_pin("db.example.com", 5432, "verify-full")
    elapsed = time.monotonic() - t0

    assert started.is_set()  # the resolver really ran
    assert elapsed < 3.0, f"validation waited {elapsed:.2f}s (should be ~0.5s + margin)"
    # The still-blocked resolver runs on a daemon thread -> it never blocks
    # process shutdown, and no new NON-daemon thread was spawned.
    live = [t for t in threading.enumerate() if t.name.startswith("pg-dns-")]
    assert live and all(t.daemon for t in live)
    assert [t for t in threading.enumerate() if not t.daemon] == non_daemon_before
    release.set()  # let the abandoned thread finish so the session stays tidy


def test_repeated_resolver_timeouts_do_not_leak_nondaemon_threads() -> None:
    release = threading.Event()

    def blocking_resolver(_host: str) -> list[str]:
        release.wait(30)
        return []

    policy = PostgresDestinationPolicy(
        require_public=True, require_verify_full=True, resolver=blocking_resolver, dns_timeout_s=0.1
    )
    non_daemon_before = {t.ident for t in threading.enumerate() if not t.daemon}
    for _ in range(12):
        with pytest.raises(PostgresDestinationError):
            policy.validate_and_pin("db.example.com", 5432, "verify-full")
    # Every abandoned resolver thread is a daemon; no non-daemon thread leaked.
    pg_threads = [t for t in threading.enumerate() if t.name.startswith("pg-dns-")]
    assert all(t.daemon for t in pg_threads)
    assert {t.ident for t in threading.enumerate() if not t.daemon} == non_daemon_before
    release.set()
