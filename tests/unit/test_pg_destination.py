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
    BoundedResolverPool,
    PostgresDestinationError,
    PostgresDestinationPolicy,
    PostgresDnsUnavailableError,
    PostgresTlsPolicyError,
    Resolver,
)
from nlw.registry.registry import ToolExecutionError


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
    # No connector/config field can flip the gate: a production policy (empty
    # operator allowlist) still deterministically blocks a private target.
    policy = PostgresDestinationPolicy.from_settings(
        SimpleNamespace(app_env="production", postgres_destination_allowlist=[]),
        resolver=_resolver({"db.example.com": ["10.0.0.5"]}),
    )
    with pytest.raises(PostgresDestinationError):
        policy.validate_and_pin("db.example.com", 5432, "verify-full")


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


# --- DNS bound: latency + RESOURCE consumption (fixed pool + bounded queue) ---


def _blocking_resolver(release: threading.Event) -> Resolver:
    def _r(_host: str) -> list[str]:
        release.wait(30)  # blocks far beyond any test deadline
        return ["93.184.216.34"]

    return _r


def _pool_policy(
    pool: BoundedResolverPool, resolver: Resolver, dns_timeout_s: float = 0.4
) -> PostgresDestinationPolicy:
    return PostgresDestinationPolicy(
        require_public=True,
        require_verify_full=True,
        resolver=resolver,
        dns_timeout_s=dns_timeout_s,
        resolver_pool=pool,
    )


def _saturate(
    pool: BoundedResolverPool, policy: PostgresDestinationPolicy, n: int
) -> list[threading.Thread]:
    """Fire n concurrent callers to fill workers + queue; return the threads."""

    def _call() -> None:
        with contextlib.suppress(Exception):  # saturation callers may time out
            policy.validate_and_pin("db.example.com", 5432, "verify-full")

    threads = [threading.Thread(target=_call, daemon=True) for _ in range(n)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + 4
    while (
        pool.live_worker_count() < pool.max_workers or pool.queued() < pool.max_queue
    ) and time.monotonic() < deadline:
        time.sleep(0.02)
    return threads


def test_repeated_timeouts_do_not_grow_threads_and_never_exceed_max_workers() -> None:
    pool = BoundedResolverPool(max_workers=2, max_queue=2)
    release = threading.Event()
    policy = _pool_policy(pool, _blocking_resolver(release), dns_timeout_s=0.3)
    try:
        for _ in range(20):
            t0 = time.monotonic()
            with pytest.raises(PostgresDnsUnavailableError):
                policy.validate_and_pin("db.example.com", 5432, "verify-full")
            assert time.monotonic() - t0 < 2.0  # bounded caller latency
            assert pool.live_worker_count() <= pool.max_workers  # fixed pool
            assert pool.queued() <= pool.max_queue  # bounded queue
        # 20 timed-out calls left exactly the fixed pool (not ~20 threads), all daemon.
        assert pool.live_worker_count() == 2
        assert all(t.daemon for t in threading.enumerate() if t.name.startswith("pg-dns-worker"))
    finally:
        release.set()


def test_blocked_lookup_caller_returns_within_dns_timeout_plus_margin() -> None:
    pool = BoundedResolverPool(max_workers=2, max_queue=2)
    release = threading.Event()
    policy = _pool_policy(pool, _blocking_resolver(release), dns_timeout_s=0.5)
    try:
        t0 = time.monotonic()
        with pytest.raises(PostgresDnsUnavailableError):
            policy.validate_and_pin("db.example.com", 5432, "verify-full")
        assert time.monotonic() - t0 < 2.0  # ~0.5s bound, not ~30s
    finally:
        release.set()


def test_capacity_exhaustion_fails_fast() -> None:
    pool = BoundedResolverPool(max_workers=2, max_queue=2)
    release = threading.Event()
    # Long caller timeout so the fast-fail is due to saturation, not the deadline.
    policy = _pool_policy(pool, _blocking_resolver(release), dns_timeout_s=5)
    threads = _saturate(pool, policy, n=4)
    try:
        assert pool.live_worker_count() <= pool.max_workers
        assert pool.queued() <= pool.max_queue
        t0 = time.monotonic()
        with pytest.raises(PostgresDnsUnavailableError):
            policy.validate_and_pin("other.example.com", 5432, "verify-full")
        assert time.monotonic() - t0 < 0.5  # admission rejected promptly, no waiting
    finally:
        release.set()
        for t in threads:
            t.join(2)


def test_capacity_recovers_after_blocked_lookups_release() -> None:
    pool = BoundedResolverPool(max_workers=2, max_queue=2)
    release = threading.Event()
    blocked = _pool_policy(pool, _blocking_resolver(release), dns_timeout_s=5)
    threads = _saturate(pool, blocked, n=4)
    release.set()
    for t in threads:
        t.join(3)
    # The same pool now resolves a fresh safe host successfully.
    ok = _pool_policy(pool, _resolver({"good.example.com": ["93.184.216.34"]}), dns_timeout_s=2)
    dest = ok.validate_and_pin("good.example.com", 5432, "verify-full")
    assert dest.hostaddr == "93.184.216.34"


def test_late_dns_result_never_initiates_a_connection(listener: SimpleNamespace) -> None:
    pool = BoundedResolverPool(max_workers=1, max_queue=1)
    release = threading.Event()
    resolved = threading.Event()

    def late_resolver(_host: str) -> list[str]:
        release.wait(30)  # completes only AFTER the caller has timed out
        resolved.set()
        return ["127.0.0.1"]  # a late answer pointing at the controlled listener

    config = pg.parse_config(
        {
            "host": "127.0.0.1",
            "port": listener.port,
            "database": "d",
            "sslmode": "disable",
            "connect_timeout_s": 2,
        }
    )
    secret = pg.parse_secret('{"username": "dummy", "password": "dummy-PW-must-not-leak"}')
    policy = PostgresDestinationPolicy(
        require_public=False,
        require_verify_full=False,
        resolver=late_resolver,
        dns_timeout_s=0.3,
        resolver_pool=pool,
    )
    # DNS times out -> transient, mapped by the connector to PostgresUnavailableError.
    with (
        pytest.raises(pg.PostgresUnavailableError),
        pg._read_only_connection(config, secret, policy),
    ):
        pass
    # Release the late resolution; it completes but the caller already returned.
    release.set()
    assert resolved.wait(3)
    time.sleep(0.3)  # give any erroneous connection a chance to appear
    listener.thread.join(timeout=1)
    assert listener.state.accepted is False  # no connection after caller timeout
    assert listener.state.received == b""  # no credential bytes transmitted


def test_dns_timeout_is_transient_but_policy_rejection_is_deterministic() -> None:
    pool = BoundedResolverPool(max_workers=1, max_queue=1)
    release = threading.Event()
    # Transient: a DNS timeout is retryable.
    transient = _pool_policy(pool, _blocking_resolver(release), dns_timeout_s=0.2)
    try:
        with pytest.raises(PostgresDnsUnavailableError):
            transient.validate_and_pin("db.example.com", 5432, "verify-full")
    finally:
        release.set()
    # PostgresDnsUnavailableError is NOT a deterministic ToolExecutionError.
    assert not issubclass(PostgresDnsUnavailableError, ToolExecutionError)
    # Deterministic: an unsafe RESOLVED address is a policy rejection (not DNS).
    deterministic = PostgresDestinationPolicy(
        require_public=True,
        require_verify_full=True,
        resolver=_resolver({"db.example.com": ["10.0.0.9"]}),
    )
    with pytest.raises(PostgresDestinationError):
        deterministic.validate_and_pin("db.example.com", 5432, "verify-full")


def test_concurrent_resolutions_do_not_cross_contaminate() -> None:
    pool = BoundedResolverPool(max_workers=4, max_queue=16)
    mapping = {
        "a.example.com": ["93.184.216.34"],
        "b.example.com": ["93.184.216.35"],
        "c.example.com": ["93.184.216.36"],
    }

    def slow_resolver(host: str) -> list[str]:
        time.sleep(0.02)
        return mapping[host]

    policy = _pool_policy(pool, slow_resolver, dns_timeout_s=3)
    got: list[tuple[str, str]] = []
    lock = threading.Lock()

    def _call(host: str) -> None:
        addr = policy.validate_and_pin(host, 5432, "verify-full").hostaddr
        with lock:
            got.append((host, addr))

    threads = [threading.Thread(target=_call, args=(h,)) for h in mapping for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)
    assert len(got) == 12
    for host, addr in got:
        assert addr == mapping[host][0]  # each caller got ITS OWN host's answer
