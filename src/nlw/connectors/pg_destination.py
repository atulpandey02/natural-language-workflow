"""PostgreSQL destination egress + TLS policy (M11.5 P1B, ADR-009/ADR-014).

Deterministic, reusable validation applied BEFORE any network/authentication
bytes are sent to an external Postgres. It:

1. rejects unsafe host forms (Unix sockets, multi-host/DSN strings);
2. enforces the port policy;
3. (production/staging) blocks platform-internal service names;
4. resolves every A/AAAA answer with a bounded timeout;
5. (production/staging) rejects if ANY resolved address is non-global and not in
   the operator CIDR allowlist — never "pick the one safe answer";
6. (production/staging) requires ``sslmode=verify-full``;
7. returns a pinned destination: the ORIGINAL hostname (for TLS SNI / certificate
   verification) plus the validated IP as ``hostaddr`` (the TCP target), so libpq
   performs no second, unvalidated DNS resolution (DNS-rebinding safe).

Local/dev (the ``app_env`` gate) may target private fixtures and honour the
connector's ``sslmode`` — this seam is dependency-injected/operator-controlled
and can NEVER be enabled by a connector field, API request, planner output or
tenant setting. Production fails closed.
"""

import concurrent.futures
import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass

from nlw.connectors.http_guard import is_public_ip
from nlw.registry.registry import ToolExecutionError

# host -> resolved IP strings. Injectable so tests are deterministic.
Resolver = Callable[[str], list[str]]

# Stable error messages (P1B F2) — no internal address/DSN/port-state leakage.
_ERR_DEST = "POSTGRES_DESTINATION_NOT_ALLOWED"
_ERR_TLS = "POSTGRES_TLS_POLICY_VIOLATION"
_ERR_PORT = "POSTGRES_PORT_NOT_ALLOWED"

# Platform-internal service names that must never be a tenant destination in
# production (search domains / container DNS could otherwise make them reachable).
_INTERNAL_HOSTNAMES = frozenset(
    {
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
    }
)

_DEFAULT_PG_PORT = 5432
_DNS_TIMEOUT_S = 5


class PostgresDestinationError(ToolExecutionError):
    """A destination violates the egress policy — deterministic (not retryable)."""


class PostgresTlsPolicyError(ToolExecutionError):
    """The TLS posture violates policy — deterministic (not retryable)."""


@dataclass(frozen=True)
class ValidatedDestination:
    """A validated destination. ``host`` is preserved for TLS verification;
    ``hostaddrs`` are the validated TCP targets to attempt (in order, all already
    validated so retrying a later one is DNS-rebinding safe); ``sslmode`` is the
    effective mode."""

    host: str
    hostaddrs: tuple[str, ...]
    port: int
    sslmode: str

    @property
    def hostaddr(self) -> str:
        """The primary pinned address."""
        return self.hostaddrs[0]


def bounded_resolver(host: str, timeout_s: int = _DNS_TIMEOUT_S) -> list[str]:
    """Resolve all A/AAAA answers with a hard timeout so DNS cannot block
    indefinitely. Returns de-duplicated IP strings."""

    def _resolve() -> list[str]:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return [str(info[4][0]) for info in infos]

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_resolve)
        try:
            ips = future.result(timeout=timeout_s)
        except concurrent.futures.TimeoutError as exc:
            raise PostgresDestinationError(_ERR_DEST) from exc
        except OSError as exc:  # resolution failed
            raise PostgresDestinationError(_ERR_DEST) from exc
    # Preserve order, drop duplicates.
    seen: dict[str, None] = {}
    for ip in ips:
        seen.setdefault(ip, None)
    return list(seen)


def _looks_like_plain_host(host: str) -> bool:
    """Reject Unix-socket paths and DSN/multi-host strings — only a bare
    hostname or IP literal is a valid destination."""
    if not host or host != host.strip():
        return False
    # Unix socket directory, DSN pieces, multi-host lists, credentials, schemes.
    bad = ("/", "\\", " ", "\t", ",", "=", "@", "?")
    if any(token in host for token in bad):
        return False
    return not ("://" in host or host.startswith("."))


@dataclass(frozen=True)
class PostgresDestinationPolicy:
    """Deterministic destination/TLS policy. Built from Settings; injectable in
    tests. ``require_public``/``require_verify_full`` are the production gates."""

    require_public: bool
    require_verify_full: bool
    allow_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    extra_allowed_ports: frozenset[int] = frozenset()
    resolver: Resolver = bounded_resolver
    dns_timeout_s: int = _DNS_TIMEOUT_S

    @classmethod
    def from_settings(
        cls, settings: object, resolver: Resolver | None = None
    ) -> "PostgresDestinationPolicy":
        app_env = getattr(settings, "app_env", "local")
        strict = app_env in ("staging", "production")
        raw_allow = list(getattr(settings, "postgres_destination_allowlist", []) or [])
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for entry in raw_allow:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError as exc:  # operator misconfiguration -> fail closed
                raise PostgresDestinationError(_ERR_DEST) from exc
        ports = frozenset(
            int(p) for p in getattr(settings, "postgres_extra_allowed_ports", []) or []
        )
        return cls(
            require_public=strict,
            require_verify_full=strict,
            allow_networks=tuple(networks),
            extra_allowed_ports=ports,
            resolver=resolver or bounded_resolver,
        )

    def _ip_allowed(self, ip_str: str) -> bool:
        if is_public_ip(ip_str):
            return True
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(ip in net for net in self.allow_networks)

    def _effective_sslmode(self, requested: str) -> str:
        if self.require_verify_full:
            if requested != "verify-full":
                # Tenant/config cannot weaken TLS in production/staging.
                raise PostgresTlsPolicyError(_ERR_TLS)
            return "verify-full"
        return requested

    def _check_port(self, port: int) -> None:
        if port == _DEFAULT_PG_PORT:
            return
        if self.require_public and port not in self.extra_allowed_ports:
            raise PostgresDestinationError(_ERR_PORT)

    def validate_and_pin(self, host: str, port: int, sslmode: str) -> ValidatedDestination:
        """Validate the destination and TLS posture and return the validated,
        pinned targets.

        Order matters: every deterministic policy check happens BEFORE any DNS or
        network activity that could send bytes. Raises before a connection is
        attempted when the destination is unsafe. Prefers IPv4 for determinism;
        every returned address is already validated, so attempting a later one
        never re-resolves (rebinding safe).
        """
        if not _looks_like_plain_host(host):
            raise PostgresDestinationError(_ERR_DEST)
        self._check_port(port)
        effective_sslmode = self._effective_sslmode(sslmode)
        if self.require_public and host.lower() in _INTERNAL_HOSTNAMES:
            raise PostgresDestinationError(_ERR_DEST)

        ips = self.resolver(host)
        if not ips:
            raise PostgresDestinationError(_ERR_DEST)
        if self.require_public:
            # Fail closed if ANY answer is unsafe (rebinding / mixed-answer safe).
            for ip in ips:
                if not self._ip_allowed(ip):
                    raise PostgresDestinationError(_ERR_DEST)

        def _is_v4(ip: str) -> bool:
            try:
                return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
            except ValueError:
                return False

        ordered = tuple(sorted(ips, key=lambda ip: 0 if _is_v4(ip) else 1))
        return ValidatedDestination(
            host=host, hostaddrs=ordered, port=port, sslmode=effective_sslmode
        )
