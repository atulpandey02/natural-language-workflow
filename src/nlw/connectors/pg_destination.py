"""PostgreSQL destination egress + TLS policy (M11.5 P1B, ADR-009/ADR-014).

Deterministic, reusable validation applied BEFORE any network/authentication
bytes are sent to an external Postgres. It:

1. rejects unsafe host forms (Unix sockets, multi-host/DSN strings);
2. enforces the port policy;
3. (production/staging) blocks platform-internal service names;
4. resolves every A/AAAA answer with a HARD wall-clock bound;
5. (production/staging) rejects if ANY resolved address is non-global and not in
   the operator CIDR allowlist — never "pick the one safe answer";
6. (production/staging) requires ``sslmode=verify-full`` and supplies the CA trust
   (``sslrootcert``, default libpq ``system`` = the OS trust store);
7. returns a pinned destination: the ORIGINAL hostname (for TLS SNI / certificate
   verification) plus the validated IP as ``hostaddr`` (the TCP target), so libpq
   performs no second, unvalidated DNS resolution (DNS-rebinding safe).

DNS bound: resolution is delegated to a FIXED, shared pool of daemon workers with
a bounded task queue (``BoundedResolverPool``). This bounds three things at once:
caller latency (a caller waits at most ``dns_timeout_s``), resolver RESOURCE
consumption (the number of resolver threads never exceeds ``max_workers`` and the
queue never exceeds ``max_queue`` regardless of request volume — no new thread per
request), and worker shutdown (all workers are daemons). A timed-out caller
abandons only its result slot, never a thread; a late result is discarded and can
never trigger a connection; when capacity is exhausted the caller fails fast with
a sanitized transient error. (A ``ThreadPoolExecutor`` is deliberately NOT used:
its context-manager exit joins still-blocked workers, and a plain thread-per-call
leaks unbounded abandoned threads.)

Local/dev (the ``app_env`` gate) may target private fixtures and honour the
connector's ``sslmode`` — this seam is dependency-injected/operator-controlled
and can NEVER be enabled by a connector field, API request, planner output or
tenant setting. Production fails closed.
"""

import ipaddress
import queue
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from nlw.connectors.http_guard import is_public_ip
from nlw.registry.registry import ToolExecutionError

# host -> resolved IP strings. May block; the pool bounds it. Injectable so
# tests are deterministic.
Resolver = Callable[[str], list[str]]

# Stable error messages (P1B F2) — no internal address/DSN/port-state leakage.
_ERR_DEST = "POSTGRES_DESTINATION_NOT_ALLOWED"
_ERR_TLS = "POSTGRES_TLS_POLICY_VIOLATION"
_ERR_PORT = "POSTGRES_PORT_NOT_ALLOWED"
_ERR_DNS = "POSTGRES_DNS_UNAVAILABLE"

# Conservative pilot resource bounds for external-DB DNS resolution.
_MAX_DNS_WORKERS = 4
_MAX_DNS_QUEUE = 16

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
# libpq sslmodes that perform certificate verification and therefore need a CA.
_VERIFY_SSLMODES = frozenset({"verify-ca", "verify-full"})


class PostgresDestinationError(ToolExecutionError):
    """A destination violates the egress policy — deterministic (not retryable)."""


class PostgresTlsPolicyError(ToolExecutionError):
    """The TLS posture violates policy — deterministic (not retryable)."""


class PostgresDnsUnavailableError(Exception):
    """DNS timed out, failed, or the resolver pool was at capacity — TRANSIENT /
    RETRYABLE infrastructure, NOT a deterministic policy rejection. It is a plain
    Exception (not a ``ToolExecutionError``) so the engine retries it; the
    connector maps it to the sanitized ``PostgresUnavailableError``."""


def system_resolver(host: str) -> list[str]:
    """Resolve all A/AAAA answers via ``getaddrinfo`` (may block; the resolver
    pool applies the wall-clock + resource bound)."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return [str(info[4][0]) for info in infos]


@dataclass
class _ResolveTask:
    host: str
    resolver: Resolver
    done: threading.Event
    result: dict[str, object]


class BoundedResolverPool:
    """A FIXED pool of daemon workers draining a BOUNDED queue.

    Guarantees, independent of request volume:
    - the number of resolver threads never exceeds ``max_workers`` (no thread per
      request); workers are started once, lazily, and are daemons;
    - the pending queue never exceeds ``max_queue``;
    - a timed-out caller abandons only its result slot (no thread is created or
      leaked); the worker later fills the abandoned slot and it is discarded, so a
      late result can never initiate a connection;
    - when both workers and queue are saturated, admission fails fast with
      ``PostgresDnsUnavailableError`` (transient) — no network, no credentials.
    """

    def __init__(
        self, max_workers: int = _MAX_DNS_WORKERS, max_queue: int = _MAX_DNS_QUEUE
    ) -> None:
        self.max_workers = max_workers
        self.max_queue = max_queue
        self._queue: queue.Queue[_ResolveTask] = queue.Queue(maxsize=max_queue)
        self._lock = threading.Lock()
        self._started = False
        self._workers: list[threading.Thread] = []

    def _ensure_workers(self) -> None:
        with self._lock:
            if self._started:
                return
            for i in range(self.max_workers):
                worker = threading.Thread(
                    target=self._worker, name=f"pg-dns-worker-{id(self)}-{i}", daemon=True
                )
                self._workers.append(worker)
                worker.start()
            self._started = True

    def _worker(self) -> None:
        while True:
            task = self._queue.get()
            try:
                task.result["ips"] = task.resolver(task.host)
            except BaseException as exc:  # noqa: BLE001 - recorded, mapped below
                task.result["err"] = exc
            finally:
                task.done.set()
                self._queue.task_done()

    def resolve(self, host: str, resolver: Resolver, timeout_s: float) -> list[str]:
        self._ensure_workers()
        task = _ResolveTask(host=host, resolver=resolver, done=threading.Event(), result={})
        try:
            self._queue.put_nowait(task)  # fail fast when saturated
        except queue.Full as exc:
            raise PostgresDnsUnavailableError(_ERR_DNS) from exc
        if not task.done.wait(timeout_s):
            # Caller abandons only this result slot; no thread was created for it.
            raise PostgresDnsUnavailableError(_ERR_DNS)
        if "err" in task.result:
            raise PostgresDnsUnavailableError(_ERR_DNS)
        ips = task.result.get("ips")
        if not isinstance(ips, list):
            raise PostgresDnsUnavailableError(_ERR_DNS)
        seen: dict[str, None] = {}
        for ip in ips:
            seen.setdefault(str(ip), None)
        return list(seen)

    def live_worker_count(self) -> int:
        """Live workers belonging to THIS pool (never exceeds ``max_workers``)."""
        return sum(1 for t in self._workers if t.is_alive())

    def queued(self) -> int:
        return self._queue.qsize()


# Shared, process-wide pool: the resource bound is global, not per-request.
_DEFAULT_POOL = BoundedResolverPool()


@dataclass(frozen=True)
class ValidatedDestination:
    """A validated destination. ``host`` is preserved for TLS verification;
    ``hostaddrs`` are the validated TCP targets to attempt (in order, all already
    validated so retrying a later one is DNS-rebinding safe); ``sslmode`` is the
    effective mode; ``sslrootcert`` is the CA trust source (None for plaintext
    modes, ``system`` or an operator path for verify modes)."""

    host: str
    hostaddrs: tuple[str, ...]
    port: int
    sslmode: str
    sslrootcert: str | None = None

    @property
    def hostaddr(self) -> str:
        """The primary pinned address."""
        return self.hostaddrs[0]


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
    resolver: Resolver = system_resolver
    dns_timeout_s: float = _DNS_TIMEOUT_S
    ssl_root_cert: str | None = None
    resolver_pool: BoundedResolverPool = field(default=_DEFAULT_POOL)

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
            resolver=resolver or system_resolver,
            ssl_root_cert=getattr(settings, "postgres_ssl_root_cert", None),
        )

    def _resolve_bounded(self, host: str) -> list[str]:
        """Resolve via the bounded pool. Raises ``PostgresDnsUnavailableError``
        (transient) on timeout, resolution failure, or pool saturation — never a
        deterministic policy error, and never after a connection attempt."""
        return self.resolver_pool.resolve(host, self.resolver, self.dns_timeout_s)

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

    def _effective_sslrootcert(self, effective_sslmode: str) -> str | None:
        if effective_sslmode not in _VERIFY_SSLMODES:
            return None
        # Operator override (e.g. a test CA or a specific bundle path) else the
        # OS trust store via libpq's "system" (libpq >= 16).
        return self.ssl_root_cert or "system"

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

        ips = self._resolve_bounded(host)
        if not ips:
            # Resolved to nothing: a resolution outcome, not a policy violation.
            raise PostgresDnsUnavailableError(_ERR_DNS)
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
            host=host,
            hostaddrs=ordered,
            port=port,
            sslmode=effective_sslmode,
            sslrootcert=self._effective_sslrootcert(effective_sslmode),
        )
