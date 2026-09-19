"""Outbound HTTP SSRF defense for action connectors (M7, ADR-014).

Enforced at connect time, not merely pre-flight:
- HTTPS only; reject userinfo and fragments in the URL.
- Resolve the host once, validate that EVERY resolved address is global/public
  (block loopback, RFC1918, CGNAT, link-local incl. cloud metadata, ULA,
  multicast, reserved, and IPv4-mapped-private IPv6), then PIN the connection to
  a validated IP (no re-resolution -> DNS-rebinding safe) while keeping TLS
  SNI/Host = the original hostname so certificate verification succeeds.
- Redirects are disabled by the caller (any 3xx is a deterministic failure).

The resolver and the inner transport are INJECTABLE so tests can exercise the
policy deterministically. There is NO production configuration/env switch that
weakens SSRF protection.
"""

import ipaddress
import socket
from collections.abc import Callable

import httpx

# host -> list of resolved IP strings.
Resolver = Callable[[str], list[str]]


class SsrfError(Exception):
    """A destination violated the outbound-HTTP safety policy (deterministic)."""


def _default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return [str(info[4][0]) for info in infos]


def is_public_ip(ip_str: str) -> bool:
    """True only for global unicast addresses safe to contact."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:10.0.0.1) so private v4 can't hide.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False
    # CGNAT 100.64.0.0/10 is not flagged private by ipaddress; block explicitly.
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return ip.is_global


def validate_url(url: str) -> tuple[str, int]:
    """Validate scheme/userinfo/fragment and return (host, port). No DNS here."""
    try:
        parsed = httpx.URL(url)
    except Exception as exc:  # malformed URL
        raise SsrfError("invalid destination URL") from exc
    if parsed.scheme != "https":
        raise SsrfError("only https destinations are allowed")
    if parsed.username or parsed.password:
        raise SsrfError("URL userinfo is not allowed")
    if parsed.fragment:
        raise SsrfError("URL fragment is not allowed")
    if not parsed.host:
        raise SsrfError("URL host is required")
    return parsed.host, parsed.port or 443


def resolve_and_validate(host: str, resolver: Resolver) -> str:
    """Resolve ``host`` and return ONE validated public IP. Raises if any
    resolved address is non-global (fail closed on mixed results)."""
    ips = resolver(host)
    if not ips:
        raise SsrfError(f"host did not resolve: {host}")
    for ip in ips:
        if not is_public_ip(ip):
            raise SsrfError("destination resolves to a non-global address")
    return ips[0]


class GuardedTransport(httpx.BaseTransport):
    """Validates + pins each request to a resolved public IP before delegating.

    Wraps an inner transport (default real; a MockTransport in tests). The SSRF
    policy runs here so it cannot be bypassed by the caller.
    """

    def __init__(
        self,
        resolver: Resolver | None = None,
        inner: httpx.BaseTransport | None = None,
    ) -> None:
        self._resolver = resolver or _default_resolver
        self._inner = inner or httpx.HTTPTransport()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        host, _port = validate_url(str(request.url))
        ip = resolve_and_validate(host, self._resolver)
        # Pin: connect to the validated IP, keep TLS SNI + Host = original host.
        request.url = request.url.copy_with(host=ip)
        request.headers["Host"] = host
        request.extensions = {**request.extensions, "sni_hostname": host}
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()
