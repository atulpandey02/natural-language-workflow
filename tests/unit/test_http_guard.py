"""SSRF guard matrix (M7, ADR-014). Pure unit tests + DI transport pinning."""

import httpx
import pytest

from nlw.connectors.http_guard import (
    GuardedTransport,
    SsrfError,
    is_public_ip,
    resolve_and_validate,
    validate_url,
)


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",  # loopback
        "10.0.0.5",  # RFC1918
        "172.16.0.1",  # RFC1918
        "192.168.1.1",  # RFC1918
        "169.254.169.254",  # cloud metadata (link-local)
        "100.64.0.1",  # CGNAT
        "0.0.0.0",  # unspecified
        "::1",  # IPv6 loopback
        "fe80::1",  # IPv6 link-local
        "fc00::1",  # IPv6 ULA
        "::ffff:10.0.0.1",  # IPv4-mapped private IPv6
        "224.0.0.1",  # multicast
    ],
)
def test_blocks_non_global_ips(ip: str) -> None:
    assert is_public_ip(ip) is False


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1::1"])
def test_allows_global_ips(ip: str) -> None:
    assert is_public_ip(ip) is True


def test_validate_url_requires_https() -> None:
    with pytest.raises(SsrfError):
        validate_url("http://example.com/hook")


def test_validate_url_rejects_userinfo() -> None:
    with pytest.raises(SsrfError):
        validate_url("https://user:pass@example.com/hook")


def test_validate_url_rejects_fragment() -> None:
    with pytest.raises(SsrfError):
        validate_url("https://example.com/hook#frag")


def test_validate_url_ok() -> None:
    assert validate_url("https://example.com:8443/hook") == ("example.com", 8443)


def test_resolve_and_validate_blocks_private() -> None:
    with pytest.raises(SsrfError):
        resolve_and_validate("evil.example", lambda _h: ["10.1.2.3"])


def test_resolve_and_validate_blocks_mixed() -> None:
    # Any private result fails closed (rebinding defense).
    with pytest.raises(SsrfError):
        resolve_and_validate("mixed.example", lambda _h: ["8.8.8.8", "127.0.0.1"])


def test_resolve_and_validate_allows_public() -> None:
    assert resolve_and_validate("good.example", lambda _h: ["8.8.8.8"]) == "8.8.8.8"


def test_guarded_transport_blocks_private_before_delegating() -> None:
    called = {"n": 0}

    def _inner(_request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200)

    transport = GuardedTransport(
        resolver=lambda _h: ["10.0.0.1"], inner=httpx.MockTransport(_inner)
    )
    with httpx.Client(transport=transport) as client, pytest.raises(SsrfError):
        client.post("https://internal.example/hook", json={})
    assert called["n"] == 0  # never reached the network


def test_guarded_transport_pins_validated_ip() -> None:
    seen: dict[str, str] = {}

    def _inner(request: httpx.Request) -> httpx.Response:
        seen["host_url"] = request.url.host
        seen["host_header"] = request.headers.get("Host", "")
        seen["sni"] = request.extensions.get("sni_hostname", "")
        return httpx.Response(200)

    transport = GuardedTransport(
        resolver=lambda _h: ["93.184.216.34"], inner=httpx.MockTransport(_inner)
    )
    with httpx.Client(transport=transport) as client:
        client.post("https://example.com/hook", json={})
    # Connection pinned to the validated IP; TLS SNI + Host keep the hostname.
    assert seen["host_url"] == "93.184.216.34"
    assert seen["host_header"] == "example.com"
    assert seen["sni"] == "example.com"
