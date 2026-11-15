"""Authorization guard: only scan systems you own or are permitted to test."""
import ipaddress
import socket
from urllib.parse import urlparse


class UnauthorizedTarget(Exception):
    pass


def _is_local(addr):
    ip = ipaddress.ip_address(addr)
    return ip.is_loopback or ip.is_private


def check_target(url_or_host, authorized=False):
    """Allow loopback / private-range targets by default.

    Anything else (a public IP or hostname) requires the explicit
    --i-am-authorized flag, which asserts you have written permission.
    """
    host = urlparse(url_or_host).hostname if "//" in url_or_host else url_or_host
    if not host:
        raise UnauthorizedTarget(f"could not determine host from {url_or_host!r}")
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise UnauthorizedTarget(f"cannot resolve {host!r}: {exc}") from exc
    if all(_is_local(a) for a in addrs):
        return host
    if authorized:
        return host
    raise UnauthorizedTarget(
        f"{host} is not a loopback/private address. Scan only systems you own or "
        "have written permission to test; pass --i-am-authorized to confirm.")
