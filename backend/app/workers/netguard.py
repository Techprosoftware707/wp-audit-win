"""Network scope guard for target-facing HTTP.

The authorization's allowed scope is the single source of truth: a request hop
(including every redirect) is permitted only if its host is in scope. This
blocks both SSRF (e.g. a redirect to 169.254.169.254 cloud metadata, which is
never in scope) and scope-escape (a redirect to an unrelated host). Authorized
internal/loopback targets still work because the operator put them in scope.

As defence-in-depth against DNS-rebinding on wildcard scopes, link-local /
multicast / unspecified resolved addresses are refused even for an in-scope
hostname unless the scope lists that exact IP/CIDR.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from app.services.authorization import host_in_scope


def _resolve(host: str) -> list[str]:
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    except OSError:
        return []


def _hard_blocked(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved


def _scope_has_exact_ip(scope: list[str], ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in scope or []:
        try:
            if addr in ipaddress.ip_network(entry.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def host_allowed(host: str, scope: list[str]) -> tuple[bool, str]:
    """Return (allowed, reason). An empty host is denied."""
    if not host:
        return False, "no host"
    if not scope:
        # No scope context supplied — fail closed for anything that resolves to a
        # link-local/metadata range; otherwise allow (caller already authorized).
        for ip in _resolve(host):
            if _hard_blocked(ip):
                return False, f"blocked address {ip}"
        return True, ""
    if not host_in_scope(host, scope):
        return False, "host not in authorized scope"
    for ip in _resolve(host):
        if _hard_blocked(ip) and not _scope_has_exact_ip(scope, ip):
            return False, f"in-scope host resolves to blocked address {ip}"
    return True, ""


def url_allowed(url: str, scope: list[str]) -> tuple[bool, str]:
    return host_allowed(urlparse(url).hostname or "", scope)
