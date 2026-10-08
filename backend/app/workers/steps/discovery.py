"""Discovery step — DNS/host + HTTP fingerprint of the base URL.

Passive and safe at every intensity: a handful of GET requests. Records the
host/URL assets, server technologies, security-header posture, and TLS usage.
"""

from __future__ import annotations

import socket
from urllib.parse import urlparse

from app.models.enums import AssetType, Severity, VerificationStatus
from app.workers import http
from app.workers.base import StepContext

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def run(ctx: StepContext) -> dict:
    base = ctx.target.base_url.rstrip("/")
    parsed = urlparse(base)
    host = parsed.hostname or ctx.target.host

    # DNS resolution (best-effort; failure is non-fatal).
    resolved: list[str] = []
    try:
        infos = socket.getaddrinfo(host, None)
        resolved = sorted({i[4][0] for i in infos})
    except OSError:
        resolved = []

    ctx.add_asset(AssetType.HOST.value, host, meta={"addresses": resolved, "scheme": parsed.scheme})

    resp = http.fetch(base, scope=ctx.scope)
    if not resp.ok:
        ctx.add_evidence(
            kind="http",
            request=f"GET {base}",
            response=resp.error or "no response",
        )
        return {"reachable": False, "error": resp.error, "addresses": resolved}

    ctx.add_asset(AssetType.URL.value, resp.url, meta={"status": resp.status_code})

    # Server tech disclosure.
    server = resp.headers.get("server", "")
    powered = resp.headers.get("x-powered-by", "")
    if server:
        ctx.add_technology(
            "HTTP Server", version="", category="server", source=server, confidence=70
        )
    if powered:
        ctx.add_technology(powered, category="language", source="x-powered-by", confidence=60)

    # Security header posture (aggregated informational finding).
    missing = [label for h, label in SECURITY_HEADERS.items() if h not in resp.headers]
    if missing:
        f = ctx.add_finding(
            title=f"Missing security headers: {', '.join(missing)}",
            severity=Severity.LOW.value if len(missing) >= 3 else Severity.INFO.value,
            dedup_key=f"sig:security-headers:{host}",
            detector="discovery",
            description=(
                "The following recommended HTTP security headers were not observed "
                f"on {resp.url}: {', '.join(missing)}."
            ),
            affected_asset=resp.url,
            cwe="CWE-693",
            verification_status=VerificationStatus.CONFIRMED.value,
            remediation="Add the missing headers at the web server or application layer.",
            auth_required=False,
        )
        f.confirmed = True
        ctx.add_evidence(
            finding=f,
            kind="request_response",
            request=f"GET {base}",
            response=f"HTTP {resp.status_code}",
            http_status=resp.status_code,
            headers=resp.headers,
        )

    tls = parsed.scheme == "https"
    if not tls:
        f = ctx.add_finding(
            title="Site served over plaintext HTTP",
            severity=Severity.MEDIUM.value,
            dedup_key=f"sig:no-tls:{host}",
            detector="discovery",
            description="The base URL uses http:// rather than https://.",
            affected_asset=base,
            cwe="CWE-319",
            verification_status=VerificationStatus.CONFIRMED.value,
            remediation="Serve the site exclusively over HTTPS and enable HSTS.",
            auth_required=False,
        )
        f.confirmed = True

    return {
        "reachable": True,
        "status": resp.status_code,
        "addresses": resolved,
        "server": server,
        "missing_security_headers": missing,
        "tls": tls,
    }
