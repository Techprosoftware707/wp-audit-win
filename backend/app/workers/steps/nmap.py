"""Nmap step — authorized service discovery.

Skips when the nmap binary is absent or when intensity is 'passive'. Uses a
non-intrusive connect/top-ports scan and records discovered services as assets.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from app.models.enums import AssetType
from app.workers import tools
from app.workers.base import StepContext

_PORT_RE = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?$")


def run(ctx: StepContext) -> dict:
    if not tools.intensity_at_least(ctx.intensity, "safe"):
        return {"skipped": True, "reason": "intensity 'passive' skips active port scanning"}
    binary = tools.which("nmap")
    if not binary:
        return {"skipped": True, "reason": "nmap not installed on this worker"}

    host = urlparse(ctx.target.base_url).hostname or ctx.target.host

    # -Pn (no ping), connect scan (-sT, no raw sockets/root), modest timing,
    # top 100 ports, service/version detection light.
    args = [binary, "-Pn", "-sT", "-T3", "--top-ports", "100", "-sV", "--version-light", host]
    rc, out, err = tools.run_cmd(args, timeout=240)
    if rc not in (0,) and not out:
        return {"skipped": True, "reason": f"nmap failed: {err.strip()[:200]}"}

    services = []
    for line in out.splitlines():
        m = _PORT_RE.match(line.strip())
        if not m:
            continue
        port, proto, state, service, extra = m.groups()
        if state != "open":
            continue
        value = f"{host}:{port}/{proto}"
        ctx.add_asset(
            AssetType.SERVICE.value,
            value,
            meta={"service": service, "state": state, "version": (extra or "").strip()},
        )
        services.append({"port": int(port), "proto": proto, "service": service})

    ctx.add_evidence(
        kind="output", request=" ".join(args), response=out[:16000], meta={"tool": "nmap"}
    )
    return {"open_services": len(services), "services": services[:50]}
