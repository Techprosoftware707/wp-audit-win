"""OWASP ZAP step — spider + passive (and, at higher intensity, active) scanning.

Talks to a ZAP daemon over its JSON API (the `zap` service on the scanner
network). Skips gracefully when ZAP is unreachable. Active scanning only runs at
intensity 'standard' or above and only against the authorized target.
"""

from __future__ import annotations

import time

import httpx

from app.core.config import settings
from app.workers import tools
from app.workers.base import StepContext
from app.workers.parsers import zap as zap_parser


def _zap_url(path: str) -> str:
    return f"http://{settings.zap_host}:{settings.zap_port}{path}"


def _call(client: httpx.Client, path: str, **params) -> dict | None:
    params.setdefault("apikey", settings.secret_key)
    try:
        r = client.get(_zap_url(path), params=params, timeout=30)
        if r.status_code == 200:
            return r.json()
    except httpx.HTTPError:
        return None
    return None


def run(ctx: StepContext) -> dict:
    base = ctx.target.base_url.rstrip("/")
    try:
        with httpx.Client(timeout=15) as probe:
            version = _call(probe, "/JSON/core/view/version/")
    except Exception:  # noqa: BLE001
        version = None
    if not version:
        return {
            "skipped": True,
            "reason": "ZAP engine not reachable (enable the 'scanners' profile)",
        }

    with httpx.Client(timeout=60) as client:
        # Spider (bounded).
        spider = _call(client, "/JSON/spider/action/scan/", url=base, maxChildren=20, recurse=True)
        scan_id = (spider or {}).get("scan")
        for _ in range(40):  # ~up to 2 min
            status = _call(client, "/JSON/spider/view/status/", scanId=scan_id)
            if not status or status.get("status") == "100":
                break
            time.sleep(3)

        # Let the passive scanner drain.
        for _ in range(20):
            rec = _call(client, "/JSON/pscan/view/recordsToScan/")
            if not rec or rec.get("recordsToScan") in ("0", 0):
                break
            time.sleep(2)

        # Optional active scan at higher intensity.
        active_ran = False
        if tools.intensity_at_least(ctx.intensity, "standard"):
            ascan = _call(
                client, "/JSON/ascan/action/scan/", url=base, recurse=True, inScopeOnly=False
            )
            aid = (ascan or {}).get("scan")
            if aid is not None:
                active_ran = True
                for _ in range(60):  # ~up to 3 min
                    st = _call(client, "/JSON/ascan/view/status/", scanId=aid)
                    if not st or st.get("status") == "100":
                        break
                    time.sleep(3)

        alerts = _call(client, "/JSON/core/view/alerts/", baseurl=base, start=0, count=500) or {}

    parsed = zap_parser.parse_alerts(alerts.get("alerts", []))
    created = 0
    for a in parsed:
        dedup = f"sig:zap:{a['plugin_id']}:{a['uri']}"
        f = ctx.add_finding(
            title=a["name"],
            severity=a["severity"],
            dedup_key=dedup,
            detector="zap",
            description=a["description"],
            cwe=f"CWE-{a['cwe']}" if a["cwe"] else "",
            affected_asset=a["uri"],
            verification_status="likely_vulnerable",
        )
        ctx.add_evidence(
            finding=f,
            kind="request_response",
            request=f"{a['method']} {a['uri']}",
            response=(a.get("evidence", "") + "\n" + a.get("solution", ""))[:4000],
            meta={"tool": "zap", "plugin_id": a["plugin_id"]},
        )
        created += 1

    return {"spidered": True, "active_scan": active_ran, "alerts": created}
