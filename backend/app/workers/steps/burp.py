"""Burp step — deep web-app testing via the Burp Suite REST API v0.1 (optional).

Burp Suite is commercial and NOT installed as a binary: the REST API ships inside
a licensed Burp Suite Professional / Burp DAST instance that the operator runs and
points ``settings.burp_api_url`` at. This step is OPTIONAL — OWASP ZAP is the free
default already integrated for deep web testing — so it skips unless the operator
has configured ``settings.burp_api_url``.

When configured, it POSTs a scan to ``{base}/{key}/v0.1/scan`` (the API key is a URL
path segment; also sent as a header fallback), polls ``{base}/{key}/v0.1/scan/{id}``
until ``scan_status`` is ``succeeded``/``failed`` (bounded), and maps the returned
issues to findings via the pure :mod:`app.workers.parsers.burp` module. Every HTTP
call uses a short timeout and is wrapped so any error skips gracefully.
"""

from __future__ import annotations

import time

from app.core.config import settings
from app.workers import tools
from app.workers.base import StepContext
from app.workers.parsers import burp as burp_parser

_POLL_MAX_ITERATIONS = 40
_POLL_INTERVAL_SECONDS = 10


def run(ctx: StepContext) -> dict:
    base = (settings.burp_api_url or "").strip()
    if not base:
        return {
            "skipped": True,
            "reason": "Burp not configured (optional; OWASP ZAP is the free default)",
        }
    if not tools.intensity_at_least(ctx.intensity, "standard"):
        return {"skipped": True, "reason": "intensity below 'standard' skips active scanning"}

    try:
        import httpx
    except ImportError:
        return {"skipped": True, "reason": "httpx not installed on this worker"}

    base = base.rstrip("/")
    key = (settings.burp_api_key or "").strip()
    target = ctx.target.base_url.rstrip("/") + "/"
    headers = {"Authorization": f"Bearer {key}", "X-API-Key": key}
    scan_url = f"{base}/{key}/v0.1/scan"

    # 1) Start the scan.
    try:
        resp = httpx.post(scan_url, json={"urls": [target]}, headers=headers, timeout=20)
    except Exception as exc:  # noqa: BLE001 - any client error -> skip gracefully
        return {"skipped": True, "reason": f"Burp start failed: {exc}"[:200]}
    if resp.status_code >= 400:
        return {"skipped": True, "reason": f"Burp start returned HTTP {resp.status_code}"}

    task = burp_parser.task_id_from_location(resp.headers.get("location", ""))
    if not task:
        try:
            task = str((resp.json() or {}).get("task_id") or "")
        except Exception:  # noqa: BLE001 - no/invalid JSON body
            task = ""
    if not task:
        return {"skipped": True, "reason": "Burp did not return a scan task id"}

    # 2) Poll until terminal, bounded.
    poll_url = f"{base}/{key}/v0.1/scan/{task}"
    data: dict = {}
    status = ""
    for _ in range(_POLL_MAX_ITERATIONS):
        try:
            poll = httpx.get(poll_url, headers=headers, timeout=20)
            data = poll.json() or {}
        except Exception as exc:  # noqa: BLE001 - any client error -> skip gracefully
            return {"skipped": True, "reason": f"Burp poll failed: {exc}"[:200]}
        status = (data.get("scan_status") or "").lower()
        if status in ("succeeded", "failed"):
            break
        time.sleep(_POLL_INTERVAL_SECONDS)

    # 3) Map issues to findings.
    issues = burp_parser.parse_issues(data)
    created = 0
    for issue in issues:
        f = ctx.add_finding(
            title=issue["title"],
            severity=issue["severity"],
            dedup_key=issue["dedup_key"],
            detector="burp",
            description=issue["description"],
            affected_asset=issue["url"],
            remediation=issue["remediation"],
            verification_status="likely_vulnerable",
            auth_required=False,
        )
        ctx.add_evidence(
            finding=f,
            kind="output",
            request=(issue["request"] or f"burp scan {target}")[:4000],
            response=(issue["response"] or issue["url"])[:4000],
            meta={
                "tool": "burp",
                "confidence": issue["confidence"],
                "type_index": issue["type_index"],
            },
        )
        created += 1

    return {"findings": created, "scan_status": status, "issues_seen": len(issues)}
