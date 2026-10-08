"""Pure parsing for Burp Suite REST API v0.1 scan JSON (unit-testable).

No I/O: functions take the already-parsed polling response dict (or a raw
``Location`` header string) and return plain dicts/lists. The ``burp`` step
drives the HTTP POST/poll and feeds the parsed JSON object to :func:`parse_issues`.
"""

from __future__ import annotations

import base64

from app.models.enums import Severity

# Burp has no "critical" band; its top severity is "high". "information" is an
# alias for "info"; "false_positive" is dropped (mapped to "").
_SEV_MAP = {
    "high": Severity.HIGH.value,
    "medium": Severity.MEDIUM.value,
    "low": Severity.LOW.value,
    "info": Severity.INFO.value,
    "information": Severity.INFO.value,
    "false_positive": "",
}


def map_severity(value: str) -> str:
    """Normalize a Burp severity to our Severity values ('' means skip)."""
    return _SEV_MAP.get((value or "").strip().lower(), Severity.INFO.value)


def task_id_from_location(location: str) -> str:
    """Extract the trailing task id from a 201 ``Location`` header (e.g. /v0.1/scan/3)."""
    return (location or "").rstrip("/").split("/")[-1] if location else ""


def _decode_segments(segments: object) -> str:
    """Join the base64-decoded ``data`` of request/response segment objects."""
    if not isinstance(segments, list):
        return ""
    parts: list[str] = []
    for seg in segments:
        if not isinstance(seg, dict):
            continue
        data = seg.get("data")
        if not isinstance(data, str) or not data:
            continue
        try:
            parts.append(base64.b64decode(data).decode("utf-8", "replace"))
        except (ValueError, TypeError):
            continue
    return "".join(parts)


def _request_response(issue: dict) -> tuple[str, str]:
    """Pull decoded request/response snippets from the first evidence entry."""
    evidence = issue.get("evidence")
    if not isinstance(evidence, list):
        return "", ""
    for item in evidence:
        if not isinstance(item, dict):
            continue
        rr = item.get("request_response")
        if not isinstance(rr, dict):
            continue
        return _decode_segments(rr.get("request")), _decode_segments(rr.get("response"))
    return "", ""


def parse_issues(data: dict) -> list[dict]:
    """Normalize a v0.1 scan-poll response's ``issue_events`` into finding dicts."""
    out: list[dict] = []
    if not isinstance(data, dict):
        return out
    events = data.get("issue_events")
    if not isinstance(events, list):
        return out
    for event in events:
        if not isinstance(event, dict):
            continue
        etype = event.get("type")
        if etype not in (None, "issue_found"):
            continue
        issue = event.get("issue")
        if not isinstance(issue, dict):
            continue
        name = (issue.get("name") or "").strip()
        if not name:
            continue
        severity = map_severity(issue.get("severity", "info"))
        if not severity:
            continue  # false_positive / unmappable -> drop
        origin = issue.get("origin", "") or ""
        path = issue.get("path", "") or ""
        url = f"{origin}{path}"
        type_index = issue.get("type_index")
        request, response = _request_response(issue)
        out.append(
            {
                "title": name,
                "url": url,
                "origin": origin,
                "path": path,
                "type_index": type_index,
                "severity": severity,
                "confidence": issue.get("confidence", "") or "",
                "description": issue.get("description", "") or "",
                "remediation": issue.get("remediation", "") or "",
                "request": request,
                "response": response,
                "dedup_key": f"sig:burp:{name or type_index}:{url}",
            }
        )
    return out
