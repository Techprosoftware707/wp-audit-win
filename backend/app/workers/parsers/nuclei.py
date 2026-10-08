"""Pure parsing for nuclei JSONL output (unit-testable)."""

from __future__ import annotations

import json

from app.models.enums import Severity

_SEV_MAP = {
    "critical": Severity.CRITICAL.value,
    "high": Severity.HIGH.value,
    "medium": Severity.MEDIUM.value,
    "low": Severity.LOW.value,
    "info": Severity.INFO.value,
    "unknown": Severity.INFO.value,
}


def map_severity(value: str) -> str:
    return _SEV_MAP.get((value or "").lower(), Severity.INFO.value)


def _cve_from(info: dict) -> str:
    classification = info.get("classification") or {}
    cves = classification.get("cve-id") or classification.get("cve_id") or []
    if isinstance(cves, list) and cves:
        return str(cves[0]).upper()
    if isinstance(cves, str) and cves:
        return cves.upper()
    return ""


def parse_jsonl(text: str) -> list[dict]:
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except (ValueError, json.JSONDecodeError):
            continue
        info = obj.get("info", {}) or {}
        out.append(
            {
                "template_id": obj.get("template-id") or obj.get("templateID") or "",
                "name": info.get("name", ""),
                "severity": info.get("severity", "info"),
                "description": info.get("description", "") or "",
                "cve": _cve_from(info),
                "matched_at": obj.get("matched-at") or obj.get("matched_at") or obj.get("host", ""),
                "extracted": obj.get("extracted-results") or obj.get("extracted_results") or "",
            }
        )
    return out
