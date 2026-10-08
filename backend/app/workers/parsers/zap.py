"""Pure parsing for OWASP ZAP alert JSON (unit-testable)."""

from __future__ import annotations

from app.models.enums import Severity

_RISK_MAP = {
    "high": Severity.HIGH.value,
    "medium": Severity.MEDIUM.value,
    "low": Severity.LOW.value,
    "informational": Severity.INFO.value,
    "info": Severity.INFO.value,
}


def map_risk(risk: str) -> str:
    return _RISK_MAP.get((risk or "").split(" ")[0].lower(), Severity.INFO.value)


def parse_alerts(alerts: list[dict]) -> list[dict]:
    out: list[dict] = []
    for a in alerts or []:
        out.append(
            {
                "name": a.get("alert") or a.get("name", "ZAP alert"),
                "severity": map_risk(a.get("risk", "")),
                "description": (a.get("description", "") or "")[:4000],
                "solution": (a.get("solution", "") or "")[:2000],
                "evidence": (a.get("evidence", "") or "")[:1000],
                "uri": a.get("url", "") or a.get("uri", ""),
                "method": a.get("method", "GET"),
                "cwe": str(a.get("cweid", "") or "").strip("0") or "",
                "plugin_id": str(a.get("pluginId", "") or a.get("pluginid", "")),
            }
        )
    return out
