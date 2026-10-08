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


def _clean_cwe(value) -> str:
    """Return the CWE id as-is (no zero-stripping); '' for missing/'-1'."""
    s = str(value or "").strip()
    return "" if s in ("", "-1", "0") else s


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
                # Keep the CWE id verbatim; ZAP uses "-1" for "no CWE".
                "cwe": _clean_cwe(a.get("cweid", "")),
                "plugin_id": str(a.get("pluginId", "") or a.get("pluginid", "")),
            }
        )
    return out
