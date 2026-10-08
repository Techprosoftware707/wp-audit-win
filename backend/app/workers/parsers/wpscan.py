"""Pure parsing for WPScan JSON output (unit-testable)."""

from __future__ import annotations

import json

from app.models.enums import Severity


def _vulns(node: dict) -> list[dict]:
    out = []
    for v in node.get("vulnerabilities", []) or []:
        refs = v.get("references", {}) or {}
        cves = refs.get("cve", []) or []
        cve = (
            f"CVE-{cves[0]}"
            if cves and not str(cves[0]).upper().startswith("CVE")
            else (str(cves[0]).upper() if cves else "")
        )
        out.append(
            {
                "title": v.get("title", ""),
                "cve": cve,
                "fixed_in": v.get("fixed_in", "") or "",
                "references": refs,
            }
        )
    return out


def parse_json(text: str) -> dict:
    try:
        data = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return {
            "ok": False,
            "version": None,
            "plugins": [],
            "themes": [],
            "users": [],
            "findings": [],
        }

    result: dict = {
        "ok": True,
        "version": None,
        "plugins": [],
        "themes": [],
        "users": [],
        "findings": [],
    }

    ver = data.get("version") or {}
    if ver:
        result["version"] = {
            "number": ver.get("number", ""),
            "status": ver.get("status", ""),
            "vulnerabilities": _vulns(ver),
        }

    for slug, node in (data.get("plugins") or {}).items():
        node = node or {}
        version = (
            (node.get("version") or {}).get("number", "")
            if isinstance(node.get("version"), dict)
            else ""
        )
        result["plugins"].append(
            {
                "slug": slug,
                "version": version,
                "latest_version": node.get("latest_version", "") or "",
                "outdated": bool(node.get("outdated")),
                "vulnerabilities": _vulns(node),
            }
        )

    for slug, node in (data.get("themes") or {}).items():
        node = node or {}
        version = (
            (node.get("version") or {}).get("number", "")
            if isinstance(node.get("version"), dict)
            else ""
        )
        result["themes"].append(
            {
                "slug": slug,
                "version": version,
                "latest_version": node.get("latest_version", "") or "",
                "outdated": bool(node.get("outdated")),
                "vulnerabilities": _vulns(node),
            }
        )

    users = data.get("users") or {}
    if isinstance(users, dict):
        for username, node in users.items():
            result["users"].append({"login": username, "detail": node or {}})

    return result


def default_vuln_severity(has_cve: bool) -> str:
    # WPScan (free) doesn't return CVSS; a known component vulnerability is
    # treated as High by default, refined later by the risk engine / NVD data.
    return Severity.HIGH.value if has_cve else Severity.MEDIUM.value
