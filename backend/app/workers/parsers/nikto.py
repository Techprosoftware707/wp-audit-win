"""Pure parsing for nikto 2.5.x JSON report output (unit-testable).

nikto writes a JSON report to a file (never stdout). The report is a top-level
ARRAY with one object per scanned host; each host carries a ``vulnerabilities``
list whose items have ``id``, ``method``, ``url``, ``msg`` and ``references``.
nikto emits no severity, so :func:`classify_severity` derives one by nature.
"""

from __future__ import annotations

import json

from app.models.enums import Severity

# Substrings that mark exposed/sensitive artifacts or known-bad components.
_MEDIUM_HINTS = (
    "config",
    ".bak",
    "backup",
    "credential",
    "password",
    "sql inj",
    "command exec",
    "remote file",
    "upload",
    "default account",
    "admin console",
    "phpmyadmin",
    "xmlrpc",
    "cve-",
)

# Substrings that mark security-hygiene / info-disclosure items.
_LOW_HINTS = (
    "header is not",
    "x-frame",
    "clickjacking",
    "httponly",
    "secure flag",
    "directory indexing",
    "trace",
    "etag",
    "inode",
    "autocomplete",
)


def classify_severity(msg: str, refs: str = "") -> str:
    """Classify a nikto item by the nature of its message/references."""
    text = f"{msg or ''} {refs or ''}".lower()
    if any(h in text for h in _MEDIUM_HINTS):
        return Severity.MEDIUM.value
    if any(h in text for h in _LOW_HINTS):
        return Severity.LOW.value
    return Severity.INFO.value


def _first_sentence(msg: str) -> str:
    text = (msg or "").strip()
    if not text:
        return ""
    cut = text.find(". ")
    return text[:cut] if cut != -1 else text


def _host_base(host: dict) -> str:
    port = str(host.get("port") or "")
    has_ssl = bool(host.get("ssl_info"))
    scheme = "https" if (port == "443" or has_ssl) else "http"
    return f"{scheme}://{host.get('host') or ''}"


def parse_report(text: str) -> list[dict]:
    """Parse a nikto JSON report. Tolerant of empty/invalid/truncated files."""
    if not text or not text.strip():
        return []
    try:
        data = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []

    out: list[dict] = []
    for host in data:
        if not isinstance(host, dict):
            continue
        base = _host_base(host)
        banner = host.get("server_banner") or ""
        hostname = host.get("host") or ""
        port = str(host.get("port") or "")
        for v in host.get("vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            nid = v.get("id") or ""
            url = v.get("url") or "/"
            method = v.get("method") or "GET"
            msg = v.get("msg") or ""
            refs = v.get("references") or ""
            full_url = base + url
            title = _first_sentence(msg) or f"nikto: {nid}"
            out.append(
                {
                    "id": nid,
                    "method": method,
                    "url": url,
                    "full_url": full_url,
                    "msg": msg,
                    "references": refs,
                    "title": title,
                    "severity": classify_severity(msg, refs),
                    "server_banner": banner,
                    "host": hostname,
                    "port": port,
                }
            )
    return out
