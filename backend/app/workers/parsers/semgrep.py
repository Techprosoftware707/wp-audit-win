"""Pure parsing for semgrep ``--json`` output (unit-testable).

semgrep prints a single JSON object to stdout (``--quiet`` suppresses the banner).
Top-level keys include ``results``, ``errors``, ``paths`` and ``version``. Each
``results[]`` item carries ``check_id``, ``path``, ``start.line`` and an ``extra``
block with ``message``, ``severity`` (``ERROR``/``WARNING``/``INFO``) and
``metadata.cwe`` (an array of ``"CWE-NN: ..."`` strings, absent on non-security
rules). :func:`map_severity` normalizes severity to our :class:`Severity` values.
"""

from __future__ import annotations

import json

from app.models.enums import Severity

_SEV_MAP = {
    "ERROR": Severity.HIGH.value,
    "WARNING": Severity.MEDIUM.value,
    "INFO": Severity.LOW.value,
}


def map_severity(value: str) -> str:
    """Map a semgrep severity to our Severity value (unknown -> low)."""
    return _SEV_MAP.get((value or "").upper(), Severity.LOW.value)


def parse_payload(text: str) -> dict | None:
    """Return the parsed semgrep JSON object, or None if empty/invalid.

    The step uses this to tell a usable scan (a JSON object) apart from a
    failed ruleset fetch (non-JSON / empty stdout) that should trigger a retry.
    """
    if not text or not text.strip():
        return None
    try:
        data = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def _cwe_from(metadata: dict) -> str | None:
    cwe = metadata.get("cwe")
    if isinstance(cwe, list) and cwe:
        return "; ".join(str(c) for c in cwe)
    if isinstance(cwe, str) and cwe:
        return cwe
    return None


def files_scanned(data: dict | None) -> int:
    """Count the source files semgrep reported scanning."""
    if not isinstance(data, dict):
        return 0
    paths = data.get("paths")
    if not isinstance(paths, dict):
        return 0
    scanned = paths.get("scanned")
    return len(scanned) if isinstance(scanned, list) else 0


def parse(text: str) -> list[dict]:
    """Parse semgrep JSON. Tolerant of empty/invalid/malformed output."""
    data = parse_payload(text)
    if data is None:
        return []
    results = data.get("results")
    if not isinstance(results, list):
        return []

    out: list[dict] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        check_id = r.get("check_id") or ""
        path = r.get("path") or ""
        start = r.get("start")
        line = start.get("line") if isinstance(start, dict) else None
        if not isinstance(line, int):
            line = 0
        extra = r.get("extra")
        if not isinstance(extra, dict):
            extra = {}
        metadata = extra.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        severity_raw = extra.get("severity") or ""
        out.append(
            {
                "check_id": check_id,
                "path": path,
                "line": line,
                "message": extra.get("message") or "",
                "severity_raw": severity_raw,
                "severity": map_severity(severity_raw),
                "cwe": _cwe_from(metadata),
                "lines": extra.get("lines") or "",
            }
        )
    return out
