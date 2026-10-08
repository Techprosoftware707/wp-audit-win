"""Pure parsing for Gitleaks JSON output (unit-testable).

Gitleaks reports exposed secrets in source / git history. This parser normalizes
each leak and REDACTS the secret material — the raw secret is never returned or
stored (only the rule, location, commit, and a masked fingerprint), per the
platform's sensitive-evidence handling rules.
"""
from __future__ import annotations

import json


def _mask(secret: str) -> str:
    """Return a non-reversible, low-information fingerprint of a secret."""
    if not secret:
        return ""
    s = str(secret)
    n = len(s)
    if n <= 8:
        return f"***({n} chars)"
    return f"{s[:2]}***{s[-2:]} ({n} chars)"


def parse_report(text: str) -> list[dict]:
    """Parse gitleaks `--report-format json` output into normalized leaks.

    Tolerant of empty/invalid/non-list input (returns [])."""
    if not text or not text.strip():
        return []
    try:
        data = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []

    out: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        rule = item.get("RuleID") or item.get("Rule") or item.get("rule") or "secret"
        file = item.get("File") or item.get("file") or ""
        line = item.get("StartLine") or item.get("startLine") or item.get("line") or 0
        commit = item.get("Commit") or item.get("commit") or ""
        secret = item.get("Secret") or item.get("secret") or ""
        match = item.get("Match") or item.get("match") or ""
        out.append(
            {
                "rule": str(rule),
                "description": str(item.get("Description") or item.get("description") or ""),
                "file": str(file),
                "line": int(line) if str(line).isdigit() else 0,
                "commit": str(commit)[:40],
                "author": str(item.get("Author") or item.get("author") or ""),
                "date": str(item.get("Date") or item.get("date") or ""),
                # Redacted only — never the raw secret.
                "redacted": _mask(secret or match),
            }
        )
    return out
