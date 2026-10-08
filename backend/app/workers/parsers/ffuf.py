"""Pure parsing for ffuf JSON output (unit-testable).

ffuf with ``-of json -o /dev/stdout`` emits a single JSON OBJECT (not JSONL)
to stdout whose ``results`` array holds one entry per matched request. Each
entry carries ``url``, ``status``, ``length``, ``content-type`` and an
``input`` map with the fuzzed keyword (``FUZZ``). :func:`classify_exposure`
derives a severity for the sensitive-file/dir patterns we care about; all other
hits are recorded as assets only (no finding).
"""

from __future__ import annotations

import json

from app.models.enums import Severity

# Secret/config leaks: disclosing these can hand over source or DB credentials.
_SECRET_CONFIG = (
    ".git",
    ".svn",
    ".env",
    "wp-config.php.bak",
    "wp-config.php.save",
    "wp-config.php.old",
    "wp-config.php~",
    "db.sql",
)

# Other sensitive artifacts worth flagging, but lower impact on their own.
_OTHER_SENSITIVE = (
    "backup",
    "debug.log",
)


def classify_exposure(word: str, url: str = "") -> tuple[str, str] | None:
    """Return (severity, matched_pattern) for a sensitive hit, else ``None``.

    Case-insensitive substring match on the fuzzed word or the URL path.
    """
    hay = f"{word or ''} {url or ''}".lower()
    for pat in _SECRET_CONFIG:
        if pat in hay:
            return Severity.HIGH.value, pat
    for pat in _OTHER_SENSITIVE:
        if pat in hay:
            return Severity.MEDIUM.value, pat
    return None


def parse_hits(text: str) -> list[dict]:
    """Parse ffuf JSON stdout into a flat list of hits.

    Tolerant of empty/invalid/truncated output (returns ``[]``).
    """
    if not text or not text.strip():
        return []
    try:
        data = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []

    out: list[dict] = []
    for r in data.get("results") or []:
        if not isinstance(r, dict):
            continue
        inp = r.get("input") if isinstance(r.get("input"), dict) else {}
        word = inp.get("FUZZ", "") if inp else ""
        out.append(
            {
                "url": r.get("url", "") or "",
                "status": r.get("status"),
                "length": r.get("length"),
                "content_type": r.get("content-type") or r.get("content_type") or "",
                "word": word,
            }
        )
    return out
