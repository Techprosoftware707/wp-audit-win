"""Verifier for the wp-audit-win Companion plugin's signed audit reports.

The companion WordPress plugin (``wordpress-plugin/``) serves an HMAC-SHA256
signed report. This module recomputes the signature the SAME way the plugin does
(recursive key-sorted, compact, slash-unescaped JSON) so the platform can trust
a report's integrity without the plugin ever disclosing its signing key.

Cross-language canonicalization contract (must match the PHP side exactly):
- dict keys sorted recursively (PHP ksort on associative arrays);
- lists keep their order;
- compact separators ``(',', ':')`` (PHP json_encode has no spaces);
- non-ASCII escaped to ``\\uXXXX`` (PHP default) -> ``ensure_ascii=True``;
- slashes NOT escaped (PHP JSON_UNESCAPED_SLASHES) -> Python already does this.
"""

from __future__ import annotations

import hashlib
import hmac
import json


def canonical(data) -> str:
    """Deterministic JSON matching the plugin's WPAWC_Report::canonical()."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sign(data, key: str) -> str:
    return hmac.new(
        key.encode("utf-8"), canonical(data).encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_report(envelope: dict, key: str) -> bool:
    """Return True iff the envelope's signature matches its data under ``key``.

    Uses a constant-time comparison. Any malformed envelope returns False.
    """
    if not isinstance(envelope, dict):
        return False
    sig = envelope.get("signature")
    data = envelope.get("data")
    if not isinstance(sig, str) or data is None:
        return False
    return hmac.compare_digest(sign(data, key), sig)


def summarize(envelope: dict) -> dict:
    """Flatten a verified report into a small inventory/checks summary.

    Caller is responsible for verifying the signature first; this only reshapes.
    """
    data = envelope.get("data", {}) if isinstance(envelope, dict) else {}
    checks = data.get("checks", []) or []
    failing = [c for c in checks if isinstance(c, dict) and c.get("status") == "fail"]
    return {
        "site": envelope.get("site", ""),
        "core_version": (data.get("core", {}) or {}).get("version", ""),
        "php_version": (data.get("php", {}) or {}).get("version", ""),
        "plugin_count": len(data.get("plugins", []) or []),
        "plugins_with_updates": sum(
            1
            for p in (data.get("plugins", []) or [])
            if isinstance(p, dict) and p.get("update_available")
        ),
        "failing_checks": [c.get("id") for c in failing],
    }
