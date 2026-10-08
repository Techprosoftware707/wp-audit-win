"""Pure parsing helpers for WordPress fingerprinting (no I/O, unit-testable)."""

from __future__ import annotations

import re

_GENERATOR_RE = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s*([0-9.]+)?""",
    re.IGNORECASE,
)
_README_VERSION_RE = re.compile(r"Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)
_PLUGIN_RE = re.compile(
    r"/wp-content/plugins/([a-z0-9][a-z0-9._-]+)/[^\"'?>\s]*(?:\?ver=([0-9][0-9A-Za-z.\-]*))?",
    re.IGNORECASE,
)
_THEME_RE = re.compile(
    r"/wp-content/themes/([a-z0-9][a-z0-9._-]+)/[^\"'?>\s]*(?:\?ver=([0-9][0-9A-Za-z.\-]*))?",
    re.IGNORECASE,
)


def looks_like_wordpress(html: str, headers: dict | None = None) -> bool:
    headers = headers or {}
    signals = [
        "/wp-content/" in html,
        "/wp-includes/" in html,
        "wp-json" in html,
        bool(_GENERATOR_RE.search(html)),
        "link" in headers and "wp-json" in headers.get("link", ""),
    ]
    return sum(bool(s) for s in signals) >= 1


def generator_version(html: str) -> str:
    m = _GENERATOR_RE.search(html)
    return (m.group(1) or "").strip() if m else ""


def readme_version(html: str) -> str:
    # The WordPress readme.html starts with "<h1 ...>WordPress</h1> ... Version X.Y".
    if "wordpress" not in html.lower():
        return ""
    m = _README_VERSION_RE.search(html)
    return m.group(1) if m else ""


def _collect(regex: re.Pattern, html: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for m in regex.finditer(html):
        slug = m.group(1).lower()
        ver = (m.group(2) or "").strip()
        if slug in ("", "index"):
            continue
        # Keep the first non-empty version seen for a slug.
        if slug not in found or (not found[slug] and ver):
            found[slug] = ver
    return found


def extract_plugins(html: str) -> dict[str, str]:
    """Return {slug: version} discovered from plugin asset URLs."""
    return _collect(_PLUGIN_RE, html)


def extract_themes(html: str) -> dict[str, str]:
    """Return {slug: version} discovered from theme asset URLs."""
    return _collect(_THEME_RE, html)


def xmlrpc_enabled(status_code: int, body: str) -> bool:
    # GET to a live xmlrpc.php returns 405 with this message, or 200 with it.
    return status_code in (200, 405) and "XML-RPC server accepts POST requests only" in body


def rest_users(json_payload) -> list[dict]:
    """Normalize /wp-json/wp/v2/users output to [{id, name, slug}]."""
    out: list[dict] = []
    if isinstance(json_payload, list):
        for u in json_payload:
            if isinstance(u, dict):
                out.append(
                    {
                        "id": u.get("id"),
                        "name": u.get("name", ""),
                        "slug": u.get("slug", ""),
                    }
                )
    return out
