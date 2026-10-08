"""Pure parsing for whatweb JSON output (unit-testable; no I/O).

whatweb (``--log-json=/dev/stdout`` paired with ``--quiet``) emits a JSON
array of per-target objects. Each object carries a ``plugins`` map whose keys
are detector names and whose values hold optional ``version``/``certainty``/
``string`` fields. This module normalizes that into flat technology dicts the
step can hand to :meth:`StepContext.add_technology`.
"""

from __future__ import annotations

import json
import re

# Plugin keys that describe metadata/headers rather than a technology.
_DENYLIST = {
    "IP",
    "Country",
    "Title",
    "UncommonHeaders",
    "Allow",
    "Cookies",
    "Email",
    "RedirectLocation",
    "HTML5",
    "Script",
    "Frame",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Access-Control-Allow-Methods",
    "Via-Proxy",
    "Content-Language",
    "HTTPOnly",
    "PasswordField",
    "HttpOnly",
    "Open-Graph-Protocol",
}

# Detector name -> our technology category.
CATEGORY_MAP = {
    # server / web-server
    "HTTPServer": "web-server",
    "nginx": "web-server",
    "Apache": "web-server",
    "IIS": "web-server",
    "Microsoft-IIS": "web-server",
    "LiteSpeed": "web-server",
    "Varnish": "web-server",
    "Caddy": "web-server",
    # cms
    "WordPress": "cms",
    "MetaGenerator": "cms",
    "Drupal": "cms",
    "Joomla": "cms",
    # language
    "PHP": "language",
    "Ruby": "language",
    "Python": "language",
    "Perl": "language",
    "ASP.NET": "language",
    "X-Powered-By": "language",
    # framework
    "Laravel": "framework",
    "Django": "framework",
    "Express": "framework",
    "Ruby-on-Rails": "framework",
    "Bootstrap": "framework",
    # javascript-library
    "jQuery": "javascript-library",
    "jQuery-Migrate": "javascript-library",
    "Modernizr": "javascript-library",
    "MooTools": "javascript-library",
    "Prototype": "javascript-library",
    "React": "javascript-library",
    "Vue.js": "javascript-library",
    # analytics
    "Google-Analytics": "analytics",
    "Google-Tag-Manager": "analytics",
    # cdn / cache
    "cloudflare": "cdn",
    "Fastly": "cdn",
    "Akamai": "cdn",
    # font
    "Google-Font-API": "font",
    "Font-Awesome": "font",
}

_VERSION_RE = re.compile(r"(\d+\.\d+[\w.\-]*)")


def parse(stdout: str) -> list[dict]:
    """Parse whatweb JSON stdout into a list of per-target objects.

    Tolerant of empty/partial output: returns ``[]`` rather than raising.
    """
    txt = (stdout or "").strip()
    try:
        data = json.loads(txt)
    except (ValueError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return [obj for obj in data if isinstance(obj, dict)]


def _extract_version(name: str, val: dict) -> str:
    versions = val.get("version") or []
    if isinstance(versions, list) and versions:
        first = versions[0]
        if first:
            return str(first)
    if name in {"WordPress", "MetaGenerator"}:
        strings = val.get("string") or []
        if isinstance(strings, list):
            m = _VERSION_RE.search(" ".join(str(s) for s in strings))
            if m:
                return m.group(1)
    return ""


def technologies(target_obj: dict) -> list[dict]:
    """Normalize one target object's ``plugins`` map into technology dicts.

    Each dict: ``{name, version, category, confidence}``.
    """
    out: list[dict] = []
    plugins = target_obj.get("plugins") or {}
    if not isinstance(plugins, dict):
        return out
    for name, val in plugins.items():
        if name in _DENYLIST:
            continue
        if not isinstance(val, dict):
            val = {}
        certainty = val.get("certainty")
        confidence = int(certainty) if certainty is not None else 100
        version = _extract_version(name, val)
        category = CATEGORY_MAP.get(name, "web")
        out.append(
            {
                "name": name,
                "version": version,
                "category": category,
                "confidence": confidence,
            }
        )
    return out


def stack_labels(techs: list[dict]) -> list[str]:
    """Human-readable sorted labels (``name`` or ``name vX``) for a summary."""
    labels = set()
    for t in techs:
        if t["version"]:
            labels.add(f"{t['name']} v{t['version']}")
        else:
            labels.add(t["name"])
    return sorted(labels)
