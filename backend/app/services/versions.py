"""Lenient version parsing/comparison for component version ranges."""

from __future__ import annotations

import re

_NUM = re.compile(r"\d+")
_PRERELEASE = re.compile(r"[-_.]?(alpha|beta|rc|dev|pre|a|b)\d*\b", re.IGNORECASE)


def parse(v: str) -> tuple[int, ...]:
    if not v:
        return ()
    parts = _NUM.findall(str(v))
    return tuple(int(p) for p in parts[:5]) if parts else ()


def _is_prerelease(v: str) -> bool:
    return bool(v) and bool(_PRERELEASE.search(str(v)))


def _key(v: str) -> tuple:
    # A pre-release sorts BELOW the same numeric release (1.0.0-rc1 < 1.0.0).
    return (parse(v), 0 if _is_prerelease(v) else 1)


def _cmp(a: str, b: str) -> int:
    ka, kb = _key(a), _key(b)
    if ka == kb:
        return 0
    return -1 if ka < kb else 1


def lt(a: str, b: str) -> bool:
    return _cmp(a, b) < 0


def le(a: str, b: str) -> bool:
    return _cmp(a, b) <= 0


def ge(a: str, b: str) -> bool:
    return _cmp(a, b) >= 0


def in_affected_range(version: str, version_min: str, version_max: str, fixed_version: str) -> bool:
    """True if `version` falls in the affected range. Unknown version -> True
    (treated as possibly-affected, to be confirmed)."""
    if not version:
        return True
    if fixed_version and ge(version, fixed_version):
        return False
    if version_min and lt(version, version_min):
        return False
    if version_max and not le(version, version_max):
        return False
    return True
