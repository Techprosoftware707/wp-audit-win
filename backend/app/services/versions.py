"""Lenient version parsing/comparison for component version ranges."""

from __future__ import annotations

import re

_NUM = re.compile(r"\d+")


def parse(v: str) -> tuple[int, ...]:
    if not v:
        return ()
    parts = _NUM.findall(str(v))
    return tuple(int(p) for p in parts[:5]) if parts else ()


def _cmp(a: str, b: str) -> int:
    ta, tb = parse(a), parse(b)
    if ta == tb:
        return 0
    return -1 if ta < tb else 1


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
