"""PoC / vulnerability *intelligence* matching.

Correlates detected software (core/plugins/themes, with versions) and CVEs
against the local Vulnerability catalog and PoC library. This is read-only
intelligence: it attaches references and applicability, and NEVER executes any
collected artifact.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Vulnerability
from app.models.poc import PoC
from app.services import versions


def vulns_for_cve(db: Session, cve: str) -> list[Vulnerability]:
    if not cve:
        return []
    return db.execute(select(Vulnerability).where(Vulnerability.cve == cve.upper())).scalars().all()


def vulns_for_component(
    db: Session, slug: str, version: str, kind: str = ""
) -> list[Vulnerability]:
    if not slug:
        return []
    q = select(Vulnerability).where(Vulnerability.affected_slug == slug)
    if kind:
        q = q.where(Vulnerability.affected_type == kind)
    out = []
    for v in db.execute(q).scalars().all():
        if versions.in_affected_range(version, v.version_min, v.version_max, v.fixed_version):
            out.append(v)
    return out


def pocs_for_cve(db: Session, cve: str) -> list[PoC]:
    if not cve:
        return []
    return db.execute(select(PoC).where(PoC.cve == cve.upper())).scalars().all()


def pocs_for_component(db: Session, slug: str, version: str, kind: str = "") -> list[PoC]:
    if not slug:
        return []
    q = select(PoC).where(PoC.affected_slug == slug)
    if kind:
        q = q.where(PoC.affected_type == kind)
    out = []
    for p in db.execute(q).scalars().all():
        if versions.in_affected_range(version, p.version_min, p.version_max, p.fixed_version):
            out.append(p)
    return out
