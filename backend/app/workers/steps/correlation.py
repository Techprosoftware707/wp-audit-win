"""Correlation step — collapse findings that describe the same issue.

add_finding() already merges by dedup_key as scanners run. This pass performs
cross-scanner correlation by CVE (different scanners may key the same CVE
differently), unioning the detector set onto one canonical finding so the UI
shows a single issue with "detected by N scanners".
"""

from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select

from app.models.base import utcnow
from app.models.enums import SEVERITY_RANK, Severity
from app.models.finding import Evidence, Finding
from app.workers.base import StepContext


def _norm_cve(cve: str | None) -> str:
    return (cve or "").strip().upper()


def run(ctx: StepContext) -> dict:
    findings = (
        ctx.db.execute(select(Finding).where(Finding.target_id == ctx.target.id)).scalars().all()
    )

    by_cve: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        cve = _norm_cve(f.cve)
        if cve:
            by_cve[cve].append(f)

    merged = 0
    for _cve, group in by_cve.items():
        if len(group) < 2:
            continue
        # Canonical = most corroborated, then oldest.
        canonical = sorted(group, key=lambda f: (-f.detector_count, f.created_at))[0]
        detectors = set(canonical.detectors or [])
        for other in group:
            if other.id == canonical.id:
                continue
            detectors.update(other.detectors or [])
            if SEVERITY_RANK.get(Severity(other.severity), 0) > SEVERITY_RANK.get(
                Severity(canonical.severity), 0
            ):
                canonical.severity = other.severity
            # Reassign evidence to the canonical finding.
            evs = (
                ctx.db.execute(select(Evidence).where(Evidence.finding_id == other.id))
                .scalars()
                .all()
            )
            for ev in evs:
                ev.finding_id = canonical.id
            ctx.db.delete(other)
            merged += 1
        canonical.detectors = sorted(detectors)
        canonical.detector_count = len(detectors)
        canonical.last_detected_at = utcnow()
        ctx.db.add(canonical)

    ctx.db.flush()
    return {"cve_groups": len(by_cve), "merged": merged}
