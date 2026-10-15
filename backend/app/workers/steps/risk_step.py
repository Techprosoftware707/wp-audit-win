"""Final risk pass — recompute scores with correlated detector counts + KEV."""

from __future__ import annotations

from sqlalchemy import select

from app.models.finding import Finding, Vulnerability
from app.services import risk as risk_service
from app.workers.base import StepContext


def _cvss_for(ctx: StepContext, f: Finding, factors: dict) -> float | None:
    """Resolve a finding's CVSS, preferring the factor breakdown and falling back
    to the authoritative Vulnerability catalog (by id, then CVE). Previously the
    final pass read CVSS only from ``factors``, so a finding whose CVSS was not
    re-injected there was scored off the severity band alone — understating risk
    when catalog CVSS and severity diverge (common for GHSA/OSV entries)."""
    cvss = factors.get("cvss_score")
    if cvss is not None:
        return cvss
    vuln = None
    if f.vulnerability_id:
        vuln = ctx.db.get(Vulnerability, f.vulnerability_id)
    if vuln is None and f.cve:
        vuln = (
            ctx.db.execute(select(Vulnerability).where(Vulnerability.cve == f.cve))
            .scalars()
            .first()
        )
    return vuln.cvss_score if vuln is not None else None


def run(ctx: StepContext) -> dict:
    findings = (
        ctx.db.execute(select(Finding).where(Finding.target_id == ctx.target.id)).scalars().all()
    )

    recomputed = 0
    for f in findings:
        factors = f.risk_factors or {}
        cvss = _cvss_for(ctx, f, factors)
        inputs = risk_service.RiskInputs(
            severity=f.severity,
            cvss_score=cvss,
            verification_status=f.verification_status,
            asset_importance=ctx.target.asset_importance,
            internet_exposed=True,
            kev=(factors.get("kev", 1.0) > 1.0),
            detector_count=f.detector_count,
            auth_required=True,
        )
        score, level, new_factors = risk_service.score(inputs)
        # Preserve the intelligence annotations added by poc_match.
        new_factors["applicable_pocs"] = factors.get("applicable_pocs", [])
        f.risk_score = score
        f.risk_level = level
        f.risk_factors = new_factors
        ctx.db.add(f)
        recomputed += 1

    ctx.db.flush()
    return {"recomputed": recomputed}
