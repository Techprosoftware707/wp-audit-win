"""Final risk pass — recompute scores with correlated detector counts + KEV."""

from __future__ import annotations

from sqlalchemy import select

from app.models.finding import Finding
from app.services import risk as risk_service
from app.workers.base import StepContext


def run(ctx: StepContext) -> dict:
    findings = (
        ctx.db.execute(select(Finding).where(Finding.target_id == ctx.target.id)).scalars().all()
    )

    recomputed = 0
    for f in findings:
        factors = f.risk_factors or {}
        inputs = risk_service.RiskInputs(
            severity=f.severity,
            cvss_score=factors.get("cvss_score"),
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
        new_factors["cvss_score"] = factors.get("cvss_score")
        f.risk_score = score
        f.risk_level = level
        f.risk_factors = new_factors
        ctx.db.add(f)
        recomputed += 1

    ctx.db.flush()
    return {"recomputed": recomputed}
