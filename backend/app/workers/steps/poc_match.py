"""PoC-matching step — intelligence correlation (no execution).

For each finding (and each detected vulnerable component) this links the local
Vulnerability catalog and PoC library, enriching findings with CVE metadata and
recording which PoCs are *applicable*. It never runs any PoC; applicable PoCs
remain UNVERIFIED and are surfaced for operator-driven, human-approved
verification.
"""

from __future__ import annotations

from sqlalchemy import select

from app.models.enums import VerificationStatus
from app.models.finding import Finding
from app.models.wordpress import Plugin, Theme
from app.services import poc_intel
from app.workers.base import StepContext


def run(ctx: StepContext) -> dict:
    findings = (
        ctx.db.execute(select(Finding).where(Finding.target_id == ctx.target.id)).scalars().all()
    )

    enriched = 0
    applicable_pocs = 0

    for f in findings:
        pocs: list[str] = []
        if f.cve:
            # Enrich from the catalog.
            for v in poc_intel.vulns_for_cve(ctx.db, f.cve):
                if not f.vulnerability_id:
                    f.vulnerability_id = v.id
                if v.cwe and not f.cwe:
                    f.cwe = v.cwe
                factors = dict(f.risk_factors or {})
                factors["kev"] = 1.25 if v.kev else factors.get("kev", 1.0)
                factors["cvss_score"] = v.cvss_score
                f.risk_factors = factors
                enriched += 1
            pocs = [p.poc_code for p in poc_intel.pocs_for_cve(ctx.db, f.cve)]

        if pocs:
            factors = dict(f.risk_factors or {})
            factors["applicable_pocs"] = pocs
            f.risk_factors = factors
            applicable_pocs += len(pocs)
        ctx.db.add(f)

    # Match detected components against the catalog, creating findings for known
    # vulnerable versions that scanners did not already flag.
    created = 0
    for plugin in (
        ctx.db.execute(select(Plugin).where(Plugin.target_id == ctx.target.id)).scalars().all()
    ):
        for v in poc_intel.vulns_for_component(ctx.db, plugin.slug, plugin.version, "plugin"):
            dedup = f"cve:{v.cve}:{plugin.slug}" if v.cve else f"vuln:{v.id}:{plugin.slug}"
            f = ctx.add_finding(
                title=f"{plugin.slug} {plugin.version}: {v.title}",
                severity=v.severity,
                dedup_key=dedup,
                detector="poc_match",
                description=v.description,
                cve=v.cve,
                cwe=v.cwe,
                affected_asset=f"plugin:{plugin.slug}@{plugin.version or '?'}",
                vulnerability_id=v.id,
                verification_status=VerificationStatus.LIKELY_VULNERABLE.value,
                kev=v.kev,
                cvss_score=v.cvss_score,
                remediation=(
                    f"Update {plugin.slug} to {v.fixed_version} or later."
                    if v.fixed_version
                    else f"Update {plugin.slug}."
                ),
            )
            plugin.vulnerable = True
            created += 1

    for theme in (
        ctx.db.execute(select(Theme).where(Theme.target_id == ctx.target.id)).scalars().all()
    ):
        for v in poc_intel.vulns_for_component(ctx.db, theme.slug, theme.version, "theme"):
            dedup = f"cve:{v.cve}:{theme.slug}" if v.cve else f"vuln:{v.id}:{theme.slug}"
            ctx.add_finding(
                title=f"{theme.slug} {theme.version}: {v.title}",
                severity=v.severity,
                dedup_key=dedup,
                detector="poc_match",
                description=v.description,
                cve=v.cve,
                cwe=v.cwe,
                affected_asset=f"theme:{theme.slug}@{theme.version or '?'}",
                vulnerability_id=v.id,
                verification_status=VerificationStatus.LIKELY_VULNERABLE.value,
                kev=v.kev,
                cvss_score=v.cvss_score,
            )
            theme.vulnerable = True
            created += 1

    ctx.db.flush()
    return {"enriched": enriched, "applicable_pocs": applicable_pocs, "catalog_findings": created}
