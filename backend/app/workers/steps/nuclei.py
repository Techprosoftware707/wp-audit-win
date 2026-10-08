"""Nuclei step — template-driven detection (CVEs, exposures, misconfigurations).

Skips when the nuclei binary is absent. At 'passive'/'safe' it runs only
non-intrusive template tags; higher intensities broaden the template set.
"""

from __future__ import annotations

from app.workers import tools
from app.workers.base import StepContext
from app.workers.parsers import nuclei as nuclei_parser


def _tags_for(intensity: str) -> list[str]:
    if tools.intensity_at_least(intensity, "standard"):
        return ["wordpress", "wp-plugin", "wp-theme", "cve", "exposure", "misconfiguration"]
    if tools.intensity_at_least(intensity, "safe"):
        return ["wordpress", "wp-plugin", "wp-theme", "exposure"]
    return ["tech", "wordpress"]  # passive: detection only


def run(ctx: StepContext) -> dict:
    binary = tools.which("nuclei")
    if not binary:
        return {"skipped": True, "reason": "nuclei not installed on this worker"}

    base = ctx.target.base_url.rstrip("/")
    tags = ",".join(_tags_for(ctx.intensity))
    args = [
        binary,
        "-u",
        base,
        "-jsonl",
        "-silent",
        "-no-color",
        "-tags",
        tags,
        "-rate-limit",
        "50",
        "-timeout",
        "10",
        "-disable-update-check",
    ]
    rc, out, err = tools.run_cmd(args, timeout=600)
    if rc == 127:
        return {"skipped": True, "reason": "nuclei not runnable"}

    results = nuclei_parser.parse_jsonl(out)
    created = 0
    for r in results:
        sev = nuclei_parser.map_severity(r["severity"])
        dedup = (
            f"cve:{r['cve']}:{ctx.target.host}"
            if r["cve"]
            else f"sig:nuclei:{r['template_id']}:{r['matched_at']}"
        )
        f = ctx.add_finding(
            title=r["name"] or r["template_id"],
            severity=sev,
            dedup_key=dedup,
            detector="nuclei",
            description=r.get("description", ""),
            cve=r["cve"] or None,
            affected_asset=r["matched_at"] or base,
            verification_status="likely_vulnerable",
            auth_required=True,
        )
        ctx.add_evidence(
            finding=f,
            kind="output",
            request=f"nuclei template={r['template_id']}",
            response=(r.get("matched_at", "") + "\n" + str(r.get("extracted", "")))[:4000],
            meta={"tool": "nuclei", "template_id": r["template_id"]},
        )
        created += 1

    return {"templates_matched": created, "stderr": err.strip()[:300]}
