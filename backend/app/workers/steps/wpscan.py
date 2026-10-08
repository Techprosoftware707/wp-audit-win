"""WPScan step — WordPress enumeration and vulnerability intelligence.

Skips when the wpscan binary is absent. Works fully without an API token
(local enumeration); a token (WPSCAN_API_TOKEN) only enriches results.
"""

from __future__ import annotations

from app.core.config import settings
from app.models.enums import VerificationStatus
from app.workers import tools
from app.workers.base import StepContext
from app.workers.parsers import wpscan as parser


def run(ctx: StepContext) -> dict:
    binary = tools.which("wpscan")
    if not binary:
        return {"skipped": True, "reason": "wpscan not installed on this worker"}

    base = ctx.target.base_url.rstrip("/")
    enumerate_opt = "vp,vt,u" if tools.intensity_at_least(ctx.intensity, "safe") else "vp,vt"
    args = [
        binary,
        "--url",
        base,
        "--format",
        "json",
        "--no-banner",
        "--random-user-agent",
        "--enumerate",
        enumerate_opt,
        "--request-timeout",
        "20",
        "--connect-timeout",
        "15",
    ]
    if settings.wpscan_api_token:
        args += ["--api-token", settings.wpscan_api_token]

    rc, out, err = tools.run_cmd(args, timeout=900)
    if rc == 127:
        return {"skipped": True, "reason": "wpscan not runnable"}

    data = parser.parse_json(out)
    if not data["ok"]:
        return {"skipped": True, "reason": f"wpscan produced no parseable JSON (rc={rc})"}

    vuln_count = 0

    def _emit_component_vulns(kind: str, slug: str, version: str, vulns: list[dict]):
        nonlocal vuln_count
        for v in vulns:
            cve = v["cve"] or None
            dedup = f"cve:{cve}:{slug}" if cve else f"sig:wpscan:{kind}:{slug}:{v['title'][:60]}"
            f = ctx.add_finding(
                title=f"{slug} {version}: {v['title']}".strip(),
                severity=parser.default_vuln_severity(bool(cve)),
                dedup_key=dedup,
                detector="wpscan",
                description=v["title"],
                cve=cve,
                affected_asset=f"{kind}:{slug}@{version or '?'}",
                verification_status=VerificationStatus.LIKELY_VULNERABLE.value,
                remediation=(
                    f"Update {slug} to {v['fixed_in']} or later."
                    if v["fixed_in"]
                    else f"Update {slug} to the latest version."
                ),
            )
            ctx.add_evidence(
                finding=f,
                kind="output",
                request=f"wpscan {kind}={slug}",
                response=str(v["references"])[:3000],
                meta={"tool": "wpscan", "fixed_in": v["fixed_in"]},
            )
            vuln_count += 1

    # Core.
    if data["version"] and data["version"]["number"]:
        ctx.add_technology(
            "WordPress",
            version=data["version"]["number"],
            category="cms",
            source="wpscan",
            confidence=90,
        )
        _emit_component_vulns(
            "core", "wordpress", data["version"]["number"], data["version"]["vulnerabilities"]
        )

    # Plugins.
    for p in data["plugins"]:
        ctx.add_plugin(
            p["slug"],
            name=p["slug"],
            version=p["version"],
            latest_version=p["latest_version"],
            outdated=p["outdated"],
            vulnerable=bool(p["vulnerabilities"]),
            source="wpscan",
            confidence=90,
        )
        _emit_component_vulns("plugin", p["slug"], p["version"], p["vulnerabilities"])

    # Themes.
    for t in data["themes"]:
        ctx.add_theme(
            t["slug"],
            name=t["slug"],
            version=t["version"],
            latest_version=t["latest_version"],
            outdated=t["outdated"],
            vulnerable=bool(t["vulnerabilities"]),
            source="wpscan",
            confidence=90,
        )
        _emit_component_vulns("theme", t["slug"], t["version"], t["vulnerabilities"])

    # Users.
    for u in data["users"]:
        ctx.add_wp_user(login=u["login"], source="wpscan", detail=u["detail"])

    ctx.add_evidence(
        kind="output",
        request=" ".join(args[:6]) + " ...",
        response=out[:16000],
        meta={"tool": "wpscan"},
    )

    return {
        "plugins": len(data["plugins"]),
        "themes": len(data["themes"]),
        "users": len(data["users"]),
        "vulnerabilities": vuln_count,
    }
