"""ffuf step — active content/endpoint discovery against ``{base}/FUZZ``.

Skips when the ffuf binary is absent, when no wordlist exists on disk, or when
intensity is below ``standard`` (content discovery is active). ffuf writes its
JSON report to stdout via ``-of json -o /dev/stdout``, which :func:`run`
captures and hands to the pure :mod:`app.workers.parsers.ffuf` module. Every
matched request becomes an ENDPOINT asset; only hits whose fuzzed word matches a
sensitive-exposure pattern (``.git``, ``wp-config.php.bak``, ``.env``, etc.)
become findings.
"""

from __future__ import annotations

from pathlib import Path

from app.core.config import settings
from app.models.enums import AssetType
from app.workers import tools
from app.workers.base import StepContext
from app.workers.parsers import ffuf as ffuf_parser


def _resolve_wordlist() -> str:
    """Return a wordlist path that exists on disk, or '' when none is available."""
    configured = (settings.ffuf_wordlist or "").strip()
    if configured and Path(configured).exists():
        return configured
    bundled = Path(__file__).resolve().parent.parent / "data" / "wp_content_wordlist.txt"
    if bundled.exists():
        return str(bundled)
    return ""


def run(ctx: StepContext) -> dict:
    if not tools.intensity_at_least(ctx.intensity, "standard"):
        return {"skipped": True, "reason": "intensity below 'standard' skips active discovery"}
    binary = tools.which("ffuf")
    if not binary:
        return {"skipped": True, "reason": "ffuf not installed on this worker"}
    wordlist = _resolve_wordlist()
    if not wordlist:
        return {"skipped": True, "reason": "no ffuf wordlist available"}

    base = ctx.target.base_url.rstrip("/")
    args = [
        binary,
        "-u",
        f"{base}/FUZZ",
        "-w",
        wordlist,
        "-mc",
        "200,204,301,302,307,401,403",
        "-t",
        "40",
        "-timeout",
        "10",
        "-maxtime",
        "180",
        "-of",
        "json",
        "-o",
        "/dev/stdout",
        "-s",
        "-noninteractive",
    ]
    rc, out, err = tools.run_cmd(args, timeout=240)
    if rc == 127:
        return {"skipped": True, "reason": "ffuf not runnable"}

    hits = ffuf_parser.parse_hits(out)
    assets = 0
    findings = 0
    for h in hits:
        url = h["url"]
        if not url:
            continue
        ctx.add_asset(
            AssetType.ENDPOINT.value,
            url,
            meta={"status": h["status"], "length": h["length"]},
        )
        assets += 1

        verdict = ffuf_parser.classify_exposure(h["word"], url)
        if not verdict:
            continue  # ordinary hit (e.g. wp-content 301): asset only, no finding
        severity, _pattern = verdict
        word = h["word"]
        description = (
            f"ffuf discovered a sensitive path at {url} (HTTP {h['status']}, {h['length']} bytes)."
        )
        f = ctx.add_finding(
            title=f"Sensitive file/dir exposed: {word}",
            severity=severity,
            dedup_key=f"sig:ffuf:exposure:{url}",
            detector="ffuf",
            description=description,
            affected_asset=url,
            verification_status="likely_vulnerable",
            auth_required=False,
        )
        ctx.add_evidence(
            finding=f,
            kind="output",
            request=f"GET {url}",
            response=(
                f"status={h['status']} length={h['length']} content-type={h['content_type']}"
            ),
            meta={"tool": "ffuf", "fuzz": word, "status": h["status"]},
        )
        findings += 1

    return {"assets": assets, "findings": findings, "stderr": err.strip()[:300]}
