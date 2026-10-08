"""Nikto step — web-server misconfiguration checks.

Skips when the nikto binary is absent or when intensity is 'passive'. nikto 2.5.x
writes its JSON report only to a file, so the step runs against a tempfile and
reads it back; parsing lives in the pure :mod:`app.workers.parsers.nikto` module.
"""

from __future__ import annotations

import os
import shutil
import tempfile

from app.workers import tools
from app.workers.base import StepContext
from app.workers.parsers import nikto as nikto_parser


def run(ctx: StepContext) -> dict:
    if not tools.intensity_at_least(ctx.intensity, "safe"):
        return {"skipped": True, "reason": "intensity 'passive' skips active web-server scanning"}
    binary = tools.which("nikto")
    if not binary:
        return {"skipped": True, "reason": "nikto not installed on this worker"}

    base = ctx.target.base_url.rstrip("/")
    workdir = tempfile.mkdtemp(prefix="nikto-")
    try:
        return _scan(ctx, binary, base, workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _scan(ctx: StepContext, binary: str, base: str, workdir: str) -> dict:
    outfile = os.path.join(workdir, "report.json")
    args = [
        binary,
        "-h",
        base,
        "-Format",
        "json",
        "-output",
        outfile,
        "-ask",
        "no",
        "-nointeractive",
        "-nocheck",
        "-nolookup",
        "-Tuning",
        "x6",  # all test classes except 6 (DoS) => safe
        "-maxtime",
        "600s",
        "-timeout",
        "10",
    ]
    rc, out, err = tools.run_cmd(args, timeout=660)
    if rc == 127:
        return {"skipped": True, "reason": "nikto not runnable"}

    try:
        with open(outfile, encoding="utf-8", errors="replace") as fh:
            report = fh.read()
    except OSError:
        report = ""

    items = nikto_parser.parse_report(report)
    created = 0
    for it in items:
        f = ctx.add_finding(
            title=it["title"],
            severity=it["severity"],
            dedup_key=f"sig:nikto:{it['id']}:{it['url']}",
            detector="nikto",
            description=it["msg"],
            affected_asset=it["full_url"] or base,
            verification_status="likely_vulnerable",
        )
        ctx.add_evidence(
            finding=f,
            kind="output",
            request=f"{it['method']} {it['full_url']}",
            response=it["msg"],
            meta={
                "tool": "nikto",
                "nikto_id": it["id"],
                "references": it["references"],
                "server_banner": it["server_banner"],
                "host": it["host"],
                "port": it["port"],
            },
        )
        created += 1

    return {"findings": created, "stderr": err.strip()[:300]}
