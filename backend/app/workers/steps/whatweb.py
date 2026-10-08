"""WhatWeb step — fast technology/server fingerprinting.

Skips when the whatweb binary is absent. Emits ``ctx.add_technology`` for each
detected component and a single INFO finding summarizing the stack. Runs at
``passive`` (aggression 1); only escalates to aggression 3 at ``aggressive``.
"""

from __future__ import annotations

import os

from app.models.enums import Severity, VerificationStatus
from app.workers import tools
from app.workers.base import StepContext
from app.workers.parsers import whatweb as parser


def run(ctx: StepContext) -> dict:
    binary = tools.which("whatweb")
    if not binary:
        return {"skipped": True, "reason": "whatweb not installed on this worker"}

    base = ctx.target.base_url
    aggression = "3" if tools.intensity_at_least(ctx.intensity, "aggressive") else "1"
    args = [
        binary,
        "--quiet",
        "--colour=never",
        "--aggression",
        aggression,
        "--user-agent",
        "WhatWeb/0.5.5",
        "--open-timeout",
        "15",
        "--read-timeout",
        "30",
        "--max-threads",
        "25",
        "--log-json=/dev/stdout",
        base,
    ]
    # Defensive: point whatweb at the apt-shipped lib when a non-system ruby
    # precedes /usr/bin on PATH (harmless when system ruby is already correct).
    # run_cmd inherits this process's environment, so set it here.
    os.environ.setdefault("RUBYLIB", "/usr/lib/ruby/vendor_ruby")
    rc, out, err = tools.run_cmd(args, timeout=300)
    if rc == 127:
        return {"skipped": True, "reason": "whatweb not runnable"}

    targets = parser.parse(out)
    tech_count = 0
    labels: list[str] = []
    for target_obj in targets:
        for tech in parser.technologies(target_obj):
            ctx.add_technology(
                tech["name"],
                version=tech["version"],
                category=tech["category"],
                source="whatweb",
                confidence=tech["confidence"],
            )
            tech_count += 1
        labels.extend(parser.stack_labels(parser.technologies(target_obj)))

    labels = sorted(set(labels))
    findings = 0
    if labels:
        f = ctx.add_finding(
            title="Technology stack fingerprint (whatweb)",
            severity=Severity.INFO.value,
            dedup_key=f"sig:whatweb:stack:{ctx.target.host}",
            detector="whatweb",
            description="whatweb fingerprinted: " + ", ".join(labels),
            affected_asset=base,
            verification_status=VerificationStatus.CONFIRMED.value,
            auth_required=False,
        )
        f.confirmed = True
        ctx.add_evidence(
            finding=f,
            kind="output",
            request=" ".join(args[:6]) + " ...",
            response=out[:16000],
            meta={"tool": "whatweb"},
        )
        findings = 1

    return {"technologies": tech_count, "findings": findings, "stderr": err.strip()[:300]}
