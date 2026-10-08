"""Gitleaks step — find secrets accidentally committed to source / git history.

Static analysis of a readable source tree (``settings.source_dir`` /
``WPSEC_SOURCE_DIR``) — it never touches the live target. Skips gracefully when
the binary is absent or no source is configured. Secrets are REDACTED before
storage (only rule/location/commit + a masked fingerprint are kept).
"""

from __future__ import annotations

import os
import tempfile

from app.core.config import settings
from app.models.enums import Severity, VerificationStatus
from app.workers import tools
from app.workers.base import StepContext
from app.workers.parsers import gitleaks as gitleaks_parser


def run(ctx: StepContext) -> dict:
    binary = tools.which("gitleaks")
    if not binary:
        return {"skipped": True, "reason": "gitleaks not installed on this worker"}

    src = (settings.source_dir or "").strip()
    if not src or not os.path.isdir(src):
        return {"skipped": True, "reason": "no source configured (set WPSEC_SOURCE_DIR)"}

    workdir = tempfile.mkdtemp(prefix="gitleaks-")
    report = os.path.join(workdir, "report.json")
    try:
        # "detect" scans git history when src is a repo; "dir" scans a plain tree.
        mode = "detect" if os.path.isdir(os.path.join(src, ".git")) else "dir"
        args = [
            binary,
            mode,
            "--source",
            src,
            "--report-format",
            "json",
            "--report-path",
            report,
            "--no-banner",
            "--redact",
            "--exit-code",
            "0",
        ]
        rc, out, err = tools.run_cmd(args, timeout=600)
        if rc == 127:
            return {"skipped": True, "reason": "gitleaks not runnable"}
        try:
            with open(report, encoding="utf-8", errors="replace") as fh:
                payload = fh.read()
        except OSError:
            payload = out  # some versions also print JSON to stdout

        leaks = gitleaks_parser.parse_report(payload)
        created = 0
        for leak in leaks:
            loc = f"{leak['file']}:{leak['line']}"
            dedup = f"sig:gitleaks:{leak['rule']}:{leak['file']}:{leak['line']}:{leak['commit']}"
            f = ctx.add_finding(
                title=f"Exposed secret ({leak['rule']}) in {leak['file']}",
                severity=Severity.HIGH.value,
                dedup_key=dedup,
                detector="gitleaks",
                description=(
                    f"Gitleaks detected a potential secret ({leak['rule']}) at {loc}"
                    + (f" in commit {leak['commit']}" if leak["commit"] else "")
                    + ". The secret value is redacted; rotate it and purge it from history."
                ),
                cwe="CWE-798",
                affected_asset=loc,
                verification_status=VerificationStatus.CONFIRMED.value,
                remediation="Rotate the exposed credential and remove it from git history.",
                auth_required=False,
            )
            f.confirmed = True
            ctx.add_evidence(
                finding=f,
                kind="output",
                request=f"gitleaks {mode} {leak['rule']}",
                response=f"{loc} commit={leak['commit']} match={leak['redacted']}",
                meta={"tool": "gitleaks", "rule": leak["rule"], "commit": leak["commit"]},
            )
            created += 1
        return {"findings": created, "leaks": len(leaks), "stderr": err.strip()[:200]}
    finally:
        # Clean the tempdir (and the report that may contain redacted matches).
        try:
            if os.path.exists(report):
                os.remove(report)
            os.rmdir(workdir)
        except OSError:
            pass
