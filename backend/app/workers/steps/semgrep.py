"""Semgrep step — static analysis of WordPress/PHP SOURCE.

This step never touches the live target; it scans a readable source tree
(``settings.source_dir`` / ``WPSEC_SOURCE_DIR``). It skips gracefully when the
binary is absent or no source is configured, and never raises for a missing
tool/config. Parsing lives in the pure :mod:`app.workers.parsers.semgrep` module.

semgrep's ``p/php`` and ``p/wordpress`` rulesets are fetched from the registry on
first run. If that fetch fails (no network / ruleset unavailable) stdout is not a
JSON object, so the step retries with ``--config auto`` and, failing that, skips.
"""

from __future__ import annotations

import os

from app.core.config import settings
from app.workers import tools
from app.workers.base import StepContext
from app.workers.parsers import semgrep as semgrep_parser


def _resolve_source() -> str:
    """Return the first configured source dir that exists on disk, else ""."""
    for candidate in (settings.source_dir,):
        if candidate and os.path.isdir(candidate):
            return candidate
    return ""


def run(ctx: StepContext) -> dict:
    binary = tools.which("semgrep")
    if not binary:
        return {"skipped": True, "reason": "semgrep not installed on this worker"}

    src = _resolve_source()
    if not src:
        return {"skipped": True, "reason": "no source configured (set WPSEC_SOURCE_DIR)"}

    base = [binary, "--json", "--quiet", "--no-error", "--timeout=0"]
    primary = base + ["--config", "p/php", "--config", "p/wordpress", src]
    rc, out, err = tools.run_cmd(primary, timeout=1800)
    if rc == 127:
        return {"skipped": True, "reason": "semgrep not runnable"}

    payload = semgrep_parser.parse_payload(out)
    config_used = "p/php,p/wordpress"
    if payload is None:
        # Registry fetch for p/php or p/wordpress failed; retry with auto.
        fallback = base + ["--config", "auto", src]
        rc, out, err = tools.run_cmd(fallback, timeout=1800)
        if rc == 127:
            return {"skipped": True, "reason": "semgrep not runnable"}
        payload = semgrep_parser.parse_payload(out)
        if payload is None:
            return {"skipped": True, "reason": "semgrep could not load rulesets"}
        config_used = "auto"

    results = semgrep_parser.parse(out)
    created = 0
    for r in results:
        affected = f"{r['path']}:{r['line']}"
        f = ctx.add_finding(
            title=r["check_id"] or "semgrep finding",
            severity=r["severity"],
            dedup_key=f"sig:semgrep:{r['check_id']}:{r['path']}:{r['line']}",
            detector="semgrep",
            description=r["message"],
            cwe=r["cwe"] or "",
            affected_asset=affected,
            verification_status="likely_vulnerable",
        )
        ctx.add_evidence(
            finding=f,
            kind="output",
            request=f"semgrep {r['check_id']}",
            response=(r["lines"] + "\n" + r["message"])[:4000],
            meta={
                "tool": "semgrep",
                "check_id": r["check_id"],
                "cwe": r["cwe"],
                "path": r["path"],
                "line": r["line"],
            },
        )
        created += 1

    return {
        "findings": created,
        "files_scanned": semgrep_parser.files_scanned(payload),
        "config": config_used,
        "stderr": err.strip()[:300],
    }
