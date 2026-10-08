"""Scan step registry.

Maps step names (as used in the orchestrator pipeline) to their implementation
functions. Each implementation is ``run(ctx: StepContext) -> dict`` and returns
an output summary; returning ``{"skipped": True, "reason": ...}`` marks the step
skipped (e.g. a scanner binary is not installed)."""

from __future__ import annotations

from collections.abc import Callable

_REGISTRY: dict[str, Callable] | None = None


def get_registry() -> dict[str, Callable]:
    global _REGISTRY
    if _REGISTRY is None:
        from app.workers.steps import (
            authz,
            auto_report,
            burp,
            change_detect,
            correlation,
            discovery,
            ffuf,
            fingerprint,
            gitleaks,
            nikto,
            nmap,
            nuclei,
            poc_match,
            risk_step,
            semgrep,
            whatweb,
            wpcli,
            wpscan,
            zap,
        )

        _REGISTRY = {
            "authorization": authz.run,
            "discovery": discovery.run,
            "wp_fingerprint": fingerprint.run,
            "whatweb": whatweb.run,
            "nmap": nmap.run,
            "nikto": nikto.run,
            "ffuf": ffuf.run,
            "wpscan": wpscan.run,
            "nuclei": nuclei.run,
            "zap": zap.run,
            "burp": burp.run,
            "wpcli": wpcli.run,
            "semgrep": semgrep.run,
            "gitleaks": gitleaks.run,
            "correlation": correlation.run,
            "poc_match": poc_match.run,
            "change_detect": change_detect.run,
            "risk": risk_step.run,
            "auto_report": auto_report.run,
        }
    return _REGISTRY
