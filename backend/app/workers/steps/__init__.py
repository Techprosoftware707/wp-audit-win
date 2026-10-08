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
            correlation,
            discovery,
            fingerprint,
            nmap,
            nuclei,
            poc_match,
            risk_step,
            wpcli,
            wpscan,
            zap,
        )

        _REGISTRY = {
            "authorization": authz.run,
            "discovery": discovery.run,
            "wp_fingerprint": fingerprint.run,
            "nmap": nmap.run,
            "wpscan": wpscan.run,
            "nuclei": nuclei.run,
            "zap": zap.run,
            "wpcli": wpcli.run,
            "correlation": correlation.run,
            "poc_match": poc_match.run,
            "risk": risk_step.run,
        }
    return _REGISTRY
