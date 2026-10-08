"""Risk engine.

Combines CVSS (when known) with contextual factors into a 0–100 risk score and a
severity band. Deterministic and unit-testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models.enums import Severity, VerificationStatus

_SEVERITY_BASE = {
    Severity.CRITICAL.value: 90.0,
    Severity.HIGH.value: 72.0,
    Severity.MEDIUM.value: 50.0,
    Severity.LOW.value: 28.0,
    Severity.INFO.value: 8.0,
}

_IMPORTANCE_FACTOR = {"low": 0.85, "medium": 1.0, "high": 1.12, "critical": 1.2}

_VERIFICATION_FACTOR = {
    VerificationStatus.CONFIRMED.value: 1.15,
    VerificationStatus.VULNERABLE.value: 1.10,
    VerificationStatus.LIKELY_VULNERABLE.value: 1.0,
    VerificationStatus.UNVERIFIED.value: 0.92,
    VerificationStatus.INCONCLUSIVE.value: 0.9,
    VerificationStatus.NOT_TESTABLE.value: 0.9,
    VerificationStatus.NOT_VULNERABLE.value: 0.3,
}


@dataclass
class RiskInputs:
    severity: str = Severity.MEDIUM.value
    cvss_score: float | None = None
    verification_status: str = VerificationStatus.UNVERIFIED.value
    asset_importance: str = "medium"
    internet_exposed: bool = True
    kev: bool = False  # CISA Known Exploited Vulnerability
    detector_count: int = 1
    auth_required: bool = True
    extra: dict = field(default_factory=dict)


def _band(score: float) -> str:
    if score >= 85:
        return Severity.CRITICAL.value
    if score >= 65:
        return Severity.HIGH.value
    if score >= 40:
        return Severity.MEDIUM.value
    if score >= 15:
        return Severity.LOW.value
    return Severity.INFO.value


def score(inp: RiskInputs) -> tuple[float, str, dict]:
    """Return (score 0-100, risk_level, factor breakdown)."""
    base = (inp.cvss_score * 10.0) if inp.cvss_score else _SEVERITY_BASE.get(inp.severity, 50.0)

    factors: dict[str, float] = {"base": round(base, 2)}

    imp = _IMPORTANCE_FACTOR.get(inp.asset_importance, 1.0)
    ver = _VERIFICATION_FACTOR.get(inp.verification_status, 1.0)
    exposure = 1.1 if inp.internet_exposed else 0.85
    kev = 1.25 if inp.kev else 1.0
    # Independent corroboration raises confidence a little (capped).
    corrob = 1.0 + min(max(inp.detector_count - 1, 0), 3) * 0.03
    unauth = 1.08 if not inp.auth_required else 1.0

    factors.update(
        importance=imp,
        verification=ver,
        exposure=exposure,
        kev=kev,
        corroboration=round(corrob, 3),
        unauth=unauth,
    )

    value = base * imp * ver * exposure * kev * corrob * unauth
    value = max(0.0, min(100.0, value))
    return round(value, 2), _band(value), factors
