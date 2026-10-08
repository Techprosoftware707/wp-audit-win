"""Safe verification engine.

Determines whether a finding is actually present *without* turning the target
into a compromised system. Methods are classified by how active they are:

  * version_match     — offline comparison of detected version vs. affected range
  * endpoint_presence — a single benign GET to check an endpoint exists
  * info_exposure     — a benign GET checking for sensitive markers in a response
  * authz_check       — compares unauth vs. low-priv access (requires approval + creds)
  * param_behavior    — observes a parameter's response (requires approval)
  * manual            — records an operator's manual determination

Active methods require explicit approval AND a valid authorization covering the
target. Nothing here attempts exploitation or state change.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.enums import VerificationMethod, VerificationStatus
from app.models.finding import Finding, VerificationTest, Vulnerability
from app.models.target import Target
from app.models.wordpress import Plugin, Theme
from app.services import authorization as authz
from app.services import poc_intel, versions
from app.workers import http

ACTIVE_METHODS = {
    VerificationMethod.AUTHZ_CHECK.value,
    VerificationMethod.PARAM_BEHAVIOR.value,
}
NETWORK_METHODS = {
    VerificationMethod.ENDPOINT_PRESENCE.value,
    VerificationMethod.INFO_EXPOSURE.value,
    VerificationMethod.AUTHZ_CHECK.value,
    VerificationMethod.PARAM_BEHAVIOR.value,
}

_SENSITIVE_MARKERS = (
    "DB_PASSWORD",
    "define('AUTH_KEY'",
    "BEGIN RSA PRIVATE KEY",
    "wp-config",
    "mysqli_connect",
    "fatal error",
    "stack trace",
)


class VerificationError(Exception):
    pass


def _version_match(db: Session, finding: Finding, target: Target) -> tuple[str, str]:
    """Offline: does the detected component version fall in the affected range?"""
    if not finding.cve and not finding.vulnerability_id:
        return VerificationStatus.INCONCLUSIVE.value, "no CVE/vulnerability reference on finding"
    # Find the component version from inventory.
    comp = None
    if finding.affected_asset.startswith("plugin:"):
        slug = finding.affected_asset.split(":", 1)[1].split("@", 1)[0]
        comp = db.query(Plugin).filter_by(target_id=target.id, slug=slug).first()
    elif finding.affected_asset.startswith("theme:"):
        slug = finding.affected_asset.split(":", 1)[1].split("@", 1)[0]
        comp = db.query(Theme).filter_by(target_id=target.id, slug=slug).first()
    version = getattr(comp, "version", "") if comp else ""

    vulns = poc_intel.vulns_for_cve(db, finding.cve) if finding.cve else []
    if not vulns and finding.vulnerability_id:
        v = db.get(Vulnerability, finding.vulnerability_id)
        if v is not None:
            vulns = [v]
    if not vulns:
        return VerificationStatus.INCONCLUSIVE.value, "no catalog entry to compare against"
    for v in vulns:
        if versions.in_affected_range(version, v.version_min, v.version_max, v.fixed_version):
            if version:
                return VerificationStatus.VULNERABLE.value, (
                    f"version {version} is within affected range for {v.cve}"
                )
            return (
                VerificationStatus.LIKELY_VULNERABLE.value,
                "version unknown; range matches by CVE",
            )
    return VerificationStatus.NOT_VULNERABLE.value, f"version {version} is outside affected range"


def _endpoint_presence(finding: Finding, scope: list[str]) -> tuple[str, str, str, str, int | None]:
    url = finding.affected_asset
    if not url.startswith("http"):
        return VerificationStatus.NOT_TESTABLE.value, "affected asset is not a URL", "", "", None
    resp = http.fetch(url, scope=scope)
    req = f"GET {url}"
    if not resp.ok:
        return VerificationStatus.INCONCLUSIVE.value, resp.error, req, resp.error, None
    if resp.status_code == 200:
        return (
            VerificationStatus.VULNERABLE.value,
            "endpoint present (HTTP 200)",
            req,
            f"HTTP {resp.status_code}",
            resp.status_code,
        )
    if resp.status_code in (401, 403, 404):
        return (
            VerificationStatus.NOT_VULNERABLE.value,
            f"endpoint not accessible (HTTP {resp.status_code})",
            req,
            f"HTTP {resp.status_code}",
            resp.status_code,
        )
    return (
        VerificationStatus.INCONCLUSIVE.value,
        f"HTTP {resp.status_code}",
        req,
        f"HTTP {resp.status_code}",
        resp.status_code,
    )


def _info_exposure(finding: Finding, scope: list[str]) -> tuple[str, str, str, str, int | None]:
    url = finding.affected_asset
    if not url.startswith("http"):
        return VerificationStatus.NOT_TESTABLE.value, "affected asset is not a URL", "", "", None
    resp = http.fetch(url, scope=scope)
    req = f"GET {url}"
    if not resp.ok:
        return VerificationStatus.INCONCLUSIVE.value, resp.error, req, resp.error, None
    hit = next((m for m in _SENSITIVE_MARKERS if m.lower() in resp.text.lower()), None)
    if resp.status_code == 200 and hit:
        return (
            VerificationStatus.CONFIRMED.value,
            f"sensitive marker exposed: {hit}",
            req,
            resp.text[:2000],
            resp.status_code,
        )
    return (
        VerificationStatus.NOT_VULNERABLE.value,
        "no sensitive markers observed",
        req,
        f"HTTP {resp.status_code}",
        resp.status_code,
    )


def run_verification(
    db: Session,
    *,
    finding: Finding,
    method: str,
    mode: str,
    approve: bool,
    performed_by: str,
    notes: str = "",
    poc_id: str | None = None,
) -> VerificationTest:
    target = db.get(Target, finding.target_id)

    # Network-touching verification requires a valid authorization at run time,
    # and is confined to that authorization's scope (so the affected-asset URL and
    # any redirect cannot leave scope / reach internal hosts).
    scope: list[str] = [target.host]
    if method in NETWORK_METHODS:
        try:
            auth = authz.assert_scannable(db, target, mode=mode)
        except authz.AuthorizationError as exc:
            raise VerificationError(f"target not authorized: {exc}") from exc
        scope = list(auth.allowed_scope) if auth.allowed_scope else [target.host]

    test = VerificationTest(
        finding_id=finding.id,
        poc_id=poc_id,
        method=method,
        mode=mode,
        performed_by=performed_by,
        notes=notes,
    )

    # Active methods must be explicitly approved before execution.
    if method in ACTIVE_METHODS and not approve:
        test.status = VerificationStatus.UNVERIFIED.value
        test.approved = False
        test.notes = (notes + " | pending approval (active method)").strip(" |")
        db.add(test)
        db.flush()
        return test

    test.approved = method not in ACTIVE_METHODS or approve
    test.approved_by = performed_by if test.approved and method in ACTIVE_METHODS else None

    request_text = response_text = ""
    http_status = None
    if method == VerificationMethod.VERSION_MATCH.value:
        status, detail = _version_match(db, finding, target)
    elif method == VerificationMethod.ENDPOINT_PRESENCE.value:
        status, detail, request_text, response_text, http_status = _endpoint_presence(
            finding, scope
        )
    elif method == VerificationMethod.INFO_EXPOSURE.value:
        status, detail, request_text, response_text, http_status = _info_exposure(finding, scope)
    elif method in ACTIVE_METHODS:
        # Active methods are approved here but conservatively report NOT_TESTABLE
        # unless the operator supplies the prerequisites (credentials / payloads),
        # which are handled by the lab workflow rather than fired at production.
        status = VerificationStatus.NOT_TESTABLE.value
        detail = (
            "approved; active verification is performed via the lab workflow "
            "or with operator-supplied parameters (see docs/VERIFICATION.md)"
        )
    else:  # manual
        status = (
            VerificationStatus.INCONCLUSIVE.value
            if not notes
            else VerificationStatus.CONFIRMED.value
        )
        detail = notes or "manual determination recorded"

    test.status = status
    test.request = request_text
    test.response = response_text
    test.notes = (test.notes + " | " + detail).strip(" |")
    db.add(test)
    db.flush()

    # Reflect the result on the finding.
    finding.verification_status = status
    if status == VerificationStatus.CONFIRMED.value:
        finding.confirmed = True
    elif status == VerificationStatus.NOT_VULNERABLE.value:
        finding.confirmed = False
    db.add(finding)
    db.flush()
    return test
