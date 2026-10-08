"""Step execution context and shared helpers.

A :class:`StepContext` is handed to every scan step. Its helpers persist
discoveries (assets, technologies, plugins, themes, WP users, findings,
evidence) with incremental deduplication/correlation and risk scoring, so each
step stays small and focused on *detection*.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.base import utcnow
from app.models.enums import SEVERITY_RANK, Severity, VerificationStatus
from app.models.finding import Evidence, Finding
from app.models.scan import Asset, Scan, Technology
from app.models.target import Target
from app.models.wordpress import Plugin, Theme, WordPressInfo, WPUser
from app.services import evidence as evidence_service
from app.services import risk as risk_service


def next_finding_code(db: Session) -> str:
    """Next FIND-YYYY-NNNNNN code for the year.

    Uses MAX(existing numeric suffix)+1, not COUNT — correlation deletes merged
    findings, so a count-based scheme would reuse a code and collide with the
    unique constraint. add_finding() additionally retries on the rare race."""
    year = utcnow().year
    prefix = f"FIND-{year}-"
    rows = db.execute(
        select(Finding.finding_code).where(Finding.finding_code.like(prefix + "%"))
    ).scalars().all()
    max_n = 0
    plen = len(prefix)
    for code in rows:
        tail = code[plen:]
        if tail.isdigit():
            max_n = max(max_n, int(tail))
    return f"{prefix}{max_n + 1:06d}"


@dataclass
class StepContext:
    db: Session
    scan: Scan
    target: Target
    step_name: str
    intensity: str
    scope: list[str] = field(default_factory=list)
    logger: object = None

    def __post_init__(self) -> None:
        if self.logger is None:
            self.logger = get_logger(f"step.{self.step_name}")

    # --------------------------------------------------------------- assets
    def add_asset(self, asset_type: str, value: str, meta: dict | None = None) -> Asset:
        now = utcnow()
        existing = self.db.execute(
            select(Asset).where(Asset.target_id == self.target.id, Asset.value == value)
        ).scalar_one_or_none()
        if existing:
            existing.last_seen = now
            existing.scan_id = self.scan.id
            if meta:
                existing.meta = {**(existing.meta or {}), **meta}
            return existing
        asset = Asset(
            target_id=self.target.id,
            scan_id=self.scan.id,
            asset_type=asset_type,
            value=value,
            meta=meta or {},
            first_seen=now,
            last_seen=now,
        )
        self.db.add(asset)
        return asset

    def add_technology(
        self,
        name: str,
        version: str = "",
        category: str = "",
        source: str = "",
        confidence: int = 50,
    ) -> Technology:
        now = utcnow()
        existing = self.db.execute(
            select(Technology).where(
                Technology.target_id == self.target.id, Technology.name == name
            )
        ).scalar_one_or_none()
        if existing:
            existing.last_seen = now
            existing.scan_id = self.scan.id
            if version:
                existing.version = version
            if confidence > existing.confidence:
                existing.confidence = confidence
            return existing
        tech = Technology(
            target_id=self.target.id,
            scan_id=self.scan.id,
            name=name,
            version=version,
            category=category,
            source=source,
            confidence=confidence,
            first_seen=now,
            last_seen=now,
        )
        self.db.add(tech)
        return tech

    # ------------------------------------------------------------ wordpress
    def set_wp_info(self, **fields) -> WordPressInfo:
        info = self.db.execute(
            select(WordPressInfo).where(
                WordPressInfo.target_id == self.target.id,
                WordPressInfo.scan_id == self.scan.id,
            )
        ).scalar_one_or_none()
        if info is None:
            info = WordPressInfo(target_id=self.target.id, scan_id=self.scan.id)
            self.db.add(info)
        for k, v in fields.items():
            setattr(info, k, v)
        return info

    def add_plugin(self, slug: str, **fields) -> Plugin:
        now = utcnow()
        existing = self.db.execute(
            select(Plugin).where(Plugin.target_id == self.target.id, Plugin.slug == slug)
        ).scalar_one_or_none()
        if existing:
            existing.last_seen = now
            existing.scan_id = self.scan.id
            for k, v in fields.items():
                if v not in (None, ""):
                    setattr(existing, k, v)
            return existing
        plugin = Plugin(
            target_id=self.target.id,
            scan_id=self.scan.id,
            slug=slug,
            first_seen=now,
            last_seen=now,
            **fields,
        )
        self.db.add(plugin)
        return plugin

    def add_theme(self, slug: str, **fields) -> Theme:
        now = utcnow()
        existing = self.db.execute(
            select(Theme).where(Theme.target_id == self.target.id, Theme.slug == slug)
        ).scalar_one_or_none()
        if existing:
            existing.last_seen = now
            existing.scan_id = self.scan.id
            for k, v in fields.items():
                if v not in (None, ""):
                    setattr(existing, k, v)
            return existing
        theme = Theme(
            target_id=self.target.id,
            scan_id=self.scan.id,
            slug=slug,
            first_seen=now,
            last_seen=now,
            **fields,
        )
        self.db.add(theme)
        return theme

    def add_wp_user(self, login: str, **fields) -> WPUser:
        existing = self.db.execute(
            select(WPUser).where(WPUser.target_id == self.target.id, WPUser.login == login)
        ).scalar_one_or_none()
        if existing:
            existing.scan_id = self.scan.id
            for k, v in fields.items():
                if v not in (None, ""):
                    setattr(existing, k, v)
            return existing
        wp_user = WPUser(target_id=self.target.id, scan_id=self.scan.id, login=login, **fields)
        self.db.add(wp_user)
        return wp_user

    # --------------------------------------------------------------- findings
    def add_finding(
        self,
        *,
        title: str,
        severity: str,
        dedup_key: str,
        detector: str,
        description: str = "",
        cve: str | None = None,
        cwe: str = "",
        affected_asset: str = "",
        vulnerability_id: str | None = None,
        verification_status: str = VerificationStatus.UNVERIFIED.value,
        remediation: str = "",
        kev: bool = False,
        cvss_score: float | None = None,
        auth_required: bool = True,
    ) -> Finding:
        """Create or merge a finding, applying incremental correlation + risk."""
        now = utcnow()
        finding = self.db.execute(
            select(Finding).where(
                Finding.target_id == self.target.id, Finding.dedup_key == dedup_key
            )
        ).scalar_one_or_none()

        newly_created = False
        if finding is None:
            finding, newly_created = self._insert_finding(
                now,
                detector=detector,
                title=title,
                description=description,
                severity=severity,
                cve=cve,
                cwe=cwe,
                affected_asset=affected_asset,
                vulnerability_id=vulnerability_id,
                verification_status=verification_status,
                remediation=remediation,
                dedup_key=dedup_key,
            )

        if not newly_created:
            # Existing finding or a concurrent race-winner: merge this detection.
            detectors = list(finding.detectors or [])
            if detector not in detectors:
                detectors.append(detector)
            finding.detectors = detectors
            finding.detector_count = len(detectors)
            finding.last_detected_at = now
            finding.scan_id = self.scan.id
            if SEVERITY_RANK.get(Severity(severity), 0) > SEVERITY_RANK.get(
                Severity(finding.severity), 0
            ):
                finding.severity = severity
            if cve and not finding.cve:
                finding.cve = cve
            if cwe and not finding.cwe:
                finding.cwe = cwe

        # (Re)compute risk.
        risk_inputs = risk_service.RiskInputs(
            severity=finding.severity,
            cvss_score=cvss_score,
            verification_status=finding.verification_status,
            asset_importance=self.target.asset_importance,
            internet_exposed=True,
            kev=kev,
            detector_count=finding.detector_count,
            auth_required=auth_required,
        )
        rs, level, factors = risk_service.score(risk_inputs)
        finding.risk_score = rs
        finding.risk_level = level
        finding.risk_factors = factors
        return finding

    def _insert_finding(self, now, *, detector: str, **fields) -> tuple[Finding, bool]:
        """Insert a new Finding, retrying on a unique-constraint collision.

        Returns (finding, created). A concurrent detector may win the
        (target_id, dedup_key) race or a finding_code may collide; both surface
        as IntegrityError, which we handle inside a SAVEPOINT so prior work in
        this step is preserved. On a dedup race we return the existing winner."""
        for _ in range(6):
            candidate = Finding(
                finding_code=next_finding_code(self.db),
                target_id=self.target.id,
                scan_id=self.scan.id,
                detectors=[detector],
                detector_count=1,
                first_detected_at=now,
                last_detected_at=now,
                **fields,
            )
            try:
                with self.db.begin_nested():
                    self.db.add(candidate)
                    self.db.flush()
                return candidate, True
            except IntegrityError:
                try:
                    self.db.expunge(candidate)
                except Exception:  # noqa: BLE001
                    pass
                winner = self.db.execute(
                    select(Finding).where(
                        Finding.target_id == self.target.id,
                        Finding.dedup_key == fields["dedup_key"],
                    )
                ).scalar_one_or_none()
                if winner is not None:
                    return winner, False
                # finding_code collision only — loop to regenerate a code.
        raise RuntimeError("could not allocate a unique finding_code after retries")

    def add_evidence(self, finding: Finding | None = None, **kwargs) -> Evidence:
        return evidence_service.store(
            self.db,
            target_id=self.target.id,
            scan_id=self.scan.id,
            finding_id=finding.id if finding else None,
            scanner=self.step_name,
            **kwargs,
        )

    def now(self) -> dt.datetime:
        return utcnow()
