"""Seed demo/sample data for a fresh install (idempotent).

Creates an example authorized target, a couple of catalog vulnerabilities, and a
lab template so the dashboard has something to show. Run:

    docker compose exec api python -m app.cli.seed_demo
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select

from app.core.config import settings
from app.core.db import create_all, session_scope
from app.models.enums import AuthorizationStatus, AuthorizationType, Intensity
from app.models.finding import Vulnerability
from app.models.lab import Lab
from app.models.target import Authorization, Target

SAMPLE_VULNS = [
    dict(
        cve="CVE-2024-10000",
        title="Example Plugin <1.5 — Unauthenticated SQLi",
        severity="critical",
        cwe="CWE-89",
        cvss_score=9.8,
        affected_slug="example-plugin",
        affected_type="plugin",
        version_min="0.0.0",
        version_max="1.4.99",
        fixed_version="1.5.0",
        source="demo",
        kev=False,
    ),
    dict(
        cve="CVE-2024-10001",
        title="Contact Form 7 — Reflected XSS (demo)",
        severity="medium",
        cwe="CWE-79",
        cvss_score=6.1,
        affected_slug="contact-form-7",
        affected_type="plugin",
        version_min="5.0.0",
        version_max="5.8.99",
        fixed_version="5.9.0",
        source="demo",
        kev=False,
    ),
]


def main() -> None:
    if settings.is_sqlite:
        create_all()
    with session_scope() as db:
        # Vulnerabilities (catalog).
        for spec in SAMPLE_VULNS:
            if not db.execute(
                select(Vulnerability).where(Vulnerability.cve == spec["cve"])
            ).scalar_one_or_none():
                db.add(Vulnerability(**spec))

        # Demo target + active authorization (scoped to a non-routable demo host).
        target = db.execute(
            select(Target).where(Target.host == "demo.wpsec.local")
        ).scalar_one_or_none()
        if not target:
            target = Target(
                name="Demo WordPress",
                base_url="http://demo.wpsec.local",
                host="demo.wpsec.local",
                owner="Demo Owner",
                scan_profile=Intensity.STANDARD.value,
                max_intensity=Intensity.STANDARD.value,
                notes="Seed data — a non-routable demo host for exploring the UI.",
            )
            db.add(target)
            db.flush()
            now = dt.datetime.now(dt.UTC)
            db.add(
                Authorization(
                    target_id=target.id,
                    status=AuthorizationStatus.ACTIVE.value,
                    auth_type=AuthorizationType.INTERNAL_ASSET.value,
                    authorized_by="Demo Owner",
                    reference="SEED-001",
                    start_date=now - dt.timedelta(days=1),
                    expiration_date=now + dt.timedelta(days=365),
                    allowed_scope=["demo.wpsec.local"],
                    max_intensity=Intensity.STANDARD.value,
                )
            )

        # Lab template.
        if not db.execute(select(Lab).where(Lab.name == "cf7-reproduction")).scalar_one_or_none():
            db.add(
                Lab(
                    name="cf7-reproduction",
                    description="Disposable WP + CF7 for reproducing CVE-2024-10001 (demo).",
                    template={
                        "wp_version": "6.4",
                        "plugin_slug": "contact-form-7",
                        "plugin_version": "5.8.1",
                        "php_version": "8.2",
                    },
                    auto_destroy=True,
                    ttl_minutes=60,
                )
            )

    print("[seed] demo data ready (target 'Demo WordPress', 2 sample CVEs, 1 lab template)")


if __name__ == "__main__":
    main()
