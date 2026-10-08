"""Vulnerability-intelligence collector.

Pulls from free, public sources into the local Vulnerability catalog. No paid
subscription or API key is required; keys (NVD) only raise rate limits. Network
failures are handled gracefully — a source that cannot be reached simply records
its error and the sync continues.

Collected entries are catalog metadata. PoC *artifacts* are never auto-executed;
any PoC record created here starts UNVERIFIED (see docs/POC_INTELLIGENCE.md).
"""

from __future__ import annotations

import datetime as dt

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.models.base import utcnow
from app.models.enums import Severity
from app.models.finding import Vulnerability
from app.models.poc import PoCSource

log = get_logger("intel")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

DEFAULT_SOURCES = [
    {"name": "CISA KEV", "source_type": "cisa-kev", "url": CISA_KEV_URL, "requires_key": False},
    {
        "name": "NVD",
        "source_type": "nvd",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "requires_key": False,
    },
]


def ensure_sources(db: Session) -> None:
    for spec in DEFAULT_SOURCES:
        existing = db.execute(
            select(PoCSource).where(PoCSource.name == spec["name"])
        ).scalar_one_or_none()
        if not existing:
            db.add(PoCSource(**spec, enabled=True))
    db.flush()


def _upsert_vuln(db: Session, *, cve: str, **fields) -> Vulnerability:
    cve = cve.upper()
    vuln = db.execute(select(Vulnerability).where(Vulnerability.cve == cve)).scalar_one_or_none()
    if vuln is None:
        vuln = Vulnerability(cve=cve, title=fields.get("title", cve))
        db.add(vuln)
    for k, v in fields.items():
        if v not in (None, ""):
            setattr(vuln, k, v)
    return vuln


def sync_cisa_kev(db: Session, *, limit: int = 2000) -> tuple[int, str]:
    try:
        with httpx.Client(timeout=30) as c:
            r = c.get(CISA_KEV_URL)
            r.raise_for_status()
            data = r.json()
    except Exception as exc:  # noqa: BLE001
        return 0, f"error: {type(exc).__name__}: {exc}"

    count = 0
    for item in (data.get("vulnerabilities") or [])[:limit]:
        cve = item.get("cveID")
        if not cve:
            continue
        pub = item.get("dateAdded")
        published = None
        if pub:
            try:
                published = dt.datetime.fromisoformat(pub).replace(tzinfo=dt.UTC)
            except ValueError:
                published = None
        _upsert_vuln(
            db,
            cve=cve,
            title=item.get("vulnerabilityName", cve),
            description=item.get("shortDescription", ""),
            affected_product=item.get("product", ""),
            severity=Severity.HIGH.value,
            source="cisa-kev",
            kev=True,
            published_at=published,
            references=[item.get("notes", "")] if item.get("notes") else [],
        )
        count += 1
    db.flush()
    return count, f"ok: {count} KEV entries"


def sync_nvd_recent(db: Session, *, days: int = 7, limit: int = 200) -> tuple[int, str]:
    """Pull recently-modified CVEs from the public NVD 2.0 API (no key needed)."""
    end = utcnow()
    start = end - dt.timedelta(days=days)
    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": min(limit, 2000),
    }
    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    try:
        with httpx.Client(timeout=40) as c:
            r = c.get(DEFAULT_SOURCES[1]["url"], params=params, headers=headers)
            r.raise_for_status()
            data = r.json()
    except Exception as exc:  # noqa: BLE001
        return 0, f"error: {type(exc).__name__}: {exc}"

    count = 0
    for entry in (data.get("vulnerabilities") or [])[:limit]:
        cve_obj = entry.get("cve", {})
        cve = cve_obj.get("id")
        if not cve:
            continue
        descs = cve_obj.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        metrics = cve_obj.get("metrics", {})
        score = None
        vector = ""
        sev = Severity.MEDIUM.value
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                m = metrics[key][0]["cvssData"]
                score = m.get("baseScore")
                vector = m.get("vectorString", "")
                sev = (m.get("baseSeverity", "") or "").lower() or sev
                break
        _upsert_vuln(
            db,
            cve=cve,
            title=cve,
            description=desc[:2000],
            cvss_score=score,
            cvss_vector=vector,
            severity=sev if sev in {s.value for s in Severity} else Severity.MEDIUM.value,
            source="nvd",
        )
        count += 1
    db.flush()
    return count, f"ok: {count} NVD entries"


def run_sync(db: Session, source_names: list[str] | None = None) -> dict:
    ensure_sources(db)
    results: dict[str, str] = {}
    sources = db.execute(select(PoCSource).where(PoCSource.enabled.is_(True))).scalars().all()
    for src in sources:
        if source_names and src.name not in source_names:
            continue
        if src.source_type == "cisa-kev":
            _, status = sync_cisa_kev(db)
        elif src.source_type == "nvd":
            _, status = sync_nvd_recent(db)
        else:
            status = "skipped: no collector for source type"
        src.last_synced_at = utcnow()
        src.last_status = status
        results[src.name] = status
        db.add(src)
    db.flush()
    return results
