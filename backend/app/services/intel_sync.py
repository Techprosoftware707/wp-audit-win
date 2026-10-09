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
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_URL = "https://api.github.com/advisories"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

# All free/public sources from the project brief. NVD/KEV/OSV/GHSA have automated
# collectors; WPScan is used per-component during scans (optional token);
# WordPress.org is used for latest-version correlation; vendor advisories are
# entered manually. Registering them all keeps the dashboard's source list honest.
DEFAULT_SOURCES = [
    {"name": "NVD", "source_type": "nvd", "url": NVD_URL, "requires_key": False},
    {"name": "CISA KEV", "source_type": "cisa-kev", "url": CISA_KEV_URL, "requires_key": False},
    {"name": "OSV", "source_type": "osv", "url": OSV_VULN_URL, "requires_key": False},
    {
        "name": "GitHub Advisory Database",
        "source_type": "gh-advisory",
        "url": GHSA_URL,
        "requires_key": False,
    },
    {
        "name": "WPScan",
        "source_type": "wpscan",
        "url": "https://wpscan.com/api/v3/",
        "requires_key": True,
    },
    {
        "name": "WordPress.org",
        "source_type": "wordpress-org",
        "url": "https://api.wordpress.org/",
        "requires_key": False,
    },
    {"name": "Vendor advisories", "source_type": "vendor", "url": "", "requires_key": False},
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
            r = c.get(NVD_URL, params=params, headers=headers)
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


_GHSA_SEV = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low"}


def parse_ghsa_advisories(items: list) -> list[dict]:
    """Pure: normalize GitHub Advisory Database /advisories records (CVE ones)."""
    out: list[dict] = []
    for a in items or []:
        if not isinstance(a, dict):
            continue
        cve = a.get("cve_id")
        if not cve:  # keep only advisories with a CVE id for catalog correlation
            continue
        refs = [
            r.get("url")
            for r in (a.get("references") or [])
            if isinstance(r, dict) and r.get("url")
        ]
        if a.get("html_url"):
            refs.insert(0, a["html_url"])
        slug = ""
        for v in a.get("vulnerabilities") or []:
            pkg = (v or {}).get("package") or {}
            if pkg.get("name"):
                slug = pkg["name"]
                break
        out.append(
            {
                "cve": str(cve).upper(),
                "title": a.get("summary", "") or str(cve),
                "description": (a.get("description", "") or "")[:2000],
                "severity": _GHSA_SEV.get((a.get("severity") or "").lower(), "medium"),
                "cvss_score": ((a.get("cvss") or {}) or {}).get("score"),
                "affected_product": slug,
                "references": refs[:10],
                "ghsa_id": a.get("ghsa_id", ""),
            }
        )
    return out


def parse_osv_vuln(obj: dict) -> dict:
    """Pure: extract CVSS score/vector + references from an OSV vuln record."""
    result: dict = {"cvss_score": None, "cvss_vector": "", "references": []}
    if not isinstance(obj, dict):
        return result
    for sev in obj.get("severity") or []:
        if isinstance(sev, dict) and str(sev.get("type", "")).startswith("CVSS"):
            result["cvss_vector"] = sev.get("score", "")  # OSV stores the vector here
            break
    refs = [
        r.get("url") for r in (obj.get("references") or []) if isinstance(r, dict) and r.get("url")
    ]
    result["references"] = refs[:10]
    return result


def sync_ghsa(db: Session, *, limit: int = 100) -> tuple[int, str]:
    """Pull recent reviewed advisories from the GitHub Advisory Database."""
    headers = {"Accept": "application/vnd.github+json"}
    import os

    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with httpx.Client(timeout=40) as c:
            r = c.get(
                GHSA_URL,
                params={"type": "reviewed", "per_page": min(limit, 100), "sort": "published"},
                headers=headers,
            )
            r.raise_for_status()
            data = r.json()
    except Exception as exc:  # noqa: BLE001
        return 0, f"error: {type(exc).__name__}: {exc}"

    count = 0
    for rec in parse_ghsa_advisories(data if isinstance(data, list) else []):
        existing = db.execute(
            select(Vulnerability).where(Vulnerability.cve == rec["cve"])
        ).scalar_one_or_none()
        # Don't downgrade a KEV/NVD entry; only fill gaps and add new CVEs.
        fields = {
            "title": rec["title"],
            "description": rec["description"],
            "references": rec["references"],
            "affected_product": rec["affected_product"],
            "source": "gh-advisory",
        }
        if rec.get("cvss_score") is not None:
            fields["cvss_score"] = rec["cvss_score"]
        if existing is None:
            fields["severity"] = rec["severity"]
        _upsert_vuln(db, cve=rec["cve"], **fields)
        count += 1
    db.flush()
    return count, f"ok: {count} GHSA advisories"


def sync_osv_enrich(db: Session, *, limit: int = 100) -> tuple[int, str]:
    """Enrich catalog CVEs that still lack a CVSS vector via the OSV API."""
    targets = (
        db.execute(
            select(Vulnerability)
            .where(Vulnerability.cve.is_not(None), Vulnerability.cvss_vector == "")
            .limit(limit)
        )
        .scalars()
        .all()
    )
    if not targets:
        return 0, "ok: nothing to enrich"
    enriched = 0
    try:
        with httpx.Client(timeout=20) as c:
            for v in targets:
                try:
                    r = c.get(OSV_VULN_URL + v.cve)
                    if r.status_code != 200:
                        continue
                    info = parse_osv_vuln(r.json())
                except Exception:  # noqa: BLE001 - per-record failure is non-fatal
                    continue
                if info["cvss_vector"]:
                    v.cvss_vector = info["cvss_vector"]
                if info["references"] and not v.references:
                    v.references = info["references"]
                v.source = v.source or "osv"
                db.add(v)
                enriched += 1
    except Exception as exc:  # noqa: BLE001
        return enriched, f"error after {enriched}: {type(exc).__name__}: {exc}"
    db.flush()
    return enriched, f"ok: enriched {enriched} via OSV"


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
        elif src.source_type == "gh-advisory":
            _, status = sync_ghsa(db)
        elif src.source_type == "osv":
            _, status = sync_osv_enrich(db)
        elif src.source_type == "wpscan":
            status = (
                "per-component lookups run during scans via the wpscan worker"
                if settings.wpscan_api_token
                else "optional: set WPSCAN_API_TOKEN (used per-component during scans)"
            )
        elif src.source_type == "wordpress-org":
            status = "used for plugin/theme latest-version correlation during scans"
        elif src.source_type == "vendor":
            status = "manual: add vendor advisories via the vulnerabilities API"
        else:
            status = "skipped: no collector for source type"
        src.last_synced_at = utcnow()
        src.last_status = status
        results[src.name] = status
        db.add(src)
    db.flush()
    return results
