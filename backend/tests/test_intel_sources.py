"""Unit tests for the GitHub Advisory Database + OSV parsers and source registry."""

from __future__ import annotations

from app.services import intel_sync


def test_ghsa_parser_normalizes_cve_advisories():
    items = [
        {
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "cve_id": "CVE-2024-12345",
            "summary": "SQL injection in Example Plugin",
            "description": "A long description.",
            "severity": "high",
            "cvss": {"score": 8.8, "vector_string": "CVSS:3.1/..."},
            "html_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"}],
            "vulnerabilities": [{"package": {"ecosystem": "composer", "name": "acme/plugin"}}],
        },
        {"ghsa_id": "GHSA-no-cve", "cve_id": None, "summary": "no cve"},  # skipped
        "garbage",
    ]
    out = intel_sync.parse_ghsa_advisories(items)
    assert len(out) == 1
    rec = out[0]
    assert rec["cve"] == "CVE-2024-12345"
    assert rec["severity"] == "high"
    assert rec["cvss_score"] == 8.8
    assert rec["affected_product"] == "acme/plugin"
    assert rec["references"][0].startswith("https://github.com/advisories/")


def test_ghsa_severity_mapping():
    rec = intel_sync.parse_ghsa_advisories(
        [{"cve_id": "CVE-1", "severity": "moderate", "summary": "s"}]
    )[0]
    assert rec["severity"] == "medium"


def test_osv_parser_extracts_cvss_and_refs():
    obj = {
        "id": "CVE-2024-1",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "references": [{"type": "WEB", "url": "https://example.com/advisory"}],
    }
    info = intel_sync.parse_osv_vuln(obj)
    assert info["cvss_vector"].startswith("CVSS:3.1/")
    assert info["references"] == ["https://example.com/advisory"]


def test_osv_parser_tolerates_junk():
    assert intel_sync.parse_osv_vuln({})["cvss_vector"] == ""
    assert intel_sync.parse_osv_vuln("nope")["references"] == []


def test_all_seven_sources_registered(client, admin_headers):
    # ensure_sources runs via the /pocs/sources endpoint; all 7 must be present.
    r = client.get("/pocs/sources", headers=admin_headers)
    assert r.status_code == 200
    names = {s["name"] for s in r.json()}
    assert {
        "NVD",
        "CISA KEV",
        "OSV",
        "GitHub Advisory Database",
        "WPScan",
        "WordPress.org",
        "Vendor advisories",
    } <= names
