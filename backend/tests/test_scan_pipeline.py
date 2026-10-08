"""Full scan pipeline, finding production, correlation, verification, reporting."""

from __future__ import annotations

from tests.conftest import make_authorized_target


def _run_scan(client, headers):
    tid, _ = make_authorized_target(client, headers)
    r = client.post(f"/targets/{tid}/scan", headers=headers, json={"profile": "standard"})
    assert r.status_code == 201, r.text
    return tid, r.json()


def test_scan_produces_findings_and_inventory(client, admin_headers, mock_wp):
    tid, scan = _run_scan(client, admin_headers)
    assert scan["status"] == "completed"
    assert scan["summary"]["total"] >= 3

    findings = client.get(f"/findings?scan_id={scan['id']}", headers=admin_headers).json()
    titles = {f["title"] for f in findings}
    assert any("REST API" in t for t in titles)
    assert any("XML-RPC" in t for t in titles)

    plugins = client.get(f"/targets/{tid}/plugins", headers=admin_headers).json()
    slugs = {p["slug"]: p["version"] for p in plugins}
    assert slugs.get("contact-form-7") == "5.8.1"
    assert slugs.get("woocommerce") == "8.2.0"

    wp = client.get(f"/targets/{tid}/wordpress", headers=admin_headers).json()
    assert wp["core_version"] == "6.4.1"
    assert wp["xmlrpc_enabled"] is True


def test_steps_skip_gracefully_without_tools(client, admin_headers, mock_wp):
    _tid, scan = _run_scan(client, admin_headers)
    detail = client.get(f"/scans/{scan['id']}", headers=admin_headers).json()
    by_name = {s["name"]: s for s in detail["steps"]}
    # discovery + fingerprint complete; external tools skip (not fail).
    assert by_name["discovery"]["status"] == "completed"
    assert by_name["wp_fingerprint"]["status"] == "completed"
    assert by_name["wpscan"]["status"] == "skipped"
    assert by_name["nuclei"]["status"] == "skipped"


def test_finding_verification_endpoint_presence(client, admin_headers, mock_wp):
    _tid, scan = _run_scan(client, admin_headers)
    findings = client.get(f"/findings?scan_id={scan['id']}", headers=admin_headers).json()
    # REST users endpoint exists in the mock -> endpoint_presence should confirm.
    target = next(f for f in findings if "REST API" in f["title"])
    r = client.post(
        f"/findings/{target['id']}/verify",
        headers=admin_headers,
        json={"method": "endpoint_presence"},
    )
    assert r.status_code == 200
    assert r.json()["status"] in ("vulnerable", "confirmed")


def test_active_verification_requires_approval(client, admin_headers, mock_wp):
    _tid, scan = _run_scan(client, admin_headers)
    findings = client.get(f"/findings?scan_id={scan['id']}", headers=admin_headers).json()
    fid = findings[0]["id"]
    # Active method without approval -> recorded as pending, not executed.
    r = client.post(
        f"/findings/{fid}/verify",
        headers=admin_headers,
        json={"method": "authz_check", "approve": False},
    )
    assert r.status_code == 200
    assert r.json()["approved"] is False
    assert r.json()["status"] == "unverified"


def test_evidence_captured(client, admin_headers, mock_wp):
    _tid, scan = _run_scan(client, admin_headers)
    findings = client.get(f"/findings?scan_id={scan['id']}", headers=admin_headers).json()
    fid = next(f["id"] for f in findings if "REST API" in f["title"])
    ev = client.get(f"/findings/{fid}/evidence", headers=admin_headers).json()
    assert len(ev) >= 1
    assert ev[0]["sha256"]


def test_report_generation_formats(client, admin_headers, mock_wp):
    _tid, scan = _run_scan(client, admin_headers)
    for fmt in ("html", "json", "csv", "markdown"):
        r = client.post(
            f"/scans/{scan['id']}/report", headers=admin_headers, json={"report_format": fmt}
        )
        assert r.status_code == 201, (fmt, r.text)
        assert r.json()["status"] == "ready"
        dl = client.get(f"/reports/{r.json()['id']}/download", headers=admin_headers)
        assert dl.status_code == 200 and len(dl.content) > 0


def test_rescan_and_dedup(client, admin_headers, mock_wp):
    tid, scan = _run_scan(client, admin_headers)
    first = client.get(f"/findings?target_id={tid}", headers=admin_headers).json()
    # Rescan should not duplicate findings (same dedup keys merge).
    r = client.post(f"/scans/{scan['id']}/rescan", headers=admin_headers)
    assert r.status_code == 201
    second = client.get(f"/findings?target_id={tid}", headers=admin_headers).json()
    assert len(second) == len(first)
