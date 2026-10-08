"""Target CRUD, credential secrecy, PoC/vuln intelligence matching, lab lifecycle."""

from __future__ import annotations

from tests.conftest import make_authorized_target


def test_target_crud(client, admin_headers):
    r = client.post(
        "/targets",
        headers=admin_headers,
        json={
            "name": "T",
            "base_url": "https://t.example.test/path",
            "owner": "o",
        },
    )
    assert r.status_code == 201
    tid = r.json()["id"]
    assert r.json()["host"] == "t.example.test"

    r = client.patch(f"/targets/{tid}", headers=admin_headers, json={"owner": "new-owner"})
    assert r.json()["owner"] == "new-owner"

    assert client.delete(f"/targets/{tid}", headers=admin_headers).status_code == 204
    assert client.get(f"/targets/{tid}", headers=admin_headers).status_code == 404


def test_credential_secret_never_returned(client, admin_headers):
    r = client.post(
        "/targets",
        headers=admin_headers,
        json={
            "name": "C",
            "base_url": "https://c.example.test",
        },
    )
    tid = r.json()["id"]
    r = client.post(
        f"/targets/{tid}/credentials",
        headers=admin_headers,
        json={
            "name": "wp-admin",
            "cred_type": "wp_password",
            "username": "admin",
            "secret": "hunter2-secret",
        },
    )
    assert r.status_code == 201
    body = r.json()
    # The secret must not appear anywhere in the response.
    assert "hunter2-secret" not in str(body)
    assert "secret_encrypted" not in body

    listed = client.get(f"/targets/{tid}/credentials", headers=admin_headers).json()
    assert "hunter2-secret" not in str(listed)


def test_poc_intel_matching_creates_catalog_finding(client, admin_headers, mock_wp):
    # Seed a vulnerability for contact-form-7 covering the detected version 5.8.1.
    r = client.post(
        "/vulnerabilities",
        headers=admin_headers,
        json={
            "cve": "CVE-2099-0001",
            "title": "CF7 test vuln",
            "severity": "high",
            "affected_slug": "contact-form-7",
            "affected_type": "plugin",
            "version_min": "5.0.0",
            "version_max": "5.9.0",
            "fixed_version": "5.9.1",
            "kev": True,
        },
    )
    assert r.status_code == 201

    tid, _ = make_authorized_target(client, admin_headers)
    scan = client.post(
        f"/targets/{tid}/scan", headers=admin_headers, json={"profile": "standard"}
    ).json()
    findings = client.get(f"/findings?scan_id={scan['id']}", headers=admin_headers).json()
    matched = [f for f in findings if f["cve"] == "CVE-2099-0001"]
    assert matched, "PoC-intelligence match should create a finding for the vulnerable plugin"
    assert matched[0]["vulnerability_id"]
    # KEV should push risk up.
    assert matched[0]["risk_score"] >= 70


def test_lab_lifecycle(client, admin_headers):
    r = client.post(
        "/labs",
        headers=admin_headers,
        json={
            "name": "cf7-lab",
            "template": {"wp_version": "6.4", "plugin_slug": "contact-form-7"},
        },
    )
    assert r.status_code == 201
    lab_id = r.json()["id"]
    r = client.post(f"/labs/{lab_id}/instances", headers=admin_headers)
    assert r.status_code == 201
    inst_id = r.json()["id"]
    assert r.json()["status"] in ("pending", "provisioning")
    r = client.delete(f"/labs/instances/{inst_id}", headers=admin_headers)
    assert r.json()["status"] == "destroyed"


def test_audit_trail_records_actions(client, admin_headers):
    client.post(
        "/targets",
        headers=admin_headers,
        json={
            "name": "A",
            "base_url": "https://a.example.test",
        },
    )
    entries = client.get("/audit", headers=admin_headers).json()
    actions = {e["action"] for e in entries}
    assert "target.create" in actions
    assert "auth.login" in actions
