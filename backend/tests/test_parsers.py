"""Unit tests for scanner output parsers (no I/O)."""

from __future__ import annotations

from app.workers.parsers import nuclei, wp, wpscan, zap


def test_wp_detection_and_versions():
    html = (
        '<meta name="generator" content="WordPress 6.4.1" />'
        '<link href="/wp-content/plugins/akismet/x.css?ver=5.3">'
        '<link href="/wp-content/themes/astra/style.css?ver=4.1.0">'
    )
    assert wp.looks_like_wordpress(html)
    assert wp.generator_version(html) == "6.4.1"
    assert wp.extract_plugins(html) == {"akismet": "5.3"}
    assert wp.extract_themes(html) == {"astra": "4.1.0"}


def test_wp_xmlrpc_and_rest_users():
    assert wp.xmlrpc_enabled(405, "XML-RPC server accepts POST requests only.")
    assert not wp.xmlrpc_enabled(200, "nope")
    users = wp.rest_users([{"id": 1, "name": "A", "slug": "a"}, "junk"])
    assert users == [{"id": 1, "name": "A", "slug": "a"}]


def test_nuclei_jsonl():
    line = (
        '{"template-id":"CVE-2021-1234","info":{"name":"X","severity":"high",'
        '"classification":{"cve-id":["CVE-2021-1234"]}},"matched-at":"http://h/x"}'
    )
    out = nuclei.parse_jsonl(line + "\ngarbage\n")
    assert len(out) == 1
    assert out[0]["cve"] == "CVE-2021-1234"
    assert nuclei.map_severity("high") == "high"
    assert nuclei.map_severity("weird") == "info"


def test_wpscan_json():
    data = (
        '{"version":{"number":"6.0","status":"insecure","vulnerabilities":'
        '[{"title":"core bug","references":{"cve":["2022-1111"]},"fixed_in":"6.1"}]},'
        '"plugins":{"foo":{"version":{"number":"1.0"},"latest_version":"1.2","outdated":true,'
        '"vulnerabilities":[{"title":"xss","references":{"cve":["2022-2222"]},"fixed_in":"1.1"}]}},'
        '"themes":{},"users":{"admin":{}}}'
    )
    parsed = wpscan.parse_json(data)
    assert parsed["ok"]
    assert parsed["version"]["number"] == "6.0"
    assert parsed["plugins"][0]["slug"] == "foo"
    assert parsed["plugins"][0]["vulnerabilities"][0]["cve"] == "CVE-2022-2222"
    assert parsed["users"][0]["login"] == "admin"


def test_wpscan_bad_json():
    assert wpscan.parse_json("not json")["ok"] is False


def test_zap_alerts():
    alerts = [
        {
            "alert": "XSS",
            "risk": "High",
            "url": "http://h/a",
            "cweid": "79",
            "method": "GET",
            "pluginId": "40012",
        }
    ]
    out = zap.parse_alerts(alerts)
    assert out[0]["severity"] == "high"
    assert out[0]["cwe"] == "79"
