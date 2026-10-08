"""Unit tests for the nikto JSON report parser (no I/O, no subprocess)."""

from __future__ import annotations

from app.workers.parsers import nikto

# Realistic nikto 2.5.x JSON report (top-level array, one host object).
SAMPLE = """[
   {
      "end_time" : "2026-10-08 14:22:53 +0000",
      "host" : "wp.example.com",
      "ip" : "203.0.113.42",
      "port" : "443",
      "server_banner" : "Apache/2.4.52 (Ubuntu)",
      "ssl_info" : {
         "altnames" : "wp.example.com, www.wp.example.com",
         "ciphers" : "TLSv1.3 TLS_AES_256_GCM_SHA384",
         "cn" : "wp.example.com",
         "issuer" : "/C=US/O=Let's Encrypt/CN=R3",
         "subject" : "/CN=wp.example.com"
      },
      "start_time" : "2026-10-08 14:19:07 +0000",
      "vulnerabilities" : [
         {
            "id" : "999103",
            "method" : "GET",
            "msg" : "The X-Content-Type-Options header is not set. MIME sniffing possible.",
            "references" : "https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/",
            "url" : "/"
         },
         {
            "id" : "999957",
            "method" : "GET",
            "msg" : "The anti-clickjacking X-Frame-Options header is not present.",
            "references" : "",
            "url" : "/"
         },
         {
            "id" : "006345",
            "method" : "GET",
            "msg" : "/wp-login.php: Cookie created without the httponly flag.",
            "references" : "",
            "url" : "/wp-login.php"
         },
         {
            "id" : "001945",
            "method" : "GET",
            "msg" : "/wp-config.php.bak: configuration backup found; may disclose secrets.",
            "references" : "",
            "url" : "/wp-config.php.bak"
         },
         {
            "id" : "000600",
            "method" : "GET",
            "msg" : "/xmlrpc.php: XML-RPC endpoint is enabled (pingback/brute-force risk).",
            "references" : "CVE-2015-5074",
            "url" : "/xmlrpc.php"
         }
      ]
   }
]"""


def test_parse_report_yields_all_items():
    items = nikto.parse_report(SAMPLE)
    assert len(items) == 5


def test_severity_classification():
    items = nikto.parse_report(SAMPLE)
    by_id = {it["id"]: it for it in items}
    # Header / cookie hygiene items are low.
    assert by_id["999103"]["severity"] == "low"
    assert by_id["999957"]["severity"] == "low"
    assert by_id["006345"]["severity"] == "low"
    # Sensitive artifact and xmlrpc/CVE items are medium.
    assert by_id["001945"]["severity"] == "medium"
    assert by_id["000600"]["severity"] == "medium"
    severities = [it["severity"] for it in items]
    assert severities.count("low") == 3
    assert severities.count("medium") == 2


def test_url_and_scheme_resolution():
    items = nikto.parse_report(SAMPLE)
    by_id = {it["id"]: it for it in items}
    # port 443 / ssl_info present => https.
    assert by_id["999103"]["full_url"] == "https://wp.example.com/"
    assert by_id["001945"]["full_url"] == "https://wp.example.com/wp-config.php.bak"
    assert by_id["000600"]["method"] == "GET"
    assert by_id["000600"]["references"] == "CVE-2015-5074"
    assert by_id["999103"]["server_banner"] == "Apache/2.4.52 (Ubuntu)"


def test_title_is_first_sentence():
    items = nikto.parse_report(SAMPLE)
    by_id = {it["id"]: it for it in items}
    assert by_id["999103"]["title"] == "The X-Content-Type-Options header is not set"


def test_http_scheme_without_ssl():
    report = (
        '[{"host":"plain.example.com","port":"80","vulnerabilities":'
        '[{"id":"000001","method":"GET","msg":"Server banner note.","references":"","url":"/"}]}]'
    )
    items = nikto.parse_report(report)
    assert len(items) == 1
    assert items[0]["full_url"] == "http://plain.example.com/"
    assert items[0]["severity"] == "info"


def test_empty_and_invalid_tolerated():
    assert nikto.parse_report("") == []
    assert nikto.parse_report("   ") == []
    assert nikto.parse_report("{not json") == []
    assert nikto.parse_report("{}") == []  # object, not the expected array
    assert nikto.parse_report("[]") == []
