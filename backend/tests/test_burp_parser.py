"""Unit tests for the Burp Suite REST API v0.1 parser (no I/O, no subprocess)."""

from __future__ import annotations

import json

from app.workers.parsers import burp

# A realistic v0.1 scan-poll response (GET /v0.1/scan/{id}) with two issue_events:
# a high-severity reflected XSS carrying base64-encoded request/response evidence,
# and a low-severity cookie issue with list-only evidence (no request_response).
SAMPLE = """{
  "task_id": "3",
  "scan_status": "succeeded",
  "scan_metrics": {
    "crawl_requests_made": 412,
    "audit_requests_made": 2941,
    "issue_events": 2,
    "crawl_and_audit_progress": 100
  },
  "issue_events": [
    {
      "id": "1",
      "type": "issue_found",
      "issue": {
        "name": "Cross-site scripting (reflected)",
        "type_index": 2097920,
        "serial_number": "4713218792701688832",
        "origin": "https://wp.authorized-target.example",
        "path": "/?s=test",
        "severity": "high",
        "confidence": "certain",
        "caption": "/?s=test [s parameter]",
        "description": "<p>Reflected cross-site scripting arises when data is copied.</p>",
        "remediation": "<p>Validate input and HTML-encode output on the s parameter.</p>",
        "evidence": [
          {
            "type": "FirstOrderEvidence",
            "detail": "The value of the s request parameter is copied into the HTML.",
            "request_response": {
              "url": "https://wp.authorized-target.example/?s=test%3Cx%3E",
              "request": [
                { "type": "DataSegment", "data": "R0VUIC8/cz10ZXN0PHg+IEhUVFAvMS4x" },
                { "type": "HighlightSegment", "data": "cz10ZXN0PHg+" }
              ],
              "response": [
                { "type": "DataSegment", "data": "SFRUUC8xLjEgMjAwIE9L" },
                { "type": "HighlightSegment", "data": "dGVzdDx4Pg==" }
              ],
              "request_time": 1739548800123
            }
          }
        ],
        "internal_data": "eyJwYXJhbSI6InMifQ=="
      }
    },
    {
      "id": "2",
      "type": "issue_found",
      "issue": {
        "name": "TLS cookie without secure flag set",
        "type_index": 5243648,
        "serial_number": "7120044559982135296",
        "origin": "https://wp.authorized-target.example",
        "path": "/wp-login.php",
        "severity": "low",
        "confidence": "firm",
        "caption": "/wp-login.php",
        "description": "<p>The cookie appears to contain a session token.</p>",
        "remediation": "<p>Set the secure flag on all cookies transmitted over HTTPS.</p>",
        "evidence": [
          {
            "type": "InformationListEvidence",
            "detail": "Cookie: wordpress_test_cookie"
          }
        ],
        "internal_data": "eyJjb29raWUiOiJ3b3JkcHJlc3NfdGVzdF9jb29raWUifQ=="
      }
    }
  ]
}"""


def _parsed() -> list[dict]:
    return burp.parse_issues(json.loads(SAMPLE))


def test_parses_both_issue_events():
    issues = _parsed()
    assert len(issues) == 2
    assert issues[0]["title"] == "Cross-site scripting (reflected)"
    assert issues[1]["title"] == "TLS cookie without secure flag set"


def test_url_is_origin_plus_path():
    issues = _parsed()
    assert issues[0]["url"] == "https://wp.authorized-target.example/?s=test"
    assert issues[1]["url"] == "https://wp.authorized-target.example/wp-login.php"


def test_dedup_key_format():
    issues = _parsed()
    assert issues[0]["dedup_key"] == (
        "sig:burp:Cross-site scripting (reflected):https://wp.authorized-target.example/?s=test"
    )


def test_severity_mapping_high_and_low():
    issues = _parsed()
    assert issues[0]["severity"] == "high"
    assert issues[1]["severity"] == "low"


def test_confidence_and_remediation_carried():
    issues = _parsed()
    assert issues[0]["confidence"] == "certain"
    assert issues[1]["confidence"] == "firm"
    assert "HTML-encode output" in issues[0]["remediation"]
    assert "secure flag" in issues[1]["remediation"]


def test_request_response_base64_decoded():
    issues = _parsed()
    # DataSegment + HighlightSegment decoded and concatenated.
    assert issues[0]["request"] == "GET /?s=test<x> HTTP/1.1s=test<x>"
    assert issues[0]["response"] == "HTTP/1.1 200 OKtest<x>"


def test_no_request_response_evidence_yields_empty_snippets():
    issues = _parsed()
    assert issues[1]["request"] == ""
    assert issues[1]["response"] == ""


def test_type_index_preserved():
    issues = _parsed()
    assert issues[0]["type_index"] == 2097920


def test_severity_map_values():
    assert burp.map_severity("high") == "high"
    assert burp.map_severity("medium") == "medium"
    assert burp.map_severity("low") == "low"
    assert burp.map_severity("info") == "info"
    assert burp.map_severity("information") == "info"
    # Burp has no critical band; unknown falls back to info.
    assert burp.map_severity("unknown-band") == "info"
    # false_positive maps to "" (dropped by parse_issues).
    assert burp.map_severity("false_positive") == ""


def test_false_positive_issue_is_dropped():
    data = {
        "issue_events": [
            {
                "type": "issue_found",
                "issue": {
                    "name": "X",
                    "severity": "false_positive",
                    "origin": "https://t.example",
                    "path": "/",
                },
            },
            {
                "type": "issue_found",
                "issue": {
                    "name": "Y",
                    "severity": "medium",
                    "origin": "https://t.example",
                    "path": "/a",
                },
            },
        ]
    }
    issues = burp.parse_issues(data)
    assert len(issues) == 1
    assert issues[0]["title"] == "Y"


def test_issue_without_name_skipped():
    data = {"issue_events": [{"type": "issue_found", "issue": {"severity": "high"}}]}
    assert burp.parse_issues(data) == []


def test_non_issue_found_event_type_skipped():
    data = {
        "issue_events": [
            {"type": "scan_metric", "issue": {"name": "noise", "severity": "high"}},
        ]
    }
    assert burp.parse_issues(data) == []


def test_empty_and_malformed_tolerated():
    assert burp.parse_issues({}) == []
    assert burp.parse_issues({"issue_events": None}) == []
    assert burp.parse_issues({"issue_events": ["junk", 5, None]}) == []
    assert burp.parse_issues("not a dict") == []


def test_task_id_from_location():
    assert burp.task_id_from_location("/v0.1/scan/3") == "3"
    assert burp.task_id_from_location("/v0.1/scan/42/") == "42"
    assert burp.task_id_from_location("") == ""
