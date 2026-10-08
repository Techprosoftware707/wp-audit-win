"""Unit tests for the semgrep JSON parser (no I/O, no subprocess)."""

from __future__ import annotations

from app.workers.parsers import semgrep

# Realistic semgrep 1.122.0 --json output (single top-level object).
SAMPLE = """{
  "version": "1.122.0",
  "errors": [],
  "paths": {
    "scanned": [
      "wp-content/plugins/acme-booking/includes/db.php",
      "wp-content/themes/acme/search.php"
    ]
  },
  "results": [
    {
      "check_id": "php.lang.security.injection.tainted-sql-string.tainted-sql-string",
      "path": "wp-content/plugins/acme-booking/includes/db.php",
      "start": { "line": 42, "col": 9, "offset": 1203 },
      "end": { "line": 42, "col": 71, "offset": 1265 },
      "extra": {
        "message": "Detected a tainted SQL statement built from user input. Use $wpdb->prepare().",
        "metadata": {
          "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
          "owasp": ["A03:2021 - Injection"],
          "category": "security",
          "technology": ["php", "wordpress"],
          "confidence": "HIGH"
        },
        "severity": "ERROR",
        "fingerprint": "6a2f41c9d0e8b73a2f1c5e40d9a7b31e",
        "lines": "        $wpdb->query( \\"SELECT * FROM {$table} WHERE id = \\" . $_GET['id'] );",
        "is_ignored": false,
        "engine_kind": "OSS",
        "validation_state": "NO_VALIDATOR"
      }
    },
    {
      "check_id": "php.lang.security.injection.echoed-request.echoed-request",
      "path": "wp-content/themes/acme/search.php",
      "start": { "line": 18, "col": 1, "offset": 540 },
      "end": { "line": 18, "col": 38, "offset": 577 },
      "extra": {
        "message": "Detected a request value echoed back without encoding (XSS). Use esc_html().",
        "metadata": {
          "cwe": ["CWE-79: Improper Neutralization of Input During Web Page Generation"],
          "owasp": ["A07:2021 - Cross-Site Scripting (XSS)"],
          "category": "security",
          "technology": ["php", "wordpress"],
          "confidence": "MEDIUM"
        },
        "severity": "WARNING",
        "fingerprint": "b17c9a0244e3f8651d7c0a9b2f3348a0",
        "lines": "echo $_GET['s'];",
        "is_ignored": false,
        "engine_kind": "OSS",
        "validation_state": "NO_VALIDATOR"
      }
    }
  ],
  "skipped_rules": []
}"""


def test_parse_yields_all_results():
    items = semgrep.parse(SAMPLE)
    assert len(items) == 2


def test_severity_mapping():
    items = semgrep.parse(SAMPLE)
    by_id = {it["check_id"]: it for it in items}
    sqli = by_id["php.lang.security.injection.tainted-sql-string.tainted-sql-string"]
    xss = by_id["php.lang.security.injection.echoed-request.echoed-request"]
    # ERROR -> high, WARNING -> medium.
    assert sqli["severity"] == "high"
    assert xss["severity"] == "medium"


def test_path_line_and_cwe():
    items = semgrep.parse(SAMPLE)
    sqli = items[0]
    assert sqli["path"] == "wp-content/plugins/acme-booking/includes/db.php"
    assert sqli["line"] == 42
    assert sqli["cwe"].startswith("CWE-89")
    assert "wp-content/themes/acme/search.php" == items[1]["path"]
    assert items[1]["line"] == 18
    assert items[1]["cwe"].startswith("CWE-79")


def test_message_and_lines_captured():
    items = semgrep.parse(SAMPLE)
    assert "wpdb->prepare" in items[0]["message"]
    assert "$wpdb->query" in items[0]["lines"]
    assert items[1]["message"]


def test_map_severity_values():
    assert semgrep.map_severity("ERROR") == "high"
    assert semgrep.map_severity("WARNING") == "medium"
    assert semgrep.map_severity("INFO") == "low"
    # Unknown / empty default to low (unknown-safe).
    assert semgrep.map_severity("") == "low"
    assert semgrep.map_severity("bogus") == "low"


def test_cwe_absent_is_none():
    text = (
        '{"results":[{"check_id":"r.style.x","path":"a.php",'
        '"start":{"line":3},"extra":{"message":"style note","severity":"INFO",'
        '"metadata":{}}}]}'
    )
    items = semgrep.parse(text)
    assert len(items) == 1
    assert items[0]["cwe"] is None
    assert items[0]["severity"] == "low"


def test_cwe_array_joined():
    text = (
        '{"results":[{"check_id":"r","path":"a.php","start":{"line":1},'
        '"extra":{"message":"m","severity":"ERROR",'
        '"metadata":{"cwe":["CWE-89: SQLi","CWE-564: SQL in ORM"]}}}]}'
    )
    items = semgrep.parse(text)
    assert items[0]["cwe"] == "CWE-89: SQLi; CWE-564: SQL in ORM"


def test_parse_payload_detects_valid_object():
    assert semgrep.parse_payload(SAMPLE) is not None
    assert semgrep.files_scanned(semgrep.parse_payload(SAMPLE)) == 2


def test_empty_and_invalid_tolerated():
    # parse_payload returns None so the step knows to retry / skip.
    assert semgrep.parse_payload("") is None
    assert semgrep.parse_payload("   ") is None
    assert semgrep.parse_payload("{not json") is None
    assert semgrep.parse_payload("[]") is None  # array, not the expected object
    # parse() always returns a list.
    assert semgrep.parse("") == []
    assert semgrep.parse("{not json") == []
    assert semgrep.parse("{}") == []  # object with no results key
    assert semgrep.parse('{"results": "oops"}') == []
    assert semgrep.files_scanned(None) == 0
