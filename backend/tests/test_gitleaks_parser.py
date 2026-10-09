"""Unit tests for the Gitleaks parser (pure; verifies secret redaction)."""

from __future__ import annotations

from app.workers.parsers import gitleaks

SAMPLE = """[
  {
    "Description": "AWS Access Key",
    "RuleID": "aws-access-token",
    "File": "wp-content/plugins/demo/config.php",
    "StartLine": 12,
    "Commit": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
    "Author": "Dev",
    "Date": "2024-01-02T03:04:05Z",
    "Secret": "AKIAIOSFODNN7EXAMPLEKEY",
    "Match": "aws_key = AKIAIOSFODNN7EXAMPLEKEY"
  },
  {
    "Description": "Generic API Key",
    "RuleID": "generic-api-key",
    "File": "wp-config.php",
    "StartLine": 5,
    "Commit": "",
    "Secret": "short"
  }
]"""


def test_parses_all_leaks():
    leaks = gitleaks.parse_report(SAMPLE)
    assert len(leaks) == 2
    assert leaks[0]["rule"] == "aws-access-token"
    assert leaks[0]["file"] == "wp-content/plugins/demo/config.php"
    assert leaks[0]["line"] == 12
    assert leaks[0]["commit"] == "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"


def test_secret_is_redacted_never_raw():
    leaks = gitleaks.parse_report(SAMPLE)
    blob = str(leaks)
    # The raw secret and raw match must never appear in the parsed output.
    assert "AKIAIOSFODNN7EXAMPLEKEY" not in blob
    assert "aws_key = AKIAIOSFODNN7EXAMPLEKEY" not in blob
    # A masked fingerprint is present instead.
    assert leaks[0]["redacted"].startswith("AK")
    assert "chars)" in leaks[0]["redacted"]
    # Short secrets are fully masked.
    assert leaks[1]["redacted"].startswith("***")


def test_empty_and_invalid_tolerated():
    assert gitleaks.parse_report("") == []
    assert gitleaks.parse_report("   ") == []
    assert gitleaks.parse_report("not json") == []
    assert gitleaks.parse_report("{}") == []  # object, not a list
    assert gitleaks.parse_report("[]") == []
