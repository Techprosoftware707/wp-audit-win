"""Unit tests for the ffuf JSON output parser (no I/O, no subprocess)."""

from __future__ import annotations

from app.workers.parsers import ffuf

# Realistic ffuf (-of json -o /dev/stdout) report: single JSON object with a
# "results" array, one entry per matched request.
SAMPLE = """{
  "commandline": "ffuf -u https://wp.example.com/FUZZ -w wl.txt -of json -o /dev/stdout",
  "time": "2026-10-08T14:00:00Z",
  "results": [
    {
      "input": {"FUZZ": ".git/HEAD"},
      "position": 1,
      "status": 200,
      "length": 23,
      "words": 2,
      "lines": 1,
      "content-type": "text/plain",
      "redirectlocation": "",
      "url": "https://wp.example.com/.git/HEAD",
      "host": "wp.example.com"
    },
    {
      "input": {"FUZZ": "wp-config.php.bak"},
      "position": 2,
      "status": 200,
      "length": 2871,
      "words": 410,
      "lines": 92,
      "content-type": "application/octet-stream",
      "redirectlocation": "",
      "url": "https://wp.example.com/wp-config.php.bak",
      "host": "wp.example.com"
    },
    {
      "input": {"FUZZ": ".env"},
      "position": 3,
      "status": 200,
      "length": 512,
      "words": 40,
      "lines": 18,
      "content-type": "text/plain",
      "redirectlocation": "",
      "url": "https://wp.example.com/.env",
      "host": "wp.example.com"
    },
    {
      "input": {"FUZZ": "backup"},
      "position": 4,
      "status": 301,
      "length": 0,
      "words": 0,
      "lines": 0,
      "content-type": "text/html",
      "redirectlocation": "https://wp.example.com/backup/",
      "url": "https://wp.example.com/backup",
      "host": "wp.example.com"
    },
    {
      "input": {"FUZZ": "wp-content/debug.log"},
      "position": 5,
      "status": 200,
      "length": 10240,
      "words": 1200,
      "lines": 300,
      "content-type": "text/plain",
      "redirectlocation": "",
      "url": "https://wp.example.com/wp-content/debug.log",
      "host": "wp.example.com"
    },
    {
      "input": {"FUZZ": "wp-content"},
      "position": 6,
      "status": 301,
      "length": 0,
      "words": 0,
      "lines": 0,
      "content-type": "text/html",
      "redirectlocation": "https://wp.example.com/wp-content/",
      "url": "https://wp.example.com/wp-content",
      "host": "wp.example.com"
    },
    {
      "input": {"FUZZ": "wp-login.php"},
      "position": 7,
      "status": 200,
      "length": 4096,
      "words": 500,
      "lines": 120,
      "content-type": "text/html; charset=UTF-8",
      "redirectlocation": "",
      "url": "https://wp.example.com/wp-login.php",
      "host": "wp.example.com"
    }
  ]
}"""


def test_parse_hits_yields_every_result():
    hits = ffuf.parse_hits(SAMPLE)
    assert len(hits) == 7
    by_word = {h["word"]: h for h in hits}
    assert by_word[".git/HEAD"]["url"] == "https://wp.example.com/.git/HEAD"
    assert by_word[".git/HEAD"]["status"] == 200
    assert by_word[".git/HEAD"]["length"] == 23
    assert by_word[".git/HEAD"]["content_type"] == "text/plain"


def test_secret_config_hits_are_high():
    assert ffuf.classify_exposure(".git/HEAD", "https://h/.git/HEAD") == ("high", ".git")
    assert ffuf.classify_exposure("wp-config.php.bak", "https://h/wp-config.php.bak") == (
        "high",
        "wp-config.php.bak",
    )
    assert ffuf.classify_exposure(".env", "https://h/.env") == ("high", ".env")
    assert ffuf.classify_exposure("site.svn/entries", "")[0] == "high"


def test_other_sensitive_hits_are_medium():
    assert ffuf.classify_exposure("backup", "https://h/backup") == ("medium", "backup")
    assert ffuf.classify_exposure("wp-content/debug.log", "https://h/debug.log") == (
        "medium",
        "debug.log",
    )


def test_ordinary_hits_are_not_classified():
    assert ffuf.classify_exposure("wp-content", "https://h/wp-content") is None
    assert ffuf.classify_exposure("wp-login.php", "https://h/wp-login.php") is None
    assert ffuf.classify_exposure("", "") is None


def test_classification_is_case_insensitive():
    assert ffuf.classify_exposure("WP-CONFIG.PHP.BAK", "")[0] == "high"
    assert ffuf.classify_exposure("Backup", "")[0] == "medium"


def test_full_sample_classification_counts():
    hits = ffuf.parse_hits(SAMPLE)
    verdicts = [ffuf.classify_exposure(h["word"], h["url"]) for h in hits]
    severities = [v[0] for v in verdicts if v]
    assert severities.count("high") == 3  # .git, wp-config.php.bak, .env
    assert severities.count("medium") == 2  # backup, debug.log
    assert verdicts.count(None) == 2  # wp-content, wp-login.php


def test_empty_and_invalid_tolerated():
    assert ffuf.parse_hits("") == []
    assert ffuf.parse_hits("   ") == []
    assert ffuf.parse_hits("{not json") == []
    assert ffuf.parse_hits("[]") == []  # array, not the expected object
    assert ffuf.parse_hits('{"results": []}') == []
