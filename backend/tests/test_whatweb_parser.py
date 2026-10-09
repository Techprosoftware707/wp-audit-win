"""Unit tests for the whatweb JSON parser (no I/O, no subprocess)."""

from __future__ import annotations

from app.workers.parsers import whatweb

# whatweb 0.5.5 output (--quiet --log-json=/dev/stdout) for two targets. The
# field values are the verbatim bytes; the JSON is pretty-printed (parsed whole
# via json.loads, so formatting is irrelevant) to honor the 100-char limit, and
# the array/between-object "," structure is preserved.
SAMPLE = """[
{
  "target": "https://wordpress.org/",
  "http_status": 200,
  "request_config": {"headers": {"User-Agent": "WhatWeb/0.5.5"}},
  "plugins": {
    "Country": {"string": ["UNITED STATES"], "module": ["US"]},
    "Frame": {},
    "HTML5": {},
    "HTTPServer": {"string": ["nginx"]},
    "IP": {"string": ["66.6.42.252"]},
    "MetaGenerator": {"string": ["WordPress 7.2-alpha-64244"]},
    "nginx": {},
    "Open-Graph-Protocol": {"version": ["website"]},
    "Script": {"string": ["application/json", "application/ld+json", "module"]},
    "Strict-Transport-Security": {"string": ["max-age=3600"]},
    "Title": {"string": ["Blog Tool, Publishing Platform, and CMS - WordPress.org"]},
    "UncommonHeaders": {"string": ["x-olaf,link,alt-svc,x-nc"]},
    "WordPress": {},
    "X-Frame-Options": {"string": ["SAMEORIGIN"]}
  }
}
,
{
  "target": "https://example.com",
  "http_status": 200,
  "request_config": {"headers": {"User-Agent": "WhatWeb/0.5.5"}},
  "plugins": {
    "Allow": {"module": ["GET, HEAD"]},
    "Country": {"string": ["RESERVED"], "module": ["ZZ"]},
    "HTML5": {},
    "HTTPServer": {"string": ["cloudflare"]},
    "IP": {"string": ["172.66.147.243"]},
    "Script": {},
    "Title": {"string": ["Example Domain"]},
    "UncommonHeaders": {"string": ["cf-cache-status,cf-ray,alt-svc"]}
  }
}
]"""


def test_parse_returns_list_of_target_objects():
    data = whatweb.parse(SAMPLE)
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["target"] == "https://wordpress.org/"
    assert data[1]["target"] == "https://example.com"


def test_technologies_filters_metadata_denylist():
    data = whatweb.parse(SAMPLE)
    techs = whatweb.technologies(data[0])
    names = {t["name"] for t in techs}
    # Real technologies survive.
    assert "WordPress" in names
    assert "MetaGenerator" in names
    assert "HTTPServer" in names
    assert "nginx" in names
    # Metadata / header plugins are filtered out.
    for denied in (
        "IP",
        "Country",
        "Title",
        "UncommonHeaders",
        "Script",
        "Frame",
        "HTML5",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "Open-Graph-Protocol",
    ):
        assert denied not in names


def test_version_regex_from_string_field():
    data = whatweb.parse(SAMPLE)
    techs = {t["name"]: t for t in whatweb.technologies(data[0])}
    # Version pulled via regex from the "string" array.
    assert techs["MetaGenerator"]["version"] == "7.2-alpha-64244"
    # Empty-match plugin with no version info.
    assert techs["WordPress"]["version"] == ""
    assert techs["nginx"]["version"] == ""


def test_category_mapping():
    data = whatweb.parse(SAMPLE)
    techs = {t["name"]: t for t in whatweb.technologies(data[0])}
    assert techs["WordPress"]["category"] == "cms"
    assert techs["MetaGenerator"]["category"] == "cms"
    assert techs["HTTPServer"]["category"] == "web-server"
    assert techs["nginx"]["category"] == "web-server"
    # Second target: cloudflare -> cdn.
    techs2 = {t["name"]: t for t in whatweb.technologies(data[1])}
    assert techs2["HTTPServer"]["category"] == "web-server"


def test_confidence_absent_defaults_to_100():
    data = whatweb.parse(SAMPLE)
    techs = whatweb.technologies(data[0])
    for t in techs:
        assert t["confidence"] == 100


def test_certainty_present_sets_confidence():
    # -a 3 produces a plugin carrying explicit version + certainty (e.g. jQuery).
    raw = (
        '[{"target":"https://t.example","plugins":{"jQuery":{"certainty":75,"version":["3.6.0"]}}}]'
    )
    data = whatweb.parse(raw)
    techs = {t["name"]: t for t in whatweb.technologies(data[0])}
    assert techs["jQuery"]["confidence"] == 75
    assert techs["jQuery"]["version"] == "3.6.0"
    assert techs["jQuery"]["category"] == "javascript-library"


def test_version_from_version_array_preferred():
    raw = '[{"target":"x","plugins":{"PHP":{"version":["8.2.1"]}}}]'
    data = whatweb.parse(raw)
    techs = whatweb.technologies(data[0])
    assert techs[0]["version"] == "8.2.1"
    assert techs[0]["category"] == "language"


def test_stack_labels_sorted_and_versioned():
    data = whatweb.parse(SAMPLE)
    labels = whatweb.stack_labels(whatweb.technologies(data[0]))
    assert "MetaGenerator v7.2-alpha-64244" in labels
    assert "WordPress" in labels
    assert labels == sorted(labels)


def test_empty_and_invalid_tolerated():
    assert whatweb.parse("") == []
    assert whatweb.parse("   ") == []
    assert whatweb.parse("[\n]") == []
    assert whatweb.parse("{not json") == []
    # Object instead of the expected array.
    assert whatweb.parse('{"target":"x"}') == []


def test_technologies_on_object_without_plugins():
    assert whatweb.technologies({"target": "x"}) == []
    assert whatweb.technologies({"target": "x", "plugins": None}) == []
