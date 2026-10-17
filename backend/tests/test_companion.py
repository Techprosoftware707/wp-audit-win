"""Backend verifier for the companion plugin's signed reports, incl. a
cross-language interop check: the Python verifier must accept a signature
produced by the REAL PHP plugin code (identical canonicalization), and reject
any tampering.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from app.services import companion

_PHP = shutil.which("php")
_SIGNER = os.path.join(
    os.path.dirname(__file__), "..", "..", "wordpress-plugin", "tests", "sign-fixture.php"
)

# A body that stresses canonicalization: unsorted nested keys, a list whose
# order must be preserved, and a non-ASCII character.
_FIXTURE = {
    "b": 1,
    "a": {"y": 2, "x": 1},
    "plugins": [{"slug": "z"}, {"slug": "a"}],
    "note": "café",
}
_KEY = "per-site-secret-123"


def test_verify_accepts_valid_and_rejects_tampered():
    sig = companion.sign(_FIXTURE, _KEY)
    env = {"data": _FIXTURE, "signature": sig}
    assert companion.verify_report(env, _KEY) is True
    assert companion.verify_report(env, "wrong-key") is False
    tampered = {"data": {**_FIXTURE, "b": 2}, "signature": sig}
    assert companion.verify_report(tampered, _KEY) is False
    assert companion.verify_report({"data": _FIXTURE}, _KEY) is False  # no signature


def test_summarize_shape():
    env = {
        "site": "https://ex.test",
        "data": {
            "core": {"version": "6.4.1"},
            "php": {"version": "8.2.0"},
            "plugins": [{"slug": "a", "update_available": True}, {"slug": "b"}],
            "checks": [
                {"id": "debug_display_off", "status": "fail"},
                {"id": "x", "status": "pass"},
            ],
        },
    }
    s = companion.summarize(env)
    assert s["core_version"] == "6.4.1"
    assert s["plugin_count"] == 2 and s["plugins_with_updates"] == 1
    assert s["failing_checks"] == ["debug_display_off"]


@pytest.mark.skipif(not _PHP, reason="php not installed")
def test_python_verifier_matches_php_signature():
    php_sig = subprocess.run(
        [_PHP, _SIGNER, _KEY],
        input=json.dumps(_FIXTURE),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    # Identical canonicalization across languages -> identical digest.
    assert php_sig == companion.sign(_FIXTURE, _KEY)
    # And the end-to-end verify accepts the PHP-produced envelope.
    assert companion.verify_report({"data": _FIXTURE, "signature": php_sig}, _KEY) is True
