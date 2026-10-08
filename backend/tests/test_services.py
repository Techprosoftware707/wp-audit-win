"""Unit tests for core services: risk, versions, crypto, queue."""

from __future__ import annotations

from app.core import crypto
from app.core.redis import MemoryJobQueue
from app.services import risk, versions


def test_risk_bands():
    s, level, _ = risk.score(risk.RiskInputs(severity="critical", cvss_score=9.8, kev=True))
    assert level == "critical" and s >= 85
    s2, level2, _ = risk.score(risk.RiskInputs(severity="info"))
    assert level2 in ("info", "low") and s2 < 40


def test_risk_verification_lowers_not_vulnerable():
    high = risk.score(risk.RiskInputs(severity="high", verification_status="confirmed"))[0]
    notv = risk.score(risk.RiskInputs(severity="high", verification_status="not_vulnerable"))[0]
    assert notv < high


def test_version_ranges():
    assert versions.in_affected_range("1.0.5", "1.0.0", "1.0.9", "1.1.0")
    assert not versions.in_affected_range("1.1.0", "1.0.0", "1.0.9", "1.1.0")  # fixed
    assert not versions.in_affected_range("0.9", "1.0.0", "", "")  # below min
    assert versions.in_affected_range("", "1.0.0", "2.0.0", "")  # unknown -> possibly affected


def test_crypto_roundtrip():
    token = crypto.encrypt("super-secret")
    assert token != "super-secret"
    assert crypto.decrypt(token) == "super-secret"


def test_memory_queue_fifo():
    q = MemoryJobQueue()
    q.enqueue("default", {"a": 1})
    q.enqueue("default", {"a": 2})
    assert q.size("default") == 2
    assert q.dequeue(["default"], timeout=1)["a"] == 1
    assert q.dequeue(["default"], timeout=1)["a"] == 2
    assert q.dequeue(["default"], timeout=1) is None
