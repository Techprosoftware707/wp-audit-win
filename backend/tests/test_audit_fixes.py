"""Regression tests for the adversarial-audit fixes (non-auth findings):

- #6 ZAP never falls back to the platform secret_key (skips without a ZAP key)
- #7 final risk pass honours CVSS over the severity band
- #9 PoC classifier flags file_put_contents/fwrite/backtick as intrusive
- #13 correlation reassigns VerificationTest history instead of deleting it
- #5 reaper reconciles cancelled scans; run_step claims a step atomically
"""

from __future__ import annotations

from types import SimpleNamespace

from app.core.config import settings
from app.core.db import SessionLocal
from app.models.enums import SafetyClass
from app.models.finding import Finding, VerificationTest, Vulnerability
from app.models.scan import Scan, ScanStep
from app.models.target import Target
from app.services import risk
from app.services.poc_collector import static_inspect
from app.workers.steps import correlation
from app.workers.steps import zap as zap_step


# -------------------------------------------------------- #9 classifier
def test_classifier_flags_unconditional_file_writes():
    assert (
        static_inspect("<?php file_put_contents('shell.php', $_GET['p']); ?>").safety_class
        is SafetyClass.INTRUSIVE
    )
    assert static_inspect("<?php fwrite($f, $payload); ?>").safety_class is SafetyClass.INTRUSIVE


def test_classifier_flags_fopen_write_mode_and_backtick():
    assert static_inspect("$f = fopen('/tmp/x', 'w');").safety_class is SafetyClass.INTRUSIVE
    assert static_inspect("<?php echo `$cmd`; ?>").safety_class is SafetyClass.INTRUSIVE


# -------------------------------------------------------- #7 risk / CVSS
def test_risk_persists_cvss_and_overrides_severity_band():
    # A 'low'-severity finding with a 9.8 CVSS must score critical, not low.
    score, level, factors = risk.score(risk.RiskInputs(severity="low", cvss_score=9.8))
    assert factors["cvss_score"] == 9.8
    assert score >= 85 and level == "critical"


def test_risk_step_resolves_cvss_from_catalog_when_factors_lack_it():
    # Runs the REAL final risk pass (the distributed worker path) against a finding
    # whose CVSS lives only on the linked Vulnerability catalog entry, not in
    # risk_factors. This guards the step against both the severity-only
    # understatement AND a crash from reading a non-existent column.
    from app.workers.steps import risk_step

    db = SessionLocal()
    try:
        t = Target(name="t", base_url="http://t.test", host="t.test")
        db.add(t)
        db.flush()
        v = Vulnerability(title="v", cve="CVE-2099-7777", cvss_score=9.8, severity="low")
        db.add(v)
        db.flush()
        f = Finding(
            finding_code="F-CVSS",
            target_id=t.id,
            title="x",
            dedup_key="k-cvss",
            severity="low",  # severity says low…
            cve="CVE-2099-7777",
            vulnerability_id=v.id,  # …but the catalog CVSS is 9.8
            risk_factors={},
        )
        db.add(f)
        db.flush()

        out = risk_step.run(SimpleNamespace(db=db, target=t))
        assert out["recomputed"] >= 1
        db.expire_all()
        fr = db.get(Finding, f.id)
        assert fr.risk_level == "critical"  # CVSS 9.8 drives it, not 'low'
        assert fr.risk_factors["cvss_score"] == 9.8
    finally:
        db.close()


# -------------------------------------------------------- #6 ZAP secret leak
def test_zap_skips_without_api_key(monkeypatch):
    monkeypatch.setattr(settings, "zap_api_key", "")
    ctx = SimpleNamespace(target=SimpleNamespace(base_url="http://x.test"), intensity="standard")
    out = zap_step.run(ctx)
    assert out.get("skipped") is True
    assert "ZAP_API_KEY" in out["reason"]


# -------------------------------------------------------- #13 correlation
def test_correlation_reassigns_verification_tests_and_confirmed():
    db = SessionLocal()
    try:
        t = Target(name="t", base_url="http://t.test", host="t.test")
        db.add(t)
        db.flush()
        canonical = Finding(
            finding_code="F-CANON",
            target_id=t.id,
            title="dup issue",
            dedup_key="k-canon",
            cve="CVE-2099-5555",
            severity="high",
            detectors=["nuclei", "wpscan"],
            detector_count=2,
        )
        dup = Finding(
            finding_code="F-DUP",
            target_id=t.id,
            title="dup issue",
            dedup_key="k-dup",
            cve="CVE-2099-5555",
            severity="high",
            detectors=["zap"],
            detector_count=1,
            confirmed=True,
        )
        db.add_all([canonical, dup])
        db.flush()
        vt = VerificationTest(finding_id=dup.id, method="version_match", status="confirmed")
        db.add(vt)
        db.flush()
        vt_id, canon_id, dup_id = vt.id, canonical.id, dup.id

        out = correlation.run(SimpleNamespace(db=db, target=t))
        assert out["merged"] == 1
        db.expire_all()

        assert db.get(Finding, dup_id) is None  # duplicate merged away
        surviving = db.get(VerificationTest, vt_id)
        assert surviving is not None, "verification history must survive the merge"
        assert surviving.finding_id == canon_id
        assert db.get(Finding, canon_id).confirmed is True  # confirmed OR'd in
    finally:
        db.close()


# -------------------------------------------------------- #5 reaper / claim
def test_reaper_reconciles_cancelled_scan():
    from app.services import scan_orchestrator as orch

    db = SessionLocal()
    try:
        t = Target(name="t", base_url="http://t.test", host="t.test")
        db.add(t)
        db.flush()
        scan = Scan(target_id=t.id, status="cancelled")
        db.add(scan)
        db.flush()
        running = ScanStep(scan_id=scan.id, name="nmap", status="running")
        pending = ScanStep(scan_id=scan.id, name="nuclei", status="pending")
        db.add_all([running, pending])
        db.flush()
        ids = (running.id, pending.id)

        orch.reap_stale_scans(db)
        db.expire_all()
        for sid in ids:
            assert db.get(ScanStep, sid).status == "skipped"
    finally:
        db.close()


def test_run_step_atomic_claim_does_not_run_an_already_running_step(monkeypatch):
    from app.services import scan_orchestrator as orch
    from app.workers import steps as steps_mod

    calls = {"n": 0}

    def _probe(ctx):
        calls["n"] += 1
        return {}

    monkeypatch.setattr(steps_mod, "get_registry", lambda: {"_probe": _probe})

    db = SessionLocal()
    try:
        t = Target(name="t", base_url="http://t.test", host="t.test")
        db.add(t)
        db.flush()
        scan = Scan(target_id=t.id, status="running")
        db.add(scan)
        db.flush()
        step = ScanStep(scan_id=scan.id, name="_probe", status="running")  # already claimed
        db.add(step)
        db.flush()
        sid = step.id

        orch.run_step(db, sid)  # claim UPDATE matches 0 rows -> must not execute
        assert calls["n"] == 0

        db.get(ScanStep, sid).status = "queued"
        db.commit()
        orch.run_step(db, sid)  # now claimable -> executes exactly once
        assert calls["n"] == 1
        assert db.get(ScanStep, sid).status == "completed"
    finally:
        db.close()
