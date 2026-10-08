"""Regression tests for audit-confirmed security fixes."""
from __future__ import annotations

import datetime as dt

import httpx

from app.core.db import session_scope
from app.models.enums import ScanStatus, StepStatus
from app.models.scan import Scan, ScanStep
from app.models.target import Target
from app.services import scan_orchestrator as orch
from app.workers import http


# --- #1 failed authorization step aborts the whole scan (no downstream run) ---
def test_failed_authorization_step_blocks_downstream():
    with session_scope() as db:
        t = Target(name="x", base_url="http://x.example.test", host="x.example.test")
        db.add(t)
        db.flush()
        scan = Scan(target_id=t.id, status=ScanStatus.RUNNING.value,
                    effective_intensity="standard")
        db.add(scan)
        db.flush()
        db.add_all([
            ScanStep(scan_id=scan.id, name="authorization", queue="default", ordering=0,
                     depends_on=[], status=StepStatus.FAILED.value),
            ScanStep(scan_id=scan.id, name="discovery", queue="fingerprint", ordering=1,
                     depends_on=["authorization"], status=StepStatus.PENDING.value),
            ScanStep(scan_id=scan.id, name="wp_fingerprint", queue="fingerprint", ordering=2,
                     depends_on=["discovery"], status=StepStatus.PENDING.value),
            ScanStep(scan_id=scan.id, name="wpscan", queue="wpscan", ordering=3,
                     depends_on=["wp_fingerprint"], status=StepStatus.PENDING.value),
        ])
        db.flush()

        # Drive the real inline drain loop: a FAILED authorization step must abort
        # the scan so NO downstream step ever runs against the unauthorized target.
        orch.execute_scan_inline(db, scan)
        statuses = {s.name: s.status for s in orch._steps(db, scan)}
        assert statuses["discovery"] == StepStatus.SKIPPED.value
        assert statuses["wp_fingerprint"] == StepStatus.SKIPPED.value
        assert statuses["wpscan"] == StepStatus.SKIPPED.value
        # None of them executed (none reached COMPLETED), and the scan failed.
        assert all(
            s.status != StepStatus.COMPLETED.value
            for s in orch._steps(db, scan)
            if s.name in ("discovery", "wp_fingerprint", "wpscan")
        )
        assert scan.status == ScanStatus.FAILED.value


# --- #3 scanner HTTP client refuses redirects that leave the authorized scope ---
def test_fetch_blocks_redirect_to_cloud_metadata():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "wp.example.test":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta/"})
        return httpx.Response(200, text="SENSITIVE-METADATA")

    http.set_transport_for_tests(httpx.MockTransport(handler))
    try:
        r = http.fetch("http://wp.example.test/", scope=["wp.example.test"])
        assert not r.ok
        assert "scope guard" in r.error
        assert "SENSITIVE-METADATA" not in (r.text or "")
    finally:
        http.set_transport_for_tests(None)


def test_fetch_blocks_offscope_host():
    http.set_transport_for_tests(httpx.MockTransport(lambda req: httpx.Response(200, text="x")))
    try:
        r = http.fetch("http://evil.example.test/", scope=["wp.example.test"])
        assert not r.ok and "scope guard" in r.error
    finally:
        http.set_transport_for_tests(None)


# --- #6 finding_code uses MAX(suffix)+1, surviving correlation deletes ---
def test_finding_code_survives_deletion():
    from app.models.finding import Finding
    from app.workers.base import next_finding_code

    with session_scope() as db:
        t = Target(name="y", base_url="http://y.example.test", host="y.example.test")
        db.add(t)
        db.flush()
        year = dt.datetime.now(dt.UTC).year
        codes = []
        for _ in range(3):
            code = next_finding_code(db)
            codes.append(code)
            db.add(Finding(finding_code=code, target_id=t.id, title="f",
                           dedup_key=f"k{code}", severity="low"))
            db.flush()
        assert codes == [f"FIND-{year}-000001", f"FIND-{year}-000002", f"FIND-{year}-000003"]
        # Correlation deletes a middle finding; the next code must NOT reuse 000003.
        victim = db.execute(
            __import__("sqlalchemy").select(Finding).where(Finding.finding_code == codes[1])
        ).scalar_one()
        db.delete(victim)
        db.flush()
        assert next_finding_code(db) == f"FIND-{year}-000004"
