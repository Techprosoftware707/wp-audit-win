"""Auto-report step — the final stage of a one-click Full Audit.

Generates a report for the scan automatically so a single click yields a
downloadable deliverable. Resilient: a reporting failure is recorded on the
Report row and never fails the scan.
"""

from __future__ import annotations

from app.core.config import settings
from app.models.report import Report
from app.services import reporting
from app.workers.base import StepContext


def run(ctx: StepContext) -> dict:
    fmt = settings.auto_report_format or "html"
    report = Report(
        target_id=ctx.target.id,
        scan_id=ctx.scan.id,
        title=f"Full Audit — {ctx.target.name}",
        report_format=fmt,
        params={"auto": True},
        created_by=ctx.scan.created_by,
    )
    ctx.db.add(report)
    ctx.db.flush()
    reporting.generate(ctx.db, report)
    return {
        "report_id": report.id,
        "format": fmt,
        "status": report.status,
        "storage_key": report.storage_key,
    }
