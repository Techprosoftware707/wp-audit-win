"""Report generation: HTML, Markdown, JSON, CSV (and PDF when weasyprint is
available). Output is stored in MinIO when reachable, otherwise on local disk;
either way it is retrievable through the download endpoint.
"""

from __future__ import annotations

import csv
import io
import json
import os

from jinja2 import Template
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.base import utcnow
from app.models.enums import SEVERITY_RANK, ReportStatus, Severity
from app.models.finding import Finding
from app.models.report import Report
from app.models.scan import Scan
from app.models.target import Authorization, Target
from app.services import evidence as evidence_service

log = get_logger("reporting")

DATA_DIR = os.environ.get("WPSEC_DATA_DIR", os.path.join(os.getcwd(), "data"))

_HTML_TEMPLATE = Template(
    """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>{{ title }}</title>
<style>
  body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;color:#111;background:#fff}
  .wrap{max-width:900px;margin:0 auto;padding:40px 24px}
  h1{font-size:26px;margin:0 0 4px} h2{font-size:18px;margin:28px 0 8px;border-bottom:2px solid #eee;padding-bottom:4px}
  .muted{color:#666} .pill{display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;font-size:12px}
  .critical{background:#b91c1c}.high{background:#ea580c}.medium{background:#ca8a04}.low{background:#2563eb}.info{background:#6b7280}
  table{border-collapse:collapse;width:100%;margin:8px 0;font-size:14px}
  th,td{border:1px solid #e5e7eb;padding:6px 8px;text-align:left;vertical-align:top}
  th{background:#f9fafb} .grid{display:flex;gap:16px;flex-wrap:wrap}
  .card{border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px;min-width:120px}
  .big{font-size:28px;font-weight:700} code{background:#f3f4f6;padding:1px 4px;border-radius:4px}
  .auth{background:#ecfdf5;border:1px solid #a7f3d0;border-radius:8px;padding:10px 14px}
</style></head><body><div class="wrap">
<h1>{{ title }}</h1>
<div class="muted">Target: {{ target.name }} &middot; {{ target.base_url }} &middot; generated {{ generated_at }}</div>

<div class="auth"><strong>Authorization:</strong>
{% if authorization %}{{ authorization.auth_type }} by {{ authorization.authorized_by or 'n/a' }},
status {{ authorization.status }}, expires {{ authorization.expiration_date or 'n/a' }}.
Scope: {{ authorization.allowed_scope or [target.host] }}{% else %}No authorization record.{% endif %}
</div>

<h2>Executive Summary</h2>
<div class="grid">
  <div class="card"><div class="big">{{ counts.critical }}</div><div class="muted">Critical</div></div>
  <div class="card"><div class="big">{{ counts.high }}</div><div class="muted">High</div></div>
  <div class="card"><div class="big">{{ counts.medium }}</div><div class="muted">Medium</div></div>
  <div class="card"><div class="big">{{ counts.low }}</div><div class="muted">Low</div></div>
  <div class="card"><div class="big">{{ counts.info }}</div><div class="muted">Info</div></div>
  <div class="card"><div class="big">{{ counts.confirmed }}</div><div class="muted">Confirmed</div></div>
</div>

<h2>Scope &amp; Methodology</h2>
<p class="muted">Automated assessment pipeline: discovery, WordPress fingerprint &amp; enumeration,
network/service discovery (nmap), template detection (nuclei), WPScan intelligence, OWASP ZAP
crawling/scanning, authenticated WP-CLI inspection (where configured), finding correlation,
PoC/vulnerability-intelligence matching, risk scoring, and evidence collection.
Scan mode: <code>{{ scan.mode if scan else 'n/a' }}</code>, intensity:
<code>{{ scan.effective_intensity if scan else 'n/a' }}</code>.</p>

<h2>Findings</h2>
<table><thead><tr><th>ID</th><th>Severity</th><th>Risk</th><th>Title</th><th>CVE</th><th>Status</th><th>Detectors</th></tr></thead>
<tbody>
{% for f in findings %}
<tr>
  <td><code>{{ f.finding_code }}</code></td>
  <td><span class="pill {{ f.severity }}">{{ f.severity }}</span></td>
  <td>{{ '%.0f'|format(f.risk_score) }}</td>
  <td>{{ f.title }}{% if f.confirmed %} ✓{% endif %}</td>
  <td>{{ f.cve or '' }}</td>
  <td>{{ f.status }} / {{ f.verification_status }}</td>
  <td>{{ f.detectors|join(', ') }}</td>
</tr>
{% endfor %}
{% if not findings %}<tr><td colspan="7" class="muted">No findings recorded.</td></tr>{% endif %}
</tbody></table>

<h2>Finding Detail &amp; Remediation</h2>
{% for f in findings %}
<h3>{{ f.finding_code }} — {{ f.title }}</h3>
<p><span class="pill {{ f.severity }}">{{ f.severity }}</span> risk {{ '%.1f'|format(f.risk_score) }}
{% if f.cve %}&middot; <code>{{ f.cve }}</code>{% endif %}{% if f.cwe %}&middot; {{ f.cwe }}{% endif %}</p>
<p>{{ f.description }}</p>
{% if f.affected_asset %}<p class="muted">Affected: <code>{{ f.affected_asset }}</code></p>{% endif %}
{% if f.remediation %}<p><strong>Remediation:</strong> {{ f.remediation }}</p>{% endif %}
{% endfor %}

<h2>Timeline</h2>
<p class="muted">Scan started {{ scan.started_at if scan else 'n/a' }}, finished
{{ scan.finished_at if scan else 'n/a' }}.</p>
<hr><p class="muted">Generated by wp-audit-win. Authorized security assessment — handle confidentially.</p>
</div></body></html>""",
    autoescape=True,  # escape finding text (scanner/target-derived) -> no stored XSS
)


def _collect(db: Session, report: Report) -> dict:
    target = db.get(Target, report.target_id)
    scan = db.get(Scan, report.scan_id) if report.scan_id else None
    q = select(Finding).where(Finding.target_id == report.target_id)
    if report.scan_id:
        q = q.where(Finding.scan_id == report.scan_id)
    findings = list(db.execute(q).scalars().all())
    findings.sort(key=lambda f: (-SEVERITY_RANK.get(Severity(f.severity), 0), -f.risk_score))

    counts = {s.value: 0 for s in Severity}
    confirmed = 0
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        if f.confirmed:
            confirmed += 1
    counts["confirmed"] = confirmed

    authorization = None
    if scan and scan.authorization_id:
        authorization = db.get(Authorization, scan.authorization_id)

    return {
        "title": report.title
        or f"Security Assessment — {target.name if target else report.target_id}",
        "target": target,
        "scan": scan,
        "authorization": authorization,
        "findings": findings,
        "counts": counts,
        "generated_at": utcnow().isoformat(timespec="seconds"),
    }


def _finding_dict(f: Finding) -> dict:
    return {
        "finding_code": f.finding_code,
        "title": f.title,
        "severity": f.severity,
        "risk_score": f.risk_score,
        "risk_level": f.risk_level,
        "cve": f.cve,
        "cwe": f.cwe,
        "status": f.status,
        "verification_status": f.verification_status,
        "confirmed": f.confirmed,
        "detectors": f.detectors,
        "affected_asset": f.affected_asset,
        "description": f.description,
        "remediation": f.remediation,
    }


def render(fmt: str, ctx: dict) -> tuple[bytes, str, str]:
    if fmt == "html":
        return _HTML_TEMPLATE.render(**ctx).encode(), "text/html", "html"
    if fmt == "json":
        payload = {
            "title": ctx["title"],
            "generated_at": ctx["generated_at"],
            "target": {
                "name": ctx["target"].name,
                "base_url": ctx["target"].base_url,
                "host": ctx["target"].host,
            }
            if ctx["target"]
            else None,
            "counts": ctx["counts"],
            "findings": [_finding_dict(f) for f in ctx["findings"]],
        }
        return json.dumps(payload, indent=2, default=str).encode(), "application/json", "json"
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(
            [
                "finding_code",
                "severity",
                "risk_score",
                "title",
                "cve",
                "cwe",
                "status",
                "verification_status",
                "detectors",
                "affected_asset",
            ]
        )
        for f in ctx["findings"]:
            w.writerow(
                [
                    f.finding_code,
                    f.severity,
                    f.risk_score,
                    f.title,
                    f.cve or "",
                    f.cwe,
                    f.status,
                    f.verification_status,
                    ",".join(f.detectors or []),
                    f.affected_asset,
                ]
            )
        return buf.getvalue().encode(), "text/csv", "csv"
    if fmt == "markdown":
        return _markdown(ctx).encode(), "text/markdown", "md"
    if fmt == "pdf":
        html = _HTML_TEMPLATE.render(**ctx)
        try:
            from weasyprint import HTML  # optional
        except ImportError as exc:
            raise RuntimeError(
                "PDF output requires the optional 'weasyprint' dependency (pip install wpsec[pdf])"
            ) from exc
        return HTML(string=html).write_pdf(), "application/pdf", "pdf"
    raise ValueError(f"unsupported report format: {fmt}")


def _markdown(ctx: dict) -> str:
    c = ctx["counts"]
    lines = [
        f"# {ctx['title']}",
        "",
        f"_Generated {ctx['generated_at']}_",
        "",
        "## Executive Summary",
        "",
        f"- Critical: {c['critical']}",
        f"- High: {c['high']}",
        f"- Medium: {c['medium']}",
        f"- Low: {c['low']}",
        f"- Info: {c['info']}",
        f"- Confirmed: {c['confirmed']}",
        "",
        "## Findings",
        "",
        "| ID | Severity | Risk | Title | CVE | Status |",
        "|----|----------|------|-------|-----|--------|",
    ]
    for f in ctx["findings"]:
        lines.append(
            f"| {f.finding_code} | {f.severity} | {f.risk_score:.0f} | {f.title} | "
            f"{f.cve or ''} | {f.status}/{f.verification_status} |"
        )
    lines += ["", "## Remediation", ""]
    for f in ctx["findings"]:
        lines.append(f"### {f.finding_code} — {f.title}")
        lines.append(f"{f.description}")
        if f.remediation:
            lines.append(f"**Remediation:** {f.remediation}")
        lines.append("")
    return "\n".join(lines)


def _store(report: Report, data: bytes, ext: str, content_type: str) -> str:
    key = f"reports/{report.id}.{ext}"
    stored = evidence_service.put_artifact(key, data, content_type)
    if stored:
        return f"minio://{key}"
    # Local fallback.
    path = os.path.join(DATA_DIR, "reports")
    os.makedirs(path, exist_ok=True)
    fpath = os.path.join(path, f"{report.id}.{ext}")
    with open(fpath, "wb") as fh:
        fh.write(data)
    return f"file://{fpath}"


def generate(db: Session, report: Report) -> Report:
    report.status = ReportStatus.GENERATING.value
    db.add(report)
    db.flush()
    try:
        ctx = _collect(db, report)
        data, content_type, ext = render(report.report_format, ctx)
        report.storage_key = _store(report, data, ext, content_type)
        report.status = ReportStatus.READY.value
        report.finished_at = utcnow()
    except Exception as exc:  # noqa: BLE001
        report.status = ReportStatus.FAILED.value
        report.error = f"{type(exc).__name__}: {exc}"
        log.exception("report generation failed")
    db.add(report)
    db.flush()
    return report


def load_bytes(report: Report) -> tuple[bytes, str] | None:
    key = report.storage_key
    ext = report.report_format
    content_types = {
        "html": "text/html",
        "json": "application/json",
        "csv": "text/csv",
        "markdown": "text/markdown",
        "pdf": "application/pdf",
    }
    ct = content_types.get(ext, "application/octet-stream")
    if key.startswith("file://"):
        path = key[len("file://") :]
        if os.path.exists(path):
            with open(path, "rb") as fh:
                return fh.read(), ct
        return None
    if key.startswith("minio://"):
        data = evidence_service.get_artifact(key[len("minio://") :])
        return (data, ct) if data is not None else None
    return None
