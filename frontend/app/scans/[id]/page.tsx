"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, downloadFile, sevClass } from "@/lib/api";

const RUNNING = new Set(["queued", "running"]);
const STEP_TONE: Record<string, string> = {
  completed: "text-emerald-400",
  running: "text-sky-400",
  queued: "text-slate-400",
  pending: "text-slate-500",
  skipped: "text-slate-500",
  failed: "text-red-400",
};

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [sev, setSev] = useState("");
  const [msg, setMsg] = useState("");
  const timer = useRef<any>(null);

  const load = useCallback(async () => {
    const s = await api(`/scans/${id}`);
    setScan(s);
    const f = await api(`/findings?scan_id=${id}`);
    setFindings(f as any[]);
    return s;
  }, [id]);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const s = await load();
        if (alive && RUNNING.has(s.status)) {
          timer.current = setTimeout(tick, 2000); // live polling while running
        }
      } catch (e: any) {
        if (alive) setMsg(e.message);
      }
    };
    tick();
    return () => {
      alive = false;
      if (timer.current) clearTimeout(timer.current);
    };
  }, [load]);

  async function stop() {
    try {
      await api(`/scans/${id}/cancel`, { method: "POST" });
      await load();
    } catch (e: any) {
      setMsg(e.message);
    }
  }

  async function exportReport(fmt: string) {
    try {
      setMsg(`Generating ${fmt.toUpperCase()} report…`);
      const rep: any = await api(`/scans/${id}/report`, {
        method: "POST",
        body: JSON.stringify({ report_format: fmt }),
      });
      if (rep.status !== "ready") {
        setMsg(`Report ${rep.status}: ${rep.error || ""}`);
        return;
      }
      const ext = fmt === "markdown" ? "md" : fmt;
      await downloadFile(`/reports/${rep.id}/download`, `report-${String(id).slice(0, 8)}.${ext}`);
      setMsg("");
    } catch (e: any) {
      setMsg(e.message);
    }
  }

  if (!scan) return <div className="text-slate-400">Loading…</div>;
  const steps = scan.steps || [];
  const done = steps.filter((s: any) => ["completed", "skipped", "failed"].includes(s.status)).length;
  const pct = steps.length ? Math.round((done / steps.length) * 100) : 0;
  const failed = steps.filter((s: any) => s.status === "failed");
  const shown = sev ? findings.filter((f) => f.severity === sev) : findings;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">Scan {String(id).slice(0, 8)}</h1>
          <div className="text-sm text-slate-400">
            status <span className="font-semibold">{scan.status}</span> · intensity{" "}
            {scan.effective_intensity} · mode {scan.mode}
          </div>
        </div>
        <div className="flex items-center gap-2">
          {RUNNING.has(scan.status) && (
            <button className="btn-ghost" onClick={stop}>
              ■ Stop scan
            </button>
          )}
          <button className="btn-ghost" onClick={() => exportReport("json")}>Export JSON</button>
          <button className="btn-ghost" onClick={() => exportReport("csv")}>Export CSV</button>
          <button className="btn" onClick={() => exportReport("html")}>Export HTML</button>
        </div>
      </div>

      {msg && <div className="card text-sm text-sky-300">{msg}</div>}

      {/* live progress */}
      <div className="card">
        <div className="mb-2 flex justify-between text-xs text-slate-400">
          <span>Pipeline progress</span>
          <span>{done}/{steps.length} stages ({pct}%)</span>
        </div>
        <div className="h-2 w-full overflow-hidden rounded bg-ink">
          <div className="h-2 bg-sky-500 transition-all" style={{ width: `${pct}%` }} />
        </div>
        <div className="mt-3 grid grid-cols-1 gap-1 md:grid-cols-2">
          {steps.map((s: any) => (
            <div key={s.id} className="flex items-center justify-between text-sm">
              <span className={STEP_TONE[s.status] || ""}>
                {s.status === "completed" ? "✓" : s.status === "failed" ? "✗" : s.status === "skipped" ? "–" : "•"}{" "}
                {s.name}
              </span>
              <span className="text-xs text-slate-500">{s.status}</span>
            </div>
          ))}
        </div>
      </div>

      {/* failed stages are surfaced, not hidden */}
      {failed.length > 0 && (
        <div className="card border-red-800">
          <div className="mb-1 font-semibold text-red-300">Failed stages</div>
          {failed.map((s: any) => (
            <div key={s.id} className="text-sm text-red-300">
              {s.name}: <span className="text-slate-300">{s.error || "failed"}</span>
            </div>
          ))}
        </div>
      )}

      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">
          Findings <span className="text-slate-400">({shown.length})</span>
        </h2>
        <select className="input w-44" value={sev} onChange={(e) => setSev(e.target.value)}>
          <option value="">all severities</option>
          {["critical", "high", "medium", "low", "info"].map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>
      <div className="card overflow-x-auto p-0">
        <table className="w-full">
          <thead>
            <tr>
              <th className="th">ID</th>
              <th className="th">Sev</th>
              <th className="th">Risk</th>
              <th className="th">Title</th>
              <th className="th">CVE</th>
              <th className="th">Verification</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((f) => (
              <tr key={f.id} className="hover:bg-edge/40">
                <td className="td font-mono text-xs">
                  <Link href={`/findings/${f.id}`} className="text-sky-400">
                    {f.finding_code}
                  </Link>
                </td>
                <td className="td"><span className={sevClass(f.severity)}>{f.severity}</span></td>
                <td className="td">{Math.round(f.risk_score)}</td>
                <td className="td">{f.title}{f.confirmed && <span className="ml-1 text-emerald-400">✓</span>}</td>
                <td className="td text-xs">{f.cve || ""}</td>
                <td className="td text-xs">{f.verification_status}</td>
              </tr>
            ))}
            {shown.length === 0 && (
              <tr><td className="td text-slate-400" colSpan={6}>No findings.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
