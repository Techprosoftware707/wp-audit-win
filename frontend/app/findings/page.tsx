"use client";

import { useEffect, useState } from "react";
import { api, sevClass } from "@/lib/api";

export default function FindingsPage() {
  const [findings, setFindings] = useState<any[]>([]);
  const [sev, setSev] = useState("");
  const [err, setErr] = useState("");

  function load() {
    const q = sev ? `?severity=${sev}` : "";
    api<any[]>(`/findings${q}`).then(setFindings).catch((e) => setErr(e.message));
  }
  useEffect(load, [sev]);

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-2xl font-bold">Findings</h1>
        <select className="input w-40" value={sev} onChange={(e) => setSev(e.target.value)}>
          <option value="">all severities</option>
          {["critical", "high", "medium", "low", "info"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>
      {err && <div className="text-red-400">{err}</div>}
      <div className="card overflow-x-auto p-0">
        <table className="w-full">
          <thead>
            <tr>
              <th className="th">ID</th>
              <th className="th">Sev</th>
              <th className="th">Risk</th>
              <th className="th">Title</th>
              <th className="th">CVE</th>
              <th className="th">Detectors</th>
              <th className="th">Status</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id}>
                <td className="td font-mono text-xs">{f.finding_code}</td>
                <td className="td">
                  <span className={sevClass(f.severity)}>{f.severity}</span>
                </td>
                <td className="td">{Math.round(f.risk_score)}</td>
                <td className="td">
                  {f.title}
                  {f.confirmed && <span className="ml-1 text-emerald-400">✓</span>}
                </td>
                <td className="td text-xs">{f.cve || ""}</td>
                <td className="td text-xs">{(f.detectors || []).join(", ")}</td>
                <td className="td text-xs">{f.status}</td>
              </tr>
            ))}
            {findings.length === 0 && (
              <tr>
                <td className="td text-slate-400" colSpan={7}>
                  No findings.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
