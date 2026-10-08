"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

export default function ScansPage() {
  const [scans, setScans] = useState<any[]>([]);
  const [err, setErr] = useState("");
  useEffect(() => {
    api<any[]>("/scans").then(setScans).catch((e) => setErr(e.message));
  }, []);
  return (
    <div>
      <h1 className="mb-4 text-2xl font-bold">Scans</h1>
      {err && <div className="text-red-400">{err}</div>}
      <div className="card overflow-x-auto p-0">
        <table className="w-full">
          <thead>
            <tr>
              <th className="th">ID</th>
              <th className="th">Status</th>
              <th className="th">Intensity</th>
              <th className="th">Critical</th>
              <th className="th">High</th>
              <th className="th">Total</th>
              <th className="th">Started</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id}>
                <td className="td font-mono text-xs">{s.id.slice(0, 8)}</td>
                <td className="td">{s.status}</td>
                <td className="td">{s.effective_intensity}</td>
                <td className="td">{s.summary?.critical ?? 0}</td>
                <td className="td">{s.summary?.high ?? 0}</td>
                <td className="td">{s.summary?.total ?? 0}</td>
                <td className="td text-xs">{s.started_at || ""}</td>
              </tr>
            ))}
            {scans.length === 0 && (
              <tr>
                <td className="td text-slate-400" colSpan={7}>
                  No scans yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
