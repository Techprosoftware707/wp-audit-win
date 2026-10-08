"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

export default function WorkersPage() {
  const [workers, setWorkers] = useState<any[]>([]);
  const [err, setErr] = useState("");
  useEffect(() => {
    const load = () => api<any[]>("/workers").then(setWorkers).catch((e) => setErr(e.message));
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);
  return (
    <div>
      <h1 className="mb-4 text-2xl font-bold">Workers</h1>
      {err && <div className="text-red-400">{err}</div>}
      <div className="card overflow-x-auto p-0">
        <table className="w-full">
          <thead>
            <tr>
              <th className="th">Name</th>
              <th className="th">Status</th>
              <th className="th">Queues</th>
              <th className="th">Jobs</th>
              <th className="th">CPU</th>
              <th className="th">RAM (MB)</th>
              <th className="th">Last heartbeat</th>
            </tr>
          </thead>
          <tbody>
            {workers.map((w) => (
              <tr key={w.id}>
                <td className="td">{w.name}</td>
                <td className="td">
                  <span
                    className={`pill ${
                      w.status === "offline" ? "bg-slate-600" : "bg-emerald-600"
                    } text-white`}
                  >
                    {w.status}
                  </span>
                </td>
                <td className="td text-xs">{w.queues}</td>
                <td className="td">{w.job_count}</td>
                <td className="td">{w.cpu_percent}</td>
                <td className="td">{w.ram_mb}</td>
                <td className="td text-xs">{w.last_heartbeat || ""}</td>
              </tr>
            ))}
            {workers.length === 0 && (
              <tr>
                <td className="td text-slate-400" colSpan={7}>
                  No workers registered. Start the stack (workers register on boot).
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
