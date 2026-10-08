"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type Stats = {
  total_targets: number;
  authorized_targets: number;
  currently_scanning: number;
  critical_findings: number;
  high_findings: number;
  confirmed_findings: number;
  unverified_findings: number;
  recently_fixed: number;
  poc_library_size: number;
  workers_online: number;
  last_scan_at: string | null;
  next_scheduled_at: string | null;
};

function Stat({ label, value, tone }: { label: string; value: any; tone?: string }) {
  return (
    <div className="card">
      <div className={`text-3xl font-bold ${tone || ""}`}>{value ?? "—"}</div>
      <div className="mt-1 text-xs uppercase tracking-wide text-slate-400">{label}</div>
    </div>
  );
}

export default function Dashboard() {
  const [s, setS] = useState<Stats | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    api<Stats>("/dashboard/stats").then(setS).catch((e) => setErr(e.message));
  }, []);

  return (
    <div>
      <h1 className="mb-4 text-2xl font-bold">Dashboard</h1>
      {err && <div className="text-red-400">{err}</div>}
      {s && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          <Stat label="Total Targets" value={s.total_targets} />
          <Stat label="Authorized" value={s.authorized_targets} tone="text-emerald-400" />
          <Stat label="Scanning Now" value={s.currently_scanning} tone="text-sky-400" />
          <Stat label="Workers Online" value={s.workers_online} />
          <Stat label="Critical" value={s.critical_findings} tone="text-red-400" />
          <Stat label="High" value={s.high_findings} tone="text-orange-400" />
          <Stat label="Confirmed" value={s.confirmed_findings} tone="text-emerald-400" />
          <Stat label="Unverified" value={s.unverified_findings} tone="text-amber-400" />
          <Stat label="Recently Fixed" value={s.recently_fixed} />
          <Stat label="PoC Library" value={s.poc_library_size} />
          <div className="card col-span-2">
            <div className="text-xs uppercase tracking-wide text-slate-400">Last scan</div>
            <div className="text-sm">{s.last_scan_at || "—"}</div>
            <div className="mt-2 text-xs uppercase tracking-wide text-slate-400">Next scheduled</div>
            <div className="text-sm">{s.next_scheduled_at || "—"}</div>
          </div>
        </div>
      )}
      <div className="mt-6 text-sm text-slate-400">
        Workflow: add a target → verify authorization → run a full audit → review
        confirmed findings &amp; evidence → generate a report → retest.
      </div>
    </div>
  );
}
