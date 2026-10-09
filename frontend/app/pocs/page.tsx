"use client";

import { useEffect, useState } from "react";
import { api, downloadFile } from "@/lib/api";

export default function PocsPage() {
  const [pocs, setPocs] = useState<any[]>([]);
  const [sources, setSources] = useState<any[]>([]);
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);

  function load() {
    api<any[]>("/pocs").then(setPocs).catch((e) => setMsg(e.message));
    api<any[]>("/pocs/sources").then(setSources).catch(() => {});
  }
  useEffect(load, []);

  async function sync() {
    setBusy(true);
    setMsg("");
    try {
      const res: any = await api("/pocs/sync", { method: "POST", body: JSON.stringify({}) });
      setMsg("Sync: " + JSON.stringify(res.results));
      load();
    } catch (e: any) {
      setMsg(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function collect() {
    setBusy(true);
    setMsg("");
    try {
      const res: any = await api("/pocs/collect", {
        method: "POST",
        body: JSON.stringify({ only_uncollected: true, limit: 100 }),
      });
      setMsg(
        `Collected ${res.collected}/${res.requested} artifact(s) — downloaded, hashed, ` +
          `and statically classified. Nothing was executed; all stay UNVERIFIED.`,
      );
      load();
    } catch (e: any) {
      setMsg(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-2xl font-bold">Exploit / PoC Intelligence</h1>
        <div className="flex gap-2">
          <button className="btn-ghost" onClick={collect} disabled={busy}>
            {busy ? "Working…" : "Collect artifacts"}
          </button>
          <button className="btn" onClick={sync} disabled={busy}>
            {busy ? "Syncing…" : "Sync sources"}
          </button>
        </div>
      </div>
      <div className="mb-3 text-sm text-slate-400">
        Local intelligence library. Records are metadata about publicly known
        vulnerabilities &amp; research; nothing here is auto-executed. Matched PoCs
        stay <span className="font-semibold">UNVERIFIED</span> until operator-driven,
        human-approved verification in the isolated lab.
      </div>
      {msg && <div className="card mb-3 text-sm text-sky-300">{msg}</div>}

      <div className="mb-4 flex flex-wrap gap-2">
        {sources.map((s) => (
          <span key={s.id} className="pill border border-edge bg-panel">
            {s.name}: {s.last_status || "not synced"}
          </span>
        ))}
      </div>

      <div className="card overflow-x-auto p-0">
        <table className="w-full">
          <thead>
            <tr>
              <th className="th">Code</th>
              <th className="th">CVE</th>
              <th className="th">Title</th>
              <th className="th">Affected</th>
              <th className="th">Maturity</th>
              <th className="th">Safety</th>
              <th className="th">Artifact</th>
            </tr>
          </thead>
          <tbody>
            {pocs.map((p) => (
              <tr key={p.id}>
                <td className="td font-mono text-xs">{p.poc_code}</td>
                <td className="td text-xs">{p.cve || ""}</td>
                <td className="td">{p.title}</td>
                <td className="td text-xs">
                  {p.affected_slug} {p.version_min}–{p.version_max}
                </td>
                <td className="td text-xs">{p.maturity}</td>
                <td className="td text-xs">{p.safety_classification}</td>
                <td className="td text-xs">
                  {p.artifact_sha256 ? (
                    <button
                      className="text-sky-400"
                      title={`sha256 ${p.artifact_sha256}`}
                      onClick={() =>
                        downloadFile(`/pocs/${p.id}/artifact`, `${p.poc_code}.txt`)
                      }
                    >
                      ⭳ {String(p.artifact_sha256).slice(0, 10)}…
                    </button>
                  ) : (
                    <span className="text-slate-500">—</span>
                  )}
                </td>
              </tr>
            ))}
            {pocs.length === 0 && (
              <tr>
                <td className="td text-slate-400" colSpan={7}>
                  Library empty — click “Sync sources”.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
