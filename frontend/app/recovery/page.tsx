"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type Target = {
  id: string;
  name: string;
  host: string;
  authorized: boolean;
  authorization_status: string;
};

type Detect = {
  loading?: boolean;
  error?: string;
  administrator_count?: number;
  total_users?: number | null;
  locked_out?: boolean;
  warnings?: string[];
};

/**
 * Top-level Recovery overview: all targets at a glance with their administrator
 * / lockout status. Recovery is OWNER-DRIVEN — it uses your own SSH/WP-CLI access
 * to a site you own (not an exploit). Detection here is read-only; the actual
 * reset/create/update actions live on each target's detail page, gated by an
 * active authorization, explicit confirmation, and super-admin rights.
 */
export default function RecoveryPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [err, setErr] = useState("");
  const [detect, setDetect] = useState<Record<string, Detect>>({});
  const [busyAll, setBusyAll] = useState(false);

  useEffect(() => {
    api<Target[]>("/targets").then(setTargets).catch((e) => setErr(e.message));
  }, []);

  async function runDetect(id: string) {
    setDetect((d) => ({ ...d, [id]: { loading: true } }));
    try {
      const r = await api(`/targets/${id}/recovery/detect`, { method: "POST", body: "{}" });
      setDetect((d) => ({ ...d, [id]: { ...r } }));
    } catch (e: any) {
      setDetect((d) => ({ ...d, [id]: { error: e.message || String(e) } }));
    }
  }

  async function detectAll() {
    setBusyAll(true);
    try {
      await Promise.allSettled(targets.filter((t) => t.authorized).map((t) => runDetect(t.id)));
    } finally {
      setBusyAll(false);
    }
  }

  function statusCell(t: Target) {
    const d = detect[t.id];
    if (!d) return <span className="text-slate-500">—</span>;
    if (d.loading) return <span className="text-slate-400">detecting…</span>;
    if (d.error) return <span className="text-amber-300" title={d.error}>⚠ {d.error.slice(0, 48)}</span>;
    return (
      <span className="text-slate-300">
        {d.locked_out ? (
          <span className="pill bg-red-700 text-white">locked out</span>
        ) : (
          <>
            <b>{d.administrator_count}</b> admin{d.administrator_count === 1 ? "" : "s"}
            {d.total_users != null ? ` / ${d.total_users} users` : ""}
          </>
        )}
        {(d.warnings || []).length > 0 && (
          <span className="ml-2 text-amber-300" title={(d.warnings || []).join("\n")}>
            ⚠ {(d.warnings || []).length}
          </span>
        )}
      </span>
    );
  }

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-2xl font-bold">Recovery</h1>
        <button className="btn" onClick={detectAll} disabled={busyAll || targets.length === 0}>
          {busyAll ? "Detecting…" : "Detect all authorized"}
        </button>
      </div>

      <div className="card mb-4 border-amber-700 text-xs text-amber-300">
        Owner-driven administrator recovery for sites you control. Detection is read-only (lists
        admins and flags lockout / damaged capabilities) and runs over your stored SSH credential
        via WP-CLI. It is <b>not</b> an exploit and does not grant access through a vulnerability.
        The reset / create-admin / component-update actions live on each target&apos;s detail page
        and require an active authorization, explicit confirmation, and super-admin rights; every
        change is backed up first and audited. Detection needs an SSH credential and an active
        authorization — rows without them report that here.
      </div>

      {err && <div className="mb-3 text-red-400">{err}</div>}

      <div className="card overflow-x-auto p-0">
        <table className="w-full">
          <thead>
            <tr>
              <th className="th">Target</th>
              <th className="th">Host</th>
              <th className="th">Authorization</th>
              <th className="th">Admin status</th>
              <th className="th"></th>
            </tr>
          </thead>
          <tbody>
            {targets.map((t) => (
              <tr key={t.id} className="hover:bg-edge/40">
                <td className="td">
                  <Link href={`/targets/${t.id}`} className="font-medium text-sky-400">
                    {t.name}
                  </Link>
                </td>
                <td className="td">{t.host}</td>
                <td className="td">
                  {t.authorized ? (
                    <span className="pill bg-emerald-600 text-white">authorized</span>
                  ) : (
                    <span className="pill bg-red-700 text-white">
                      {t.authorization_status || "none"}
                    </span>
                  )}
                </td>
                <td className="td text-xs">{statusCell(t)}</td>
                <td className="td text-right">
                  <button
                    className="btn-ghost"
                    disabled={!t.authorized || detect[t.id]?.loading}
                    title={t.authorized ? "Read-only admin detection" : "Authorize the target first"}
                    onClick={() => runDetect(t.id)}
                  >
                    Detect
                  </button>
                  <Link href={`/targets/${t.id}`} className="btn-ghost ml-1">
                    Recover…
                  </Link>
                </td>
              </tr>
            ))}
            {targets.length === 0 && (
              <tr>
                <td className="td text-slate-400" colSpan={5}>
                  No targets yet. Add and authorize one under Targets.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
