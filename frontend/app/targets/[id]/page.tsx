"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { api, sevClass } from "@/lib/api";

export default function TargetDetail() {
  const { id } = useParams<{ id: string }>();
  const [target, setTarget] = useState<any>(null);
  const [auths, setAuths] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [plugins, setPlugins] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [showAuth, setShowAuth] = useState(false);
  const [authForm, setAuthForm] = useState({ authorized_by: "", expiration_date: "", scope: "" });

  const load = useCallback(async () => {
    const [t, a, f, p, s] = await Promise.all([
      api(`/targets/${id}`),
      api(`/targets/${id}/authorizations`),
      api(`/findings?target_id=${id}`),
      api(`/targets/${id}/plugins`),
      api(`/scans?target_id=${id}`),
    ]);
    setTarget(t);
    setAuths(a as any[]);
    setFindings(f as any[]);
    setPlugins(p as any[]);
    setScans(s as any[]);
  }, [id]);

  useEffect(() => {
    load().catch((e) => setMsg(e.message));
  }, [load]);

  async function authorize(e: React.FormEvent) {
    e.preventDefault();
    setMsg("");
    try {
      const body: any = {
        auth_type: "written_consent",
        authorized_by: authForm.authorized_by,
        allowed_scope: authForm.scope ? authForm.scope.split(",").map((s) => s.trim()) : [],
        max_intensity: "standard",
      };
      if (authForm.expiration_date) body.expiration_date = `${authForm.expiration_date}T23:59:59+00:00`;
      const created: any = await api(`/targets/${id}/authorizations`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      await api(`/targets/${id}/authorizations/${created.id}/status`, {
        method: "POST",
        body: JSON.stringify({ status: "active" }),
      });
      setShowAuth(false);
      await load();
    } catch (e: any) {
      setMsg(e.message);
    }
  }

  async function fullAudit() {
    setBusy(true);
    setMsg("");
    try {
      const scan: any = await api(`/targets/${id}/scan`, {
        method: "POST",
        body: JSON.stringify({ profile: target?.scan_profile || "standard", mode: "production" }),
      });
      setMsg(`Scan ${scan.id.slice(0, 8)} ${scan.status}. A report is generated automatically.`);
      await load();
      // One-click: open the auto-generated report for this scan if it's ready.
      try {
        const reps: any[] = await api(`/reports?target_id=${id}`);
        const rep = reps.find((r) => r.scan_id === scan.id && r.status === "ready");
        if (rep) {
          window.open(
            `${process.env.NEXT_PUBLIC_API_BASE || "/api"}/reports/${rep.id}/download`,
            "_blank",
          );
        }
      } catch {
        /* report may still be generating on a worker; the scan row has a Report button */
      }
    } catch (e: any) {
      setMsg(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function report(scanId: string) {
    try {
      const rep: any = await api(`/scans/${scanId}/report`, {
        method: "POST",
        body: JSON.stringify({ report_format: "html", title: `Report ${target.name}` }),
      });
      window.open(`${process.env.NEXT_PUBLIC_API_BASE || "/api"}/reports/${rep.id}/download`, "_blank");
    } catch (e: any) {
      setMsg(e.message);
    }
  }

  if (!target) return <div className="text-slate-400">Loading…</div>;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">{target.name}</h1>
          <div className="text-sm text-slate-400">{target.base_url}</div>
        </div>
        <div className="flex items-center gap-2">
          {target.authorized ? (
            <span className="pill bg-emerald-600 text-white">authorized</span>
          ) : (
            <span className="pill bg-red-700 text-white">{target.authorization_status}</span>
          )}
          <button className="btn-ghost" onClick={() => setShowAuth((v) => !v)}>
            Authorize
          </button>
          <button className="btn" disabled={!target.authorized || busy} onClick={fullAudit}>
            {busy ? "Running…" : "▶ Full Audit"}
          </button>
        </div>
      </div>

      {msg && <div className="card text-sm text-sky-300">{msg}</div>}
      {!target.authorized && (
        <div className="card border-amber-700 text-sm text-amber-300">
          This target is not authorized. Scanning is blocked until an active
          authorization covers this host.
        </div>
      )}

      {showAuth && (
        <form onSubmit={authorize} className="card grid grid-cols-1 gap-3 md:grid-cols-3">
          <input
            className="input"
            placeholder="Authorized by"
            value={authForm.authorized_by}
            onChange={(e) => setAuthForm({ ...authForm, authorized_by: e.target.value })}
          />
          <input
            className="input"
            type="date"
            value={authForm.expiration_date}
            onChange={(e) => setAuthForm({ ...authForm, expiration_date: e.target.value })}
          />
          <input
            className="input"
            placeholder={`scope (default: ${target.host})`}
            value={authForm.scope}
            onChange={(e) => setAuthForm({ ...authForm, scope: e.target.value })}
          />
          <button className="btn md:col-span-3">Create &amp; activate authorization</button>
        </form>
      )}

      <section>
        <h2 className="mb-2 text-lg font-semibold">
          Findings <span className="text-slate-400">({findings.length})</span>
        </h2>
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
                  <td className="td text-xs">{f.verification_status}</td>
                </tr>
              ))}
              {findings.length === 0 && (
                <tr>
                  <td className="td text-slate-400" colSpan={6}>
                    No findings yet — run a Full Audit.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <section>
          <h2 className="mb-2 text-lg font-semibold">
            Plugins <span className="text-slate-400">({plugins.length})</span>
          </h2>
          <div className="card space-y-1 text-sm">
            {plugins.map((p) => (
              <div key={p.id} className="flex justify-between">
                <span>
                  {p.slug} <span className="text-slate-400">{p.version}</span>
                </span>
                {p.vulnerable && <span className="pill bg-red-700 text-white">vuln</span>}
              </div>
            ))}
            {plugins.length === 0 && <div className="text-slate-400">None discovered.</div>}
          </div>
        </section>

        <section>
          <h2 className="mb-2 text-lg font-semibold">Scan history</h2>
          <div className="card space-y-2 text-sm">
            {scans.map((s) => (
              <div key={s.id} className="flex items-center justify-between">
                <span className="font-mono text-xs">{s.id.slice(0, 8)}</span>
                <span>{s.status}</span>
                <button className="btn-ghost" onClick={() => report(s.id)}>
                  Report
                </button>
              </div>
            ))}
            {scans.length === 0 && <div className="text-slate-400">No scans yet.</div>}
          </div>
        </section>
      </div>
    </div>
  );
}
