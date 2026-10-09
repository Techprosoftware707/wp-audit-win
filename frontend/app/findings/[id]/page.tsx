"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { api, sevClass } from "@/lib/api";

const STATUSES = [
  "open", "acknowledged", "in_progress", "fixed",
  "retest_required", "verified_fixed", "accepted_risk", "false_positive",
];
const METHODS = [
  ["version_match", "Version match (offline)"],
  ["endpoint_presence", "Endpoint presence (benign GET)"],
  ["info_exposure", "Info exposure (benign GET)"],
  ["authz_check", "Authorization check (active — needs approval)"],
];

function cveLink(cve: string) {
  return `https://nvd.nist.gov/vuln/detail/${cve}`;
}

export default function FindingDetail() {
  const { id } = useParams<{ id: string }>();
  const [f, setF] = useState<any>(null);
  const [evidence, setEvidence] = useState<any[]>([]);
  const [tests, setTests] = useState<any[]>([]);
  const [method, setMethod] = useState("version_match");
  const [approve, setApprove] = useState(false);
  const [msg, setMsg] = useState("");

  const load = useCallback(async () => {
    const [finding, ev, vt] = await Promise.all([
      api(`/findings/${id}`),
      api(`/findings/${id}/evidence`),
      api(`/findings/${id}/verification`),
    ]);
    setF(finding);
    setEvidence(ev as any[]);
    setTests(vt as any[]);
  }, [id]);

  useEffect(() => {
    load().catch((e) => setMsg(e.message));
  }, [load]);

  async function verify() {
    try {
      setMsg("Running verification…");
      const t: any = await api(`/findings/${id}/verify`, {
        method: "POST",
        body: JSON.stringify({ method, approve }),
      });
      setMsg(`Verification: ${t.status}${t.approved ? "" : " (pending approval)"}`);
      await load();
    } catch (e: any) {
      setMsg(e.message);
    }
  }

  async function setStatus(status: string) {
    try {
      await api(`/findings/${id}/status`, {
        method: "PATCH",
        body: JSON.stringify({ status }),
      });
      await load();
    } catch (e: any) {
      setMsg(e.message);
    }
  }

  if (!f) return <div className="text-slate-400">Loading…</div>;

  return (
    <div className="space-y-5">
      <div>
        <div className="flex items-center gap-2">
          <span className={sevClass(f.severity)}>{f.severity}</span>
          <h1 className="text-xl font-bold">{f.title}</h1>
          {f.confirmed && <span className="pill bg-emerald-600 text-white">confirmed</span>}
        </div>
        <div className="mt-1 font-mono text-xs text-slate-400">
          {f.finding_code} · risk {Math.round(f.risk_score)} ({f.risk_level}) ·{" "}
          verification: {f.verification_status}
        </div>
      </div>

      {msg && <div className="card text-sm text-sky-300">{msg}</div>}

      <div className="card space-y-2">
        <p>{f.description}</p>
        {f.affected_asset && (
          <p className="text-sm text-slate-400">Affected: <code>{f.affected_asset}</code></p>
        )}
        <p className="text-sm text-slate-400">
          Detectors: {(f.detectors || []).join(", ") || "—"}
          {f.cwe ? ` · ${f.cwe}` : ""}
          {f.cve ? (
            <>
              {" · "}
              <a className="text-sky-400" href={cveLink(f.cve)} target="_blank" rel="noreferrer">
                {f.cve}
              </a>
            </>
          ) : null}
        </p>
        {f.remediation && (
          <p className="text-sm"><span className="font-semibold">Remediation:</span> {f.remediation}</p>
        )}
      </div>

      {/* status workflow incl. retest */}
      <div className="card">
        <div className="mb-2 text-sm font-semibold">Status: {f.status}</div>
        <div className="flex flex-wrap gap-2">
          {STATUSES.map((s) => (
            <button
              key={s}
              className={`btn-ghost ${f.status === s ? "border-sky-500 text-sky-300" : ""}`}
              onClick={() => setStatus(s)}
            >
              {s.replaceAll("_", " ")}
            </button>
          ))}
        </div>
      </div>

      {/* safe verification */}
      <div className="card">
        <div className="mb-2 text-sm font-semibold">Verify (safe, non-destructive)</div>
        <div className="flex flex-wrap items-center gap-2">
          <select className="input w-72" value={method} onChange={(e) => setMethod(e.target.value)}>
            {METHODS.map(([v, label]) => (
              <option key={v} value={v}>{label}</option>
            ))}
          </select>
          <label className="flex items-center gap-1 text-xs text-slate-400">
            <input type="checkbox" checked={approve} onChange={(e) => setApprove(e.target.checked)} />
            approve active method
          </label>
          <button className="btn" onClick={verify}>Run verification</button>
        </div>
        <div className="mt-3 space-y-1 text-xs">
          {tests.map((t) => (
            <div key={t.id} className="text-slate-300">
              {t.method}: <span className="text-slate-100">{t.status}</span>
              {t.approved ? "" : " (pending approval)"} — {t.notes}
            </div>
          ))}
          {tests.length === 0 && <div className="text-slate-500">No verification runs yet.</div>}
        </div>
      </div>

      {/* evidence */}
      <div>
        <h2 className="mb-2 text-lg font-semibold">
          Evidence <span className="text-slate-400">({evidence.length})</span>
        </h2>
        <div className="space-y-3">
          {evidence.map((e) => (
            <div key={e.id} className="card">
              <div className="mb-1 text-xs text-slate-400">
                {e.scanner} · {e.kind} · sha256 {String(e.sha256).slice(0, 16)}…
                {e.http_status ? ` · HTTP ${e.http_status}` : ""}
              </div>
              {e.request && (
                <pre className="overflow-x-auto rounded bg-ink p-2 text-xs text-slate-300">
{e.request}</pre>
              )}
              {(e.response || e.body_excerpt) && (
                <pre className="mt-1 overflow-x-auto rounded bg-ink p-2 text-xs text-slate-300">
{(e.response || e.body_excerpt).slice(0, 4000)}</pre>
              )}
            </div>
          ))}
          {evidence.length === 0 && <div className="card text-slate-500">No evidence captured.</div>}
        </div>
      </div>
    </div>
  );
}
