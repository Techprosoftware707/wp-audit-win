"use client";

import { useState } from "react";
import { api } from "@/lib/api";

/**
 * Owner-authorized administrator recovery & remediation controls.
 *
 * Every state-changing action requires an explicit confirm checkbox + reason,
 * an active authorization, a stored SSH credential, and super-admin rights
 * (recovery:execute) — all enforced server-side. The server backs up the
 * database first and never logs the generated password; it is shown here once.
 */
export default function RecoveryPanel({
  targetId,
  authorized,
}: {
  targetId: string;
  authorized: boolean;
}) {
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  const [detect, setDetect] = useState<any>(null);
  const [newPassword, setNewPassword] = useState<{ what: string; value: string } | null>(null);
  const [result, setResult] = useState<any>(null);

  // form state
  const [pw, setPw] = useState({ user: "", reason: "", confirm: false });
  const [mk, setMk] = useState({ login: "", email: "", reason: "", confirm: false });
  const [up, setUp] = useState({ component_type: "plugin", slug: "", to_version: "", reason: "", confirm: false });

  async function call(label: string, path: string, body: any, onOk: (r: any) => void) {
    setBusy(label);
    setErr("");
    setResult(null);
    try {
      const r = await api(path, { method: "POST", body: JSON.stringify(body) });
      onOk(r);
    } catch (e: any) {
      setErr(e.message || String(e));
    } finally {
      setBusy("");
    }
  }

  return (
    <section>
      <h2 className="mb-2 text-lg font-semibold">Recovery &amp; Remediation</h2>
      <div className="card border-amber-700 mb-3 text-xs text-amber-300">
        Owner-authorized, break-glass actions on a site you control — run over your stored SSH
        credential via WP-CLI. They require an <b>active authorization</b>, an <b>SSH credential</b>,
        and <b>super-admin</b> rights. Every change is <b>backed up first</b> and <b>audited</b>; the
        generated password is shown once and never logged.
        {!authorized && (
          <div className="mt-1 text-red-300">This target is not authorized — actions will be refused.</div>
        )}
      </div>

      {err && <div className="card mb-3 border-red-700 text-sm text-red-300">{err}</div>}

      {newPassword && (
        <div className="card mb-3 border-emerald-700 text-sm">
          <div className="mb-1 font-semibold text-emerald-300">
            {newPassword.what} — save this now; it will not be shown again:
          </div>
          <code className="block overflow-x-auto rounded bg-ink p-2 text-emerald-200">
            {newPassword.value}
          </code>
        </div>
      )}

      {result && (
        <div className="card mb-3 text-xs">
          <pre className="overflow-x-auto text-slate-300">{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {/* Detect (read-only) */}
        <div className="card space-y-2">
          <div className="text-sm font-semibold">Detect admins / lockout</div>
          <p className="text-xs text-slate-400">Read-only: lists administrators and flags lockout or damaged capabilities.</p>
          <button
            className="btn"
            disabled={!!busy}
            onClick={() =>
              call("detect", `/targets/${targetId}/recovery/detect`, {}, (r) => {
                setDetect(r);
                setNewPassword(null);
              })
            }
          >
            {busy === "detect" ? "Detecting…" : "Detect"}
          </button>
          {detect && (
            <div className="text-xs text-slate-300">
              <div>
                administrators: <b>{detect.administrator_count}</b>
                {detect.total_users != null ? ` / ${detect.total_users} users` : ""}
                {detect.locked_out && <span className="ml-2 pill bg-red-700 text-white">locked out</span>}
              </div>
              {(detect.administrators || []).map((a: any) => (
                <div key={a.ID ?? a.user_login} className="text-slate-400">
                  #{a.ID} {a.user_login} — {a.roles || "(no roles)"}
                </div>
              ))}
              {(detect.warnings || []).map((w: string, i: number) => (
                <div key={i} className="text-amber-300">⚠ {w}</div>
              ))}
            </div>
          )}
        </div>

        {/* Reset password */}
        <form
          className="card space-y-2"
          onSubmit={(e) => {
            e.preventDefault();
            setNewPassword(null);
            call(
              "reset",
              `/targets/${targetId}/recovery/reset-password`,
              { user: pw.user, reason: pw.reason, confirm: pw.confirm },
              (r) => {
                setResult({ action: r.action, user: r.user, backup_file: r.backup_file, verified_admin: r.verified_admin, rollback: r.rollback });
                setNewPassword({ what: `New password for ${r.user}`, value: r.new_password });
              },
            );
          }}
        >
          <div className="text-sm font-semibold">Reset an admin&apos;s password</div>
          <input className="input" placeholder="admin login or user ID" value={pw.user} required
            onChange={(e) => setPw({ ...pw, user: e.target.value })} />
          <input className="input" placeholder="reason (audited)" value={pw.reason} required
            onChange={(e) => setPw({ ...pw, reason: e.target.value })} />
          <label className="flex items-center gap-2 text-xs text-slate-400">
            <input type="checkbox" checked={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.checked })} />
            I confirm this change (backup is taken first)
          </label>
          <button className="btn" disabled={!!busy || !pw.confirm}>
            {busy === "reset" ? "Resetting…" : "Reset password"}
          </button>
        </form>

        {/* Create admin */}
        <form
          className="card space-y-2"
          onSubmit={(e) => {
            e.preventDefault();
            setNewPassword(null);
            call(
              "mkadmin",
              `/targets/${targetId}/recovery/create-admin`,
              { login: mk.login, email: mk.email, reason: mk.reason, confirm: mk.confirm },
              (r) => {
                setResult({ action: r.action, login: r.login, user_id: r.user_id, backup_file: r.backup_file, rollback: r.rollback });
                setNewPassword({ what: `Password for new admin ${r.login}`, value: r.new_password });
              },
            );
          }}
        >
          <div className="text-sm font-semibold">Create a new administrator</div>
          <input className="input" placeholder="login" value={mk.login} required
            onChange={(e) => setMk({ ...mk, login: e.target.value })} />
          <input className="input" type="email" placeholder="email" value={mk.email} required
            onChange={(e) => setMk({ ...mk, email: e.target.value })} />
          <input className="input" placeholder="reason (audited)" value={mk.reason} required
            onChange={(e) => setMk({ ...mk, reason: e.target.value })} />
          <label className="flex items-center gap-2 text-xs text-slate-400">
            <input type="checkbox" checked={mk.confirm} onChange={(e) => setMk({ ...mk, confirm: e.target.checked })} />
            I confirm creating an administrator (backup first)
          </label>
          <button className="btn" disabled={!!busy || !mk.confirm}>
            {busy === "mkadmin" ? "Creating…" : "Create admin"}
          </button>
        </form>

        {/* Update component */}
        <form
          className="card space-y-2"
          onSubmit={(e) => {
            e.preventDefault();
            setNewPassword(null);
            const body: any = { component_type: up.component_type, slug: up.slug, reason: up.reason, confirm: up.confirm };
            if (up.to_version) body.to_version = up.to_version;
            call("update", `/targets/${targetId}/remediation/update`, body, (r) => setResult(r));
          }}
        >
          <div className="text-sm font-semibold">Update a component (never downgrades)</div>
          <div className="flex gap-2">
            <select className="input w-32" value={up.component_type}
              onChange={(e) => setUp({ ...up, component_type: e.target.value })}>
              <option value="plugin">plugin</option>
              <option value="theme">theme</option>
            </select>
            <input className="input flex-1" placeholder="slug" value={up.slug} required
              onChange={(e) => setUp({ ...up, slug: e.target.value })} />
          </div>
          <input className="input" placeholder="target version (optional; blank = latest)" value={up.to_version}
            onChange={(e) => setUp({ ...up, to_version: e.target.value })} />
          <input className="input" placeholder="reason (audited)" value={up.reason} required
            onChange={(e) => setUp({ ...up, reason: e.target.value })} />
          <label className="flex items-center gap-2 text-xs text-slate-400">
            <input type="checkbox" checked={up.confirm} onChange={(e) => setUp({ ...up, confirm: e.target.checked })} />
            I confirm this update (backup first)
          </label>
          <button className="btn" disabled={!!busy || !up.confirm}>
            {busy === "update" ? "Updating…" : "Update component"}
          </button>
        </form>
      </div>
    </section>
  );
}
