"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type Target = {
  id: string;
  name: string;
  base_url: string;
  host: string;
  owner: string;
  scan_profile: string;
  authorized: boolean;
  authorization_status: string;
};

export default function TargetsPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [err, setErr] = useState("");
  const [show, setShow] = useState(false);
  const [form, setForm] = useState({ name: "", base_url: "", owner: "", scan_profile: "safe" });

  async function load() {
    try {
      setTargets(await api<Target[]>("/targets"));
    } catch (e: any) {
      setErr(e.message);
    }
  }
  useEffect(() => {
    load();
  }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api("/targets", {
        method: "POST",
        body: JSON.stringify({ ...form, max_intensity: "standard" }),
      });
      setShow(false);
      setForm({ name: "", base_url: "", owner: "", scan_profile: "safe" });
      load();
    } catch (e: any) {
      setErr(e.message);
    }
  }

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-2xl font-bold">Targets</h1>
        <button className="btn" onClick={() => setShow((v) => !v)}>
          + Add target
        </button>
      </div>
      {err && <div className="mb-3 text-red-400">{err}</div>}

      {show && (
        <form onSubmit={create} className="card mb-4 grid grid-cols-1 gap-3 md:grid-cols-4">
          <input
            className="input"
            placeholder="Name"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
          />
          <input
            className="input"
            placeholder="https://example.com"
            value={form.base_url}
            onChange={(e) => setForm({ ...form, base_url: e.target.value })}
          />
          <input
            className="input"
            placeholder="Owner"
            value={form.owner}
            onChange={(e) => setForm({ ...form, owner: e.target.value })}
          />
          <select
            className="input"
            value={form.scan_profile}
            onChange={(e) => setForm({ ...form, scan_profile: e.target.value })}
          >
            {["passive", "safe", "standard", "aggressive"].map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
          <button className="btn md:col-span-4">Create</button>
        </form>
      )}

      <div className="card overflow-x-auto p-0">
        <table className="w-full">
          <thead>
            <tr>
              <th className="th">Name</th>
              <th className="th">Host</th>
              <th className="th">Authorization</th>
              <th className="th">Profile</th>
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
                <td className="td">{t.scan_profile}</td>
              </tr>
            ))}
            {targets.length === 0 && (
              <tr>
                <td className="td text-slate-400" colSpan={4}>
                  No targets yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
