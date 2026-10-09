"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { getToken, setToken } from "@/lib/api";

const NAV = [
  ["Dashboard", "/"],
  ["Targets", "/targets"],
  ["Scans", "/scans"],
  ["Findings", "/findings"],
  ["Exploit / PoC", "/pocs"],
  ["Workers", "/workers"],
];

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [authed, setAuthed] = useState<boolean | null>(null);

  const isLogin = pathname === "/login";

  useEffect(() => {
    const t = getToken();
    setAuthed(!!t);
    if (!t && !isLogin) router.replace("/login");
  }, [pathname, isLogin, router]);

  if (isLogin) return <>{children}</>;
  if (authed === null) return <div className="p-8 text-slate-400">Loading…</div>;
  // Never render the authenticated app shell for an unauthenticated viewer;
  // the effect above is redirecting to /login.
  if (!authed) return <div className="p-8 text-slate-400">Redirecting to sign in…</div>;

  return (
    <div className="flex min-h-screen">
      <aside className="w-56 shrink-0 border-r border-edge bg-panel p-4">
        <div className="mb-6">
          <div className="text-lg font-bold">wp-audit-win</div>
          <div className="text-xs text-slate-400">authorized assessment</div>
        </div>
        <nav className="space-y-1">
          {NAV.map(([label, href]) => {
            const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                className={`block rounded-lg px-3 py-2 text-sm ${
                  active ? "bg-sky-600 text-white" : "hover:bg-edge text-slate-300"
                }`}
              >
                {label}
              </Link>
            );
          })}
        </nav>
        <button
          onClick={() => {
            setToken(null);
            router.replace("/login");
          }}
          className="btn-ghost mt-8 w-full justify-center"
        >
          Sign out
        </button>
      </aside>
      <main className="flex-1 overflow-x-hidden p-6">{children}</main>
    </div>
  );
}
