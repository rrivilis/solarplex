"use client";

import { useEffect, useState } from "react";
import AppNav from "@/components/AppNav";
import { captureSpTokenFromHash, isAuthenticated } from "@/lib/auth";
import { ShellAuthContext } from "@/lib/shellAuth";

/**
 * Shared chrome + auth check for every top-level app page (Sessions,
 * Inbox, Activity, Search, Teammates, Agents, Settings). Because this is
 * a real Next.js layout rather than a component each page separately
 * imported, it mounts once and persists across navigation between those
 * pages — AppNav no longer unmounts and remounts (losing its own query
 * subscriptions, open dropdown state, and hover/focus state) on every
 * nav click, and the auth check below only ever runs once per app
 * session instead of once per page visited.
 *
 * `sessions/[id]` and `sessions/[id]/sync` are deliberately not part of
 * this group — they use a different, inline auth pattern (no full-page
 * gate) and weren't part of the duplicated authed/authChecked pattern
 * this layout replaces.
 */
export default function ShellLayout({ children }: { children: React.ReactNode }) {
  const [authed, setAuthed] = useState(false);
  const [authChecked, setAuthChecked] = useState(false);

  useEffect(() => {
    // Providers also captures the hash token in its own mount effect, but
    // React runs child effects before parent effects within a commit —
    // this layout is the child, so relying solely on Providers would check
    // isAuthenticated() before its effect has actually run. Capturing here
    // too removes the dependency on that ordering: captureSpTokenFromHash
    // is idempotent, so whichever of the two runs first does the real work.
    captureSpTokenFromHash();
    setAuthed(isAuthenticated());
    setAuthChecked(true);
  }, []);

  if (!authChecked) {
    return <div className="flex h-full bg-surface-0" />;
  }

  const status: { authed: boolean; authChecked: boolean } = { authed, authChecked };

  if (!authed) {
    // No persistent rail while signed out. Each page still owns its own
    // sign-in prompt (the Sessions landing page's is intentionally more
    // elaborate than the rest) — this layout just stops re-deriving the
    // same authed/authChecked pair once per page and hands it down instead.
    return <ShellAuthContext.Provider value={status}>{children}</ShellAuthContext.Provider>;
  }

  return (
    <ShellAuthContext.Provider value={status}>
      <div className="flex h-full bg-surface-0 text-primary">
        <AppNav />
        <main className="flex-1 overflow-y-auto min-w-0">
          {children}
        </main>
      </div>
    </ShellAuthContext.Provider>
  );
}
