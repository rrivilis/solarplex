"use client";

import { useParams, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { getMe, isAuthenticated, signIn } from "@/lib/auth";
import { getActorOverride } from "@/lib/actorOverride";
import SyncWorkspace from "@/components/SyncWorkspace";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

export default function SessionSyncPage() {
  useDocumentTitle("Cross-Session Sync");
  const params = useParams();
  const searchParams = useSearchParams();
  const sessionId = params.id as string;

  // Deferred auth check — server and the client's first render pass both
  // have no localStorage access, so both must render the same "checking"
  // placeholder. Reading isAuthenticated() synchronously in the render body
  // (like an earlier version of this file did) diverges on the client's
  // very first render, which fires a hydration-mismatch warning. Same
  // pattern as app/activity/page.tsx.
  const [authed, setAuthed]     = useState(false);
  const [authChecked, setAuthChecked] = useState(false);

  useEffect(() => {
    const ok = isAuthenticated();
    setAuthed(ok);
    setAuthChecked(true);
    if (!ok) signIn(window.location.pathname + window.location.search);
  }, []);

  const { data: me } = useQuery({
    queryKey: ["me"],
    queryFn: getMe,
    enabled: authed,
    staleTime: 60_000,
  });
  const ACTOR_ID = me?.id ?? getActorOverride(searchParams) ?? "user";

  const token: string | null =
    searchParams.get("token") ??
    (typeof window !== "undefined" ? sessionStorage.getItem(`sol-tok-${sessionId}-${ACTOR_ID}`) : null);

  if (!authed) {
    if (!authChecked) return <div className="flex h-full bg-surface-0" />;
    return (
      <div className="flex h-full items-center justify-center bg-surface-0 text-primary">
        <div className="text-center max-w-sm px-6">
          <h1 className="text-base font-semibold text-primary mb-2">Sign in to Solarplex</h1>
          <button
            onClick={() => signIn(window.location.pathname + window.location.search)}
            className="text-xs px-4 py-2 rounded-lg font-medium bg-accent-blue text-surface-0 hover:bg-accent-blue/90 transition-colors"
          >
            Sign in
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full bg-surface-0">
      <div className="shrink-0 h-11 flex items-center gap-3 px-4 border-b border-border">
        <Link
          href={`/sessions/${sessionId}`}
          className="text-xs text-muted hover:text-subtle transition-colors"
        >
          ← Back to session
        </Link>
        <span className="text-border">|</span>
        <h1 className="text-xs font-medium text-subtle">Cross-Session Sync</h1>
      </div>
      <div className="flex-1 min-h-0">
        <SyncWorkspace sessionId={sessionId} actorId={ACTOR_ID} token={token} />
      </div>
    </div>
  );
}
