"use client";

import { useQuery } from "@tanstack/react-query";
import RelativeTime from "@/components/RelativeTime";
import { signIn } from "@/lib/auth";
import { getTeammates, Teammate } from "@/lib/team";
import { useShellAuth } from "@/lib/shellAuth";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

const ROLE_BADGE: Record<string, string> = {
  owner:        "text-accent-amber bg-accent-amber/10 border-accent-amber/20",
  collaborator: "text-accent-blue  bg-accent-blue/10  border-accent-blue/20",
  observer:     "text-muted        bg-surface-3        border-border",
  agent:        "text-accent-purple bg-accent-purple/10 border-accent-purple/20",
};

export default function TeamPage() {
  useDocumentTitle("Teammates");
  const { authed } = useShellAuth();

  const { data: teammates, isPending, isError } = useQuery({
    queryKey: ["teammates"],
    queryFn: getTeammates,
    enabled: authed,
    staleTime: 30_000,
  });

  if (!authed) {
    return (
      <div className="flex h-full items-center justify-center bg-surface-0 text-primary">
        <div className="text-center max-w-sm px-6">
          <h1 className="text-base font-semibold text-primary mb-2">Sign in to Solarplex</h1>
          <button
            onClick={() => signIn("/team")}
            className="text-xs px-4 py-2 rounded-lg font-medium bg-accent-blue text-surface-0 hover:bg-accent-blue/90 transition-colors"
          >
            Sign in
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-[740px] mx-auto py-10 px-8">
      <div className="mb-5">
        <h1 className="text-base font-semibold text-primary mb-0.5">Teammates</h1>
        <p className="text-xs text-muted">
          You and everyone you currently share a session with
        </p>
      </div>

      {isPending ? (
        <div className="space-y-1.5">
          {[0, 1, 2, 3].map(i => <div key={i} className="h-[52px] rounded-lg bg-surface-1 animate-pulse" />)}
        </div>
      ) : isError ? (
        <div className="rounded-xl border border-border bg-surface-1 panel-shine p-14 text-center">
          <p className="text-sm font-medium text-subtle mb-1">Couldn&apos;t load teammates</p>
          <p className="text-xs text-muted">Your sign-in may have expired.</p>
        </div>
      ) : (teammates ?? []).length === 0 ? (
        <div className="rounded-xl border border-border bg-surface-1 panel-shine p-14 text-center">
          <div className="text-4xl mb-4 text-border select-none leading-none">⬡</div>
          <p className="text-sm font-medium text-subtle mb-1">No teammates yet</p>
          <p className="text-xs text-muted">Invite someone to a session to get started.</p>
        </div>
      ) : (
        <div className="space-y-0.5">
          {(teammates ?? []).map(t => <TeammateRow key={t.id} teammate={t} />)}
        </div>
      )}
    </div>
  );
}

function TeammateRow({ teammate }: { teammate: Teammate }) {
  return (
    <div className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-surface-1 transition-colors duration-100">
      <div className="w-8 h-8 rounded-full shrink-0 bg-accent-blue/15 text-accent-blue ring-1 ring-accent-blue/20 flex items-center justify-center text-[10px] font-bold">
        {teammate.name.slice(0, 2).toUpperCase()}
      </div>

      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium text-primary truncate">{teammate.name}</p>
      </div>

      <div className="hidden sm:flex items-center gap-1 shrink-0">
        {teammate.roles.length === 0 ? (
          <span className="text-2xs text-muted">no active sessions</span>
        ) : teammate.roles.map(r => (
          <span key={r} className={`text-2xs font-mono px-1.5 py-0.5 rounded border ${ROLE_BADGE[r] ?? "text-muted bg-surface-3 border-border"}`}>
            {r}
          </span>
        ))}
      </div>

      <span className="text-2xs text-muted w-16 text-right shrink-0 hidden md:inline">
        {teammate.session_count} {teammate.session_count === 1 ? "session" : "sessions"}
      </span>

      <span className="text-2xs text-muted w-24 text-right shrink-0">
        {teammate.last_active_at ? <RelativeTime date={teammate.last_active_at} /> : "never active"}
      </span>
    </div>
  );
}
