"use client";

import { useQuery } from "@tanstack/react-query";
import RelativeTime from "@/components/RelativeTime";
import { signIn } from "@/lib/auth";
import { getAgents, Agent } from "@/lib/agents";
import { useShellAuth } from "@/lib/shellAuth";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

const ROLE_BADGE: Record<string, string> = {
  owner:        "text-accent-amber bg-accent-amber/10 border-accent-amber/20",
  collaborator: "text-accent-blue  bg-accent-blue/10  border-accent-blue/20",
  observer:     "text-muted        bg-surface-3        border-border",
  agent:        "text-accent-purple bg-accent-purple/10 border-accent-purple/20",
};

export default function AgentsPage() {
  useDocumentTitle("Agents");
  const { authed } = useShellAuth();

  const { data: agents, isPending, isError } = useQuery({
    queryKey: ["agents"],
    queryFn: getAgents,
    enabled: authed,
    staleTime: 30_000,
  });

  if (!authed) {
    return (
      <div className="flex h-full items-center justify-center bg-surface-0 text-primary">
        <div className="text-center max-w-sm px-6">
          <h1 className="text-base font-semibold text-primary mb-2">Sign in to Solarplex</h1>
          <button
            onClick={() => signIn("/agents")}
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
        <h1 className="text-base font-semibold text-primary mb-0.5">Agents</h1>
        <p className="text-xs text-muted">
          Every agent currently attached to a session you&apos;re in. 
        </p>
      </div>

      {isPending ? (
        <div className="space-y-1.5">
          {[0, 1, 2, 3].map(i => <div key={i} className="h-[52px] rounded-lg bg-surface-1 animate-pulse" />)}
        </div>
      ) : isError ? (
        <div className="rounded-xl border border-border bg-surface-1 panel-shine p-14 text-center">
          <p className="text-sm font-medium text-subtle mb-1">Couldn&apos;t load agents</p>
          <p className="text-xs text-muted">Your sign-in may have expired.</p>
        </div>
      ) : (agents ?? []).length === 0 ? (
        <div className="rounded-xl border border-border bg-surface-1 panel-shine p-14 text-center">
          <div className="text-4xl mb-4 text-border select-none leading-none">⬡</div>
          <p className="text-sm font-medium text-subtle mb-1">No agents yet</p>
          <p className="text-xs text-muted">Attach an agent to a session to get started.</p>
        </div>
      ) : (
        <div className="space-y-0.5">
          {(agents ?? []).map(a => <AgentRow key={a.id} agent={a} />)}
        </div>
      )}
    </div>
  );
}

function AgentRow({ agent }: { agent: Agent }) {
  return (
    <div className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-surface-1 transition-colors duration-100">
      <div className="relative w-8 h-8 rounded-full shrink-0 bg-accent-purple/15 text-accent-purple ring-1 ring-accent-purple/20 flex items-center justify-center text-[10px] font-bold">
        {agent.name.slice(0, 2).toUpperCase()}
        <span
          className={`absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full ring-2 ring-surface-0 ${
            agent.live ? "bg-accent-green" : "bg-surface-4"
          }`}
          title={agent.live ? "Live — heartbeating now" : "Not currently connected"}
        />
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5">
          <p className="text-xs font-medium text-primary truncate">{agent.name}</p>
          {agent.live && (
            <span className="text-2xs font-mono px-1.5 py-0.5 rounded border text-accent-green bg-accent-green/10 border-accent-green/20 shrink-0">
              live
            </span>
          )}
        </div>
      </div>

      <div className="hidden sm:flex items-center gap-1 shrink-0">
        {agent.roles.length === 0 ? (
          <span className="text-2xs text-muted">no active sessions</span>
        ) : agent.roles.map(r => (
          <span key={r} className={`text-2xs font-mono px-1.5 py-0.5 rounded border ${ROLE_BADGE[r] ?? "text-muted bg-surface-3 border-border"}`}>
            {r}
          </span>
        ))}
      </div>

      <span className="text-2xs text-muted w-16 text-right shrink-0 hidden md:inline">
        {agent.session_count} {agent.session_count === 1 ? "session" : "sessions"}
      </span>

      <span className="text-2xs text-muted w-24 text-right shrink-0">
        {agent.last_active_at ? <RelativeTime date={agent.last_active_at} /> : "never active"}
      </span>
    </div>
  );
}
